
from concurrent.futures import ThreadPoolExecutor, as_completed
from enum import EnumMeta, StrEnum
from http.client import HTTPResponse
import os
from pathlib import Path
from string import Template
from subprocess import run
from textwrap import dedent
import tomllib
import time
from typing import Any, ClassVar, override
import urllib
from urllib.error import HTTPError
import urllib.request

from jinja2 import Environment, FileSystemLoader, select_autoescape
from nft_blackhole.debug import save_debug_file

from . import Absent, ABSENT, DEBUG_FLAG, NftbArgs, NftbColorCodes as cc
from .exceptions import NftbConfigError
from .logger import logger
from .data.countries import country_code_lookup


class Config(object):
    """The Config object holds all configuration values.
    The user is able to customize settings in /usr/local/etc/nft-blackhole.yaml.
    """
    _active_address_lists: list[AddressList | CountryAddressList | Absent] = list()

    bool_map: ClassVar[dict[str, bool]] = {
    'true': True, 't': True, 'yes': True, 'y': True, '1': True,
    'false': False, 'f': False, 'no': False, 'n': False, '0': False
    }

    ignore_certs_env: ClassVar[str | None] = os.getenv(
        'NFT_BLACKHOLE_IGNORE_CERTS', None
    )

    nft_blackhole_config: ClassVar[str] = os.getenv(
        'NFT_BLACKHOLE_CONFIG_PATH', '/usr/local/etc/nft-blackhole.yaml'
    )

    ip_version_support: ClassVar[list[str]] = ['v4', 'v6']

    forward_template: ClassVar[str] = (
        '\tchain forward {\n\t\ttype filter hook forward priority ${priority}; policy ${default_policy};\n'
        '\t\tct state established,related accept\n'
        '\t\tip saddr @whitelist-v4 counter accept\n'
        '\t\tip6 saddr @whitelist-v6 counter accept\n'
        '\t\tip saddr @blacklist-v4 counter ${block_policy}\n'
        '\t\tip6 saddr @blacklist-v6 counter ${block_policy}\n'
        '\t\t${country_ex_ports_rule}\n'
        '\t\tip saddr @country-v4 counter ${country_policy}\n'
        '\t\tip6 saddr @country-v6 counter ${country_policy}\n'
        '\t\tcounter\n\t}'
    ).expandtabs()

    output_template: ClassVar[str] = (
        'chain output {\n\t\ttype filter hook output priority ${priority}; policy accept;\n'
        '\t\tip daddr @whitelist-v4 counter accept\n'
        '\t\tip6 daddr @whitelist-v6 counter accept\n'
        '\t\tip daddr @blacklist-v4 counter ${block_policy}\n'
        '\t\tip6 daddr @blacklist-v6 counter ${block_policy}\n\t}'
    ).expandtabs()

    nft_set_template: ClassVar[str] = (
        'table inet blackhole {\n\tset ${set_name} {\n\t\ttype ${ip_ver}_addr\n'
        '\t\tflags interval\n\t\tauto-merge\n\t\telements = { ${ip_list} }\n\t}\n}'
    ).expandtabs()

    def __init__(self, args:NftbArgs):
        self._active_ip_versions: list[str]
        self._blacklist: AddressList | Absent
        self._block_forward: bool
        self._block_output: bool
        self._block_policy: str
        self._chain_forward: str
        self._chain_output: str
        self._country_address_list: CountryAddressList | Absent
        self._default_policy: str
        self._dry_run: bool
        self._ignore_certs: bool  # urllib
        self._priority: str
        self._whitelist: AddressList | Absent

        _config: dict[str, Any] | Exception = Config._load_config()  # pyright: ignore[reportExplicitAny]
        self._dry_run = args.dry_run
        _ = logger.debug(f'DRY RUN: {self._dry_run}')  # pyright: ignore[reportUnknownVariableType, reportUnknownMemberType, reportAttributeAccessIssue]
        self._configure(_config)  # pyright: ignore[reportArgumentType]

        self.jinja_env: Environment = Environment(
            loader=FileSystemLoader("/usr/local/share/nft-blackhole"),
            autoescape=select_autoescape(),
            trim_blocks=True,
            lstrip_blocks=True
        )

    @property
    def active_address_lists(cls) -> list[AddressList | CountryAddressList | Absent]:
        return cls._active_address_lists

    @active_address_lists.setter
    def active_address_lists(cls, value: list[AddressList | CountryAddressList | Absent]) -> None:
        cls._active_address_lists = value

    def apply_nft_sets(self, reload: bool = False):
        '''Create all nftables sets (whitelist, blacklist, country)'''
        _ = logger.info("Applying NFT Sets...")  # pyright: ignore[reportUnknownVariableType, reportUnknownMemberType, reportAttributeAccessIssue]
        for address_list in self.active_address_lists:
            for ip_version in self.active_ip_versions:
                set_name = f'{address_list.list_type}-{ip_version}'
                ip_list = address_list.nft_sets.get(ip_version)
                if ip_list:
                    set_list = ', '.join(ip_list)
                    nft_set = (
                        Template(self.nft_set_template).substitute(
                            ip_ver=f'ip{ip_version}', set_name=set_name, ip_list=set_list
                        )
                    )
                    if not DEBUG_FLAG:
                        if reload:
                            _ = run(['nft', 'flush', 'set', 'inet', 'blackhole', set_name], check=False)
                        if ip_list:
                            _ = run(['nft', '-f', '-'], input=nft_set.encode(), check=True)
                    else:
                        save_debug_file(f'nft_set_{ip_version}', nft_set)

    @property
    def active_ip_versions(self) -> list[str]:
        return self._active_ip_versions

    @active_ip_versions.setter
    def active_ip_versions(self, value: list[str]) -> None:
        self._active_ip_versions = value

    @property
    def blacklist(self) -> AddressList | Absent:
        return self._blacklist

    @blacklist.setter
    def blacklist(self, value: AddressList | Absent) -> None:
        self._blacklist = value

    @property
    def block_forward(self) -> bool:
        return self._block_forward

    @block_forward.setter
    def block_forward(self, value: bool) -> None:
        self._block_forward = value

    @property
    def block_output(self) -> bool:
        return self._block_output

    @block_output.setter
    def block_output(self, value: bool) -> None:
        self._block_output = value

    @property
    def block_policy(self) -> str:
        return self._block_policy

    @block_policy.setter
    def block_policy(self, value: str) -> None:
        self._block_policy = value

    @property
    def chain_forward(self) -> str:
        return self._chain_forward

    @chain_forward.setter
    def chain_forward(self, value: str) -> None:
        self._chain_forward = value

    @property
    def chain_output(self) -> str:
        return self._chain_output

    @chain_output.setter
    def chain_output(self, value: str) -> None:
        self._chain_output = value

    @property
    def country_address_list(self) -> CountryAddressList | Absent:
        return self._country_address_list

    @country_address_list.setter
    def country_address_list(self, value: CountryAddressList | Absent):
        self._country_address_list = value

    @property
    def default_policy(self) -> str:
        return self._default_policy

    @default_policy.setter
    def default_policy(self, value: str):
        self._default_policy = value

    @property
    def dry_run(self) -> bool:
        return self._dry_run

    @dry_run.setter
    def dry_run(self, value: bool) -> None:
        self._block_forward = value

    @property
    def ignore_certs(self):
        return self._ignore_certs

    @ignore_certs.setter
    def ignore_certs(self, value: bool):
        self._ignore_certs = value

    @property
    def priority(self):
        return self._priority

    @priority.setter
    def priority(self, value: str):
        self._priority = value

    @property
    def whitelist(self) -> AddressList | Absent:
        return self._whitelist

    @whitelist.setter
    def whitelist(self, value: AddressList | Absent):
        self._whitelist = value

    def _get_bool(self, value: str) -> bool:
        bool_value = self.bool_map.get(value.strip().lower(), False)

        return bool_value

    def _configure(self, _config: dict[str, Any]) -> None:  # pyright: ignore[reportExplicitAny]
        (_active_ip_versions := _config.get('active_ip_versions', None) or ABSENT)
        _finalized_version_list: list[str] = list()

        for v in self.ip_version_support:
            (_version := _active_ip_versions.get(v, False) or False)  # pyright: ignore[reportUnknownMemberType]
            if _version:
                try:
                    assert isinstance(_version, bool)
                except AssertionError:
                    raise NftbConfigError(
                        f'IP Version {v} MUST be set to a boolean (true or false) in config! Exiting...'
                    )
                else:
                    _finalized_version_list.append(v)


        if not _finalized_version_list:
            _active_ip_versions = ABSENT

        if _active_ip_versions is ABSENT:
            raise NftbConfigError(
                f'At least one of {self.ip_version_support} MUST be declared as true in config! Exiting...'
            )
        else:
            self.active_ip_versions = _finalized_version_list

        _blacklist_ips: list[str] | Absent = ABSENT
        _blacklist_files: list[str] | Absent = ABSENT
        _blacklist_urls: list[str] | Absent = ABSENT
        _blacklist = _config.get('blacklist', ABSENT)  # pyright: ignore[reportAny]        

        if _blacklist is ABSENT:
            self.blacklist = ABSENT
        else:
            (_blacklist_ips := _blacklist.get('ips', None) or ABSENT)  # pyright: ignore[reportAny]
            (_blacklist_files := _blacklist.get('files', None) or ABSENT)  # pyright: ignore[reportAny]
            (_blacklist_urls := _blacklist.get('urls', None) or ABSENT)  # pyright: ignore[reportAny]

        if all((_blacklist_files is ABSENT, _blacklist_ips is ABSENT, _blacklist_urls is ABSENT)):
            self.blacklist = ABSENT
        else:
            if _blacklist_ips is not ABSENT:
                try:
                    assert isinstance(_blacklist_ips, list) 
                except AssertionError:
                    raise NftbConfigError('blacklist ips MUST be a list of strings or absent from config! Exiting...')
                try:
                    assert all(isinstance(item, str) for item in _blacklist_ips)
                except AssertionError:
                    raise NftbConfigError('ALL items in blacklist ips MUST be strings! Exiting...')
            if _blacklist_files is not ABSENT:
                try:
                    assert isinstance(_blacklist_files, list)
                except AssertionError:
                    raise NftbConfigError('blacklist files MUST be a list of strings or absent from config! Exiting...')
                try:    
                    assert all(isinstance(item, str) for item in _blacklist_files)
                except AssertionError:
                    raise NftbConfigError('ALL items in blacklist files MUST be strings! Exiting...')
            if _blacklist_urls is not ABSENT:
                try:
                    assert isinstance(_blacklist_urls, list)
                except AssertionError:
                    raise NftbConfigError('blacklist urls MUST be a list of strings or absent from config! Exiting...')
                try:
                    assert all(isinstance(item, str) for item in _blacklist_urls)
                except AssertionError:
                    raise NftbConfigError('ALL items in blacklist urls MUST be strings! Exiting...')
            self.blacklist = AddressList(AddressListType.BLACKLIST, _blacklist_ips, _blacklist_files, _blacklist_urls)
            self.active_address_lists.append(self.blacklist)

        (_block_forward := _config.get('block_forward', None) or False)
        try:
            assert isinstance(_block_forward, bool)
        except AssertionError:
            raise NftbConfigError('block_forward MUST be a boolean value or absent from config! Exiting...')
        self.block_forward = _block_forward

        (_block_output := _config.get('block_output', None) or False)
        try:
            assert isinstance(_block_output, bool)
        except AssertionError:
            raise NftbConfigError('block_output MUST be a boolean value or absent from config! Exiting...')
        self.block_output = _block_output

        (_block_policy := _config.get('block_forward', None) or 'drop')
        try:
            assert isinstance(_block_policy, str)
        except AssertionError:
            # TODO: Create StrEnum of acceptable values!
            raise NftbConfigError('block_policy MUST be a string value or absent from config! Exiting...')
        self.block_policy = _block_policy

        (_priority := _config.get('priority', None) or -1)
        try:
            assert isinstance(_priority, str | int)
        except AssertionError:
            raise NftbConfigError(
                f'a priority of {_priority} is not a valid string or integer value in config! Exiting...'
            )

        try:
            _priority = int(_priority)
        except ValueError:
            _priority = _priority.lower()  # pyright: ignore[reportUnknownVariableType, reportUnknownMemberType, reportAttributeAccessIssue]
            if _priority in NftPriorityKeyword:
                self.priority = NftPriorityKeyword(_priority)
            else:
                raise NftbConfigError(
                    f'a priority of {_priority} is not a valid string or integer value in config! Exiting...'
                )
        else:
            self.priority = str(_priority)

        (_country_list := _config.get('country_list', None) or ABSENT)
        _finalized_country_list: list[str] = list()
        if _country_list is not ABSENT:
            try:
                assert isinstance(_country_list, list)
            except AssertionError:
                raise NftbConfigError(f'country_list {_country_list} is not a list! Exiting...')
            for item in _country_list:  # pyright: ignore[reportUnknownVariableType]
                try:
                    assert isinstance(item, str)
                except AssertionError:
                    raise NftbConfigError(f'country_list item {item} is not a string! Exiting...')
                else:
                    _capitalized_item = item.upper()
                    if _capitalized_item in country_code_lookup.keys():
                        _finalized_country_list.append(_capitalized_item)
                    else:
                        raise NftbConfigError(
                            f"country code '{item}' in config is not defined in ISO 3166-1! Exiting..."
                        )
            _country_list = _finalized_country_list

        (_country_exclude_ports := _config.get('country_exclude_ports', None) or ABSENT)
        _finalized_country_exclude_ports_list: list[str] = list()
        if _country_exclude_ports is not ABSENT:
            try:
                assert isinstance(_country_exclude_ports, list)
            except AssertionError:
                raise NftbConfigError(
                    f'The country_exclude_ports {_country_exclude_ports} is not a valid '
                    f'string or integer value in config! Exiting...'
                )


            for item in _country_exclude_ports:  # pyright: ignore[reportUnknownVariableType]
                try:
                    _value = int(item)  # pyright: ignore[reportUnknownArgumentType]
                except ValueError:
                    _value = item.lower()  # pyright: ignore[reportUnknownVariableType, reportUnknownMemberType]
                _finalized_country_exclude_ports_list.append(str(_value))  # pyright: ignore[reportUnknownArgumentType]
            _country_exclude_ports = _finalized_country_exclude_ports_list


        (_country_list_source := _config.get('country_list_source', None) or ABSENT)
        try:
            assert isinstance(_country_list_source, str)
        except AssertionError:
            raise NftbConfigError('country_list_source MUST be a string value or absent from config! Exiting...')
        _country_list_source = _country_list_source.lower()
        if _country_list_source in CountryListSource:
            _country_list_source = CountryListSource(_country_list_source)
        else:
            raise NftbConfigError(
                f'a country_list_source of {_country_list_source} is not one of the valid values in config! Exiting...'
            )

        (_country_policy := _config.get('country_policy', None) or 'block')
        try:
            assert isinstance(_country_policy, str)
        except AssertionError:
            # TODO: Create StrEnum of acceptable values!
            raise NftbConfigError('country_policy MUST be a string value or absent from config! Exiting...')
        else:
            # TODO: Why does this make sense?
            if _country_policy == 'drop':
                self.default_policy = 'accept'
            else:
                self.default_policy = self.block_policy

        self.country_address_list = CountryAddressList(
            country_exclude_ports=_finalized_country_exclude_ports_list,
            country_list=_country_list,
            country_list_source=_country_list_source,
            country_policy=_country_policy,
            active_ip_versions=self.active_ip_versions
        )
        self.active_address_lists.append(self.country_address_list)

        if self.ignore_certs_env is not None:
            _ignore_certs = self._get_bool(self.ignore_certs_env)
        else:
            (_ignore_certs := _config.get('ignore_certs', None) or False)
            try:
                assert isinstance(_ignore_certs, bool)
            except AssertionError:
                raise NftbConfigError('ignore_certs MUST be a boolean value or absent from config! Exiting...')

        self.ignore_certs = _ignore_certs

        _whitelist_ips: list[str] | Absent = ABSENT
        _whitelist_files: list[str] | Absent = ABSENT
        _whitelist_urls: list[str] | Absent = ABSENT
        _whitelist = _config.get('whitelist', ABSENT)  # pyright: ignore[reportAny]

        if _whitelist is ABSENT:
            self.whitelist = ABSENT
        else:
            (_whitelist_ips := _whitelist.get('ips', None) or ABSENT)  # pyright: ignore[reportAny]
            (_whitelist_files := _whitelist.get('files', None) or ABSENT)  # pyright: ignore[reportAny]
            (_whitelist_urls := _whitelist.get('urls', None) or ABSENT)  # pyright: ignore[reportAny]

        if all((_whitelist_files is ABSENT, _whitelist_ips is ABSENT, _whitelist_urls is ABSENT)):
            self.whitelist = ABSENT
        else:
            if _whitelist_ips is not ABSENT:
                try:
                    assert isinstance(_whitelist_ips, list)
                except AssertionError:
                    raise NftbConfigError('whitelist ips MUST be a list of strings or absent from config! Exiting...')
                try:
                    assert all(isinstance(item, str) for item in _whitelist_ips)
                except AssertionError:
                    raise NftbConfigError('ALL items in whitelist ips MUST be strings! Exiting...')
            if _whitelist_files is not ABSENT:
                try:
                    assert isinstance(_whitelist_files, list)
                except AssertionError:
                    raise NftbConfigError('whitelist files MUST be a list of strings or absent from config! Exiting...')
                try:
                    assert all(isinstance(item, str) for item in _whitelist_files)
                except AssertionError:
                    raise NftbConfigError('ALL items in whitelist files MUST be strings! Exiting...')
            if _whitelist_urls is not ABSENT:
                try:
                    assert isinstance(_whitelist_urls, list)
                except AssertionError:
                    raise NftbConfigError('whitelist urls MUST be a list of strings or absent from config! Exiting...')
                try:
                    assert all(isinstance(item, str) for item in _whitelist_urls)
                except AssertionError:
                    raise NftbConfigError('ALL items in whitelist urls MUST be strings! Exiting...')
            self.whitelist = AddressList(AddressListType.WHITELIST, _whitelist_ips, _whitelist_files, _whitelist_urls)
            self.active_address_lists.append(self.whitelist)

        if self.block_output:
            self.chain_output = Template(self.output_template).substitute(
                priority=self.priority, block_policy=self.block_policy
            )
        else:
            self.chain_output = ''

        if self.block_forward:
            self.chain_forward = Template(self.forward_template).substitute(
                priority=self.priority,
                default_policy=self.default_policy,
                block_policy=self.block_policy,
                country_policy=self.country_address_list.country_policy,
                country_ex_ports_rule=self.country_address_list.country_exclude_ports_rule
            )
        else:
            self.chain_forward = ''

    @classmethod
    def _load_config(cls) -> dict[str, Any] | Exception:  # pyright: ignore[reportExplicitAny]
        try:
            with open(cls.nft_blackhole_config, 'rb') as stream:
                data = tomllib.load(stream)
        except FileNotFoundError:
            msg = f"No config file found at: {cls.nft_blackhole_config}. Exiting..."
            raise NftbConfigError(msg)
        except tomllib.TOMLDecodeError:
            msg = f"Error parsing TOML file: {cls.nft_blackhole_config}. Exiting..."
            raise NftbConfigError(msg)
        else:
            _ = logger.info(f"Config loaded from {cls.nft_blackhole_config}")  # pyright: ignore[reportUnknownVariableType, reportUnknownMemberType, reportAttributeAccessIssue]
            return data


    @override
    def __str__(self):
        config = f"""
        {str(self.blacklist)}
        {cc.ORANGE}block_forward: {cc.GREEN}{self.block_forward}
        {cc.ORANGE}block_policy: {cc.GREEN}{self.block_policy}
        {cc.ORANGE}block_output: {cc.GREEN}{self.block_output}{cc.RESET}
        {str(self.country_address_list)}
        {cc.ORANGE}default_policy: {cc.GREEN}{self.default_policy}
        {cc.ORANGE}ignore_certs: {cc.GREEN}{self.ignore_certs}
        {cc.ORANGE}active_ip_versions: {cc.GREEN}{self.active_ip_versions}
        {cc.ORANGE}priority: {cc.GREEN}{self.priority}{cc.RESET}
        {str(self.whitelist)}
        """
        return dedent(config)


class NftPriorityKeywordMeta(EnumMeta):
    """
    This class allows us to determine if a value passed from the config
    file is one of the enumerated values in the NftPriorityKeyword enum.
    """
    @override
    def __contains__(cls, item: object):
        try:
            _ = cls(item)
        except ValueError:
            return False
        return True


class NftPriorityKeyword(StrEnum, metaclass=NftPriorityKeywordMeta):
    DSTNAT = 'dstnat'
    FILTER = 'filter'
    MANGLE = 'mangle'
    OUT = 'out'
    RAW = 'raw'
    SECURITY = 'security'
    SRCNAT = 'srcnat'


class AddressListType(StrEnum):
    """docstring for AddressList"""
    ABSENT = ABSENT
    BLACKLIST = 'blacklist'
    COUNTRY_LIST = "country_list"
    WHITELIST = 'whitelist'


class AddressListBase(object):
    """docstring for AddressListBase"""
    def __init__(
        self,
        list_type: AddressListType,
        urls: list[str] | Absent = ABSENT
    ):
        self._list_type: AddressListType = list_type
        self._nft_sets: dict[str, set[str]] = dict()
        self._resolved_ips: list[str] = list()
        self._urls: list[str] | Absent = urls

    @property
    def list_type(self) -> StrEnum:
        return self._list_type

    @list_type.setter
    def list_type(self, value: AddressListType) -> None:
        self._list_type = value

    @property
    def nft_sets(self):
        return self._nft_sets

    @property
    def resolved_ips(self) -> list[str]:
        return self._resolved_ips

    @resolved_ips.setter
    def resolved_ips(self, value: list[str]) -> None:
        self._resolved_ips = value

    @property
    def urls(self) -> list[str] | Absent:
        """
        Returns a clean list of urls
        """
        return self._urls

    @urls.setter
    def urls(self, value: list[str] | Absent, reset: bool = False) -> None:
        if value:
            if value is not ABSENT:
                if len(self.urls) > 0 and not reset:
                    pass
                else:
                    self._urls = list()

                for url in value:
                    if url.startswith('#'):
                        continue
                    else:
                        url = url.strip()
                        self._urls.append(url)
            else:
                self._urls = value

    def get_urls(self, max_retries: int=3, retry_delay: int=5, timeout: int=10) -> int | None:
        '''Download url in threads with retry logic'''
        def get_url(url: str) -> list[str] | None:
            for attempt in range(max_retries):
                try:
                    response: HTTPResponse = urllib.request.urlopen(url, timeout=timeout)  # pyright: ignore[reportAny]
                except HTTPError as exc:
                    if exc.code == 408 and attempt < max_retries - 1:
                        _ = logger.warning(  # pyright: ignore[reportUnknownVariableType, reportUnknownMemberType, reportAttributeAccessIssue]
                            f'Failed to fetch {url} on attempt {attempt+1}/{max_retries}. '
                            f'Retrying in {retry_delay}s. Error: {exc}'
                        )
                        time.sleep(retry_delay)
                        continue
                    else:
                        return None
                else:
                    content: str = response.read().decode('utf-8')
                    return content.splitlines()

        with ThreadPoolExecutor(max_workers=8) as executor:
            do_urls = [executor.submit(get_url, url) for url in self.urls]
            count = 0
            for out in as_completed(do_urls):
                ip_list = out.result()
                if ip_list is None or ABSENT:
                    pass
                else:
                    count += len(ip_list)
                    _ = self.resolved_ips.extend(ip_list)
            return count            


    def split_ip_versions(self, ip_addr_count: int | None) -> None:
        '''Split mixed list into deduplicated IPv4 and IPv6 sets'''
        _v6_set = self.nft_sets.get('v6', set())
        _v4_set = self.nft_sets.get('v4', set())
        _v_all_set_count = 0

        if DEBUG_FLAG:
            _ = logger.debug(f'_v6_set contains {cc.BB_YELLOW}{len(_v6_set): >12,}{cc.BB_CYAN} IPs')  # pyright: ignore[reportUnknownVariableType, reportUnknownMemberType, reportAttributeAccessIssue]
            _ = logger.debug(f'_v4_set contains {cc.BB_YELLOW}{len(_v4_set): >12,}{cc.BB_CYAN} IPs')  # pyright: ignore[reportUnknownVariableType, reportUnknownMemberType, reportAttributeAccessIssue]

        resolved_ips_count = len(self.resolved_ips)

        for line in self.resolved_ips:
            line = line.partition('#')[0].strip()  # Watch for comments to right of ips from config
            if ':' in line:
                _v6_set.add(line)
            elif '.' in line:
                _v4_set.add(line)

        if _v6_set:
            if DEBUG_FLAG:
                _v6_set_len = len(_v6_set)
                _v_all_set_count += _v6_set_len
                _ = logger.debug(f'{cc.LIGHT_GRAY}_v6_set{cc.BB_CYAN} NOW contains {cc.BB_YELLOW}{_v6_set_len: >8,}{cc.BB_CYAN} IPs')  # pyright: ignore[reportUnknownVariableType, reportUnknownMemberType, reportAttributeAccessIssue]
            self.nft_sets['v6'] = _v6_set
        if _v4_set:
            if DEBUG_FLAG:
                _v4_set_len = len(_v4_set)
                _v_all_set_count += _v4_set_len
                _ = logger.debug(f'{cc.LIGHT_GRAY}_v4_set{cc.BB_CYAN} NOW contains {cc.BB_YELLOW}{_v4_set_len: >8,}{cc.BB_CYAN} IPs')  # pyright: ignore[reportUnknownVariableType, reportUnknownMemberType, reportAttributeAccessIssue]
            self.nft_sets['v4'] = _v4_set

        if DEBUG_FLAG:
            if resolved_ips_count != ip_addr_count:
                _ = logger.error(f'resolved_ips_count: {resolved_ips_count} | ip_addr_count: {ip_addr_count}')  # pyright: ignore[reportUnknownVariableType, reportUnknownMemberType, reportAttributeAccessIssue]

            _ = logger.debug(f'{cc.BB_GREEN}DUPES Percentage: {1 - (_v_all_set_count / ip_addr_count) if ip_addr_count is not None else 0:.2%}{cc.BB_CYAN}')  # pyright: ignore[reportUnknownVariableType, reportUnknownMemberType, reportAttributeAccessIssue]

class AddressList(AddressListBase):
    """docstring for IPVersion"""
    def __init__(
        self,
        list_type: AddressListType,
        ips: list[str] | Absent = ABSENT,
        files: list[str] | Absent = ABSENT,
        urls: list[str] | Absent = ABSENT
    ):
        super(AddressList, self).__init__(list_type=list_type, urls=urls)
        self._ips: list[str] | Absent = ips
        self._files: list[str] | Absent = files

    @property
    def ips(self) -> list[str] | Absent:
        return self._ips

    @ips.setter
    def ips(self, value: list[str]) -> None:
        if value:
            self._ips = value
        else:
            self._ips = ABSENT

    @property
    def files(self) -> list[str] | Absent:
        return self._files

    @files.setter
    def files(self, value: list[str]) -> None:
        if value:
            self._files = value
        else:
            self._files = ABSENT

    def load_ip_sources(self, skip_urls: bool = False) -> int | None:
        '''Load IP sources: extract direct IPs, read local files, and fetch URLs, splitting into v4 and v6'''
        # Read local files
        if self.files is not ABSENT:
            for path in self.files:
                if path.startswith('#'):
                    continue
                file_path = Path(path).resolve()
                try:
                    with open(file_path, 'r') as f:
                        _ = self.resolved_ips.extend(f.readlines())
                except OSError:
                    _ = logger.error(f'Failed to read local file {file_path}')  # pyright: ignore[reportUnknownVariableType, reportUnknownMemberType, reportAttributeAccessIssue]
                    continue
                else:
                    if DEBUG_FLAG:
                        _ = logger.debug(f'Loaded {len(self.resolved_ips)} IPs from {file_path}')  # pyright: ignore[reportUnknownVariableType, reportUnknownMemberType, reportAttributeAccessIssue]

        if not skip_urls and self.urls is not ABSENT:
            downloaded_count = self.get_urls()
            if DEBUG_FLAG:
                _ = logger.debug(f'Downloaded {cc.BB_YELLOW}{downloaded_count: ,}{cc.BB_CYAN} IPs for {self.list_type}')  # pyright: ignore[reportUnknownVariableType, reportUnknownMemberType, reportAttributeAccessIssue]
            return downloaded_count
        else:
            return None

    @override
    def __str__(self) -> str:
        str_rep = f"""
        {cc.ORANGE}{str(super().list_type)}   ips: {cc.GREEN}{self.ips}
        {cc.ORANGE}{str(super().list_type)} files: {cc.GREEN}{self.files}
        {cc.ORANGE}{str(super().list_type)}  urls: {cc.GREEN}{self.urls}{cc.RESET}
        """
        return str_rep

class CountryListSourceMeta(EnumMeta):
    """
    This class allows us to determine if a value passed from the config
    file is one of the enumerated values in the CountryListSource enum.
    """
    @override
    def __contains__(cls, item: object):
        try:
            _ = cls(item)
        except ValueError:
            return False
        return True


class CountryListSource(StrEnum, metaclass=CountryListSourceMeta):
    ABSENT = ABSENT
    EBRASHA = 'ebrasha'
    IPDENY = 'ipdeny'
    IPVERSE = 'ipverse'


class CountryAddressList(AddressList):
    """docstring for CountryAddressList"""
    country_exclude_ports_template: ClassVar[str] = (
        'meta l4proto { tcp, udp } th dport { ${country_exclude_ports} } counter accept'
    )

    url_templates: ClassVar[dict[str, str | dict[str, str]]] = {
        'ebrasha': (
            'https://raw.githubusercontent.com/ebrasha/cidr-ip-ranges-by-country/refs/heads/master/'
            'CIDR/${country_code}-ip${ip_ver}-Hackers.Zone.txt'
        ),
        'ipdeny': {
            'v4': 'https://www.ipdeny.com/ipblocks/data/aggregated/${country_code}-aggregated.zone',
            'v6': 'https://www.ipdeny.com/ipv6/ipaddresses/aggregated/${country_code}-aggregated.zone'
        },
        'ipverse': (
            'https://raw.githubusercontent.com/ipverse/geo-ip-blocks/refs/heads/master/'
            'country/${country_code}/${country_code}-ip${ip_ver}.txt'
        )
    }

    def __init__(
        self,
        country_exclude_ports: list[str] | Absent,
        country_list: list[str] | Absent,
        country_list_source: CountryListSource,
        country_policy: str,
        active_ip_versions: list[str]
    ):
        super(CountryAddressList, self).__init__(list_type=AddressListType.COUNTRY_LIST, urls=list())
        self._country_exclude_ports: list[str] | Absent = country_exclude_ports
        self._country_exclude_ports_rule: str
        self._country_list: list[str] | Absent = country_list
        self._country_list_source: CountryListSource | Absent = country_list_source
        self._country_policy: str = country_policy
        self._active_ip_versions: list[str] = active_ip_versions

        if self._country_exclude_ports is not ABSENT:
            self._country_exclude_ports_rule = Template(
                self.country_exclude_ports_template
            ).substitute(
                country_exclude_ports=self._country_exclude_ports
            )
        else:
            self._country_exclude_ports_rule = ''

    @property
    def active_ip_versions(self) -> list[str]:
        return self._active_ip_versions

    @active_ip_versions.setter
    def active_ip_versions(self, value: list[str]):
        self._active_ip_versions = value

    @property
    def country_exclude_ports(self) -> list[str] | Absent:
        return self._country_exclude_ports

    @country_exclude_ports.setter
    def country_exclude_ports(self, value: list[str] | Absent) -> None:
        if value is not ABSENT:
            self.country_exclude_ports_rule = Template(
                self.country_exclude_ports_template
            ).substitute(country_exclude_ports=value)
        else:
            self._country_exclude_ports = ABSENT
            self.country_exclude_ports_rule = ''

    @property
    def country_exclude_ports_rule(self) -> str:
        return self._country_exclude_ports_rule

    @country_exclude_ports_rule.setter
    def country_exclude_ports_rule(self, value: str) -> None:
        self._country_exclude_ports_rule = value

    @property
    def country_list(self) -> list[str] | Absent:
        return self._country_list

    @country_list.setter
    def country_list(self, value: list[str] | Absent):
        self._country_list = value

    @property
    def country_list_source(self) -> CountryListSource | Absent:
        return self._country_list_source

    @country_list_source.setter
    def country_list_source(self, value: CountryListSource | Absent):
        self._country_list_source = value

    @property
    def country_policy(self) -> str:
        return self._country_policy

    @country_policy.setter
    def country_policy(self, value: str):
        self._country_policy = value

    def get_country_ips(self) -> None:
        '''Fetch country IP lists based on configured source and return dict per IP version'''

        count = 0
        for ip_ver in self.active_ip_versions:
            for country in self.country_list:
                if self.country_list_source == 'ebrasha':
                    country_code = country.upper()
                    url_string: str = self.url_templates[self.country_list_source]  # pyright: ignore[reportAssignmentType]
                elif self.country_list_source == 'ipdeny':
                    country_code = country.lower()
                    url_string = self.url_templates[self.country_list_source][ip_ver]  # pyright: ignore[reportArgumentType]
                elif self.country_list_source == 'ipverse':
                    country_code = country.lower()
                    url_string = self.url_templates[self.country_list_source]  # pyright: ignore[reportAssignmentType]
                else:
                    raise
                url: str = Template(url_string).substitute(country_code=country_code, ip_ver=ip_ver)
                if DEBUG_FLAG:
                    _ = logger.debug(f'url for country list download: {url}')  # pyright: ignore[reportUnknownVariableType, reportUnknownMemberType, reportAttributeAccessIssue]
                self.urls.append(url)
                count += 1

        if DEBUG_FLAG:
            _ = logger.debug(f'Adding {count} country_urls')  # pyright: ignore[reportUnknownVariableType, reportUnknownMemberType, reportAttributeAccessIssue]

    @override
    def load_ip_sources(self, skip_urls: bool = True) -> int | None:
        _ = logger.debug('Running super().load_ip_sources(skip_urls=True)')  # pyright: ignore[reportUnknownVariableType, reportUnknownMemberType, reportAttributeAccessIssue]
        _ = super().load_ip_sources(skip_urls=skip_urls)

        _ = logger.debug('Getting Country IPs...')  # pyright: ignore[reportUnknownVariableType, reportUnknownMemberType, reportAttributeAccessIssue]
        self.get_country_ips()

        _ = logger.debug('Getting URLs...')  # pyright: ignore[reportUnknownVariableType, reportUnknownMemberType, reportAttributeAccessIssue]
        ip_addr_count = self.get_urls()

        _ = logger.debug(f'Downloaded {cc.BB_YELLOW}{ip_addr_count: ,}{cc.BB_CYAN} IPs for {self.list_type}')  # pyright: ignore[reportUnknownVariableType, reportUnknownMemberType, reportAttributeAccessIssue]

        return ip_addr_count

    @override
    def __str__(self):
        str_rep = f"""
        {cc.ORANGE}country_list:{cc.GREEN} {self.country_list}
        {cc.ORANGE}country_list_source:{cc.GREEN} {self.country_list_source}
        {cc.ORANGE}country_policy:{cc.GREEN} {self.country_policy}
        {cc.ORANGE}country_exclude_ports:{cc.GREEN} {self.country_exclude_ports}{cc.RESET}
        """

        return str_rep
