
import os
from string import Template
import sys
from textwrap import dedent
from typing import ClassVar, override

from jinja2 import Environment, FileSystemLoader, select_autoescape

from . import NotProvided, NOT_PROVIDED
from .config_types import Data, BLACKLIST, IPVERSION, WHITELIST
from .exceptions import NftbConfigError
from .logger import logger

class Config(object):
    """The Config object holds all configuration values.
    The user is able to customize settings in /usr/local/etc/nft-blackhole.yaml.
    """
    bool_map: ClassVar[dict[str, bool]] = {
    'true': True, 't': True, 'yes': True, 'y': True, '1': True,
    'false': False, 'f': False, 'no': False, 'n': False, '0': False
    }

    ignore_certs_env = os.getenv('NFT_BLACKHOLE_IGNORE_CERTS', None)  # pyright: ignore[reportUnannotatedClassAttribute]

    country_exclude_ports_template: ClassVar[str] = (
        'meta l4proto { tcp, udp } th dport { ${country_exclude_ports} } counter accept'
    )

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

    ip_version_support: ClassVar[list[str]] = ['v4', 'v6']
    nft_blackhole_config: ClassVar[str] = os.getenv('NFT_BLACKHOLE_CONFIG_PATH', '/usr/local/etc/nft-blackhole.yaml')

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


    def __init__(self):
        self._active_ip_versions: list[str] = list()
        self._blacklist: BLACKLIST
        self._block_forward: bool
        self._block_output: bool
        self._block_policy: str
        self._chain_forward: str
        self._chain_output: str
        self._country_exclude_ports: list[str] | NotProvided
        self._country_exclude_ports_rule: str
        self._country_list: list[str] | NotProvided
        self._country_list_source: str
        self._country_policy: str
        self._default_policy: str
        self._ignore_certs: bool  # urllib
        self._priority: int
        self._whitelist: WHITELIST

        _config: Data = Config._load_config()  # pyright: ignore[reportAssignmentType]
        self._configure(_config)

        self.jinja_env: Environment = Environment(
            loader=FileSystemLoader("/usr/local/share/nft-blackhole"),
            autoescape=select_autoescape(),
            trim_blocks=True,
            lstrip_blocks=True
        )

    @property
    def active_ip_versions(self) -> list[str]:
        return self._active_ip_versions

    @active_ip_versions.setter
    def active_ip_versions(self, value: IPVERSION):  # pyright: ignore[reportPropertyTypeMismatch]
        for ip_v in self.ip_version_support:
            try:
                v: bool = getattr(value, ip_v)  # pyright: ignore[reportAny]
                if v:
                    self._active_ip_versions.append(ip_v)
            except AttributeError:
                logger.info(f'No value found for {ip_v} in ip_version_support of config file.')

    @property
    def blacklist(self) -> BLACKLIST:
        return self._blacklist

    @blacklist.setter
    def blacklist(self, value: BLACKLIST):
        self._blacklist = value

    @property
    def block_forward(self) -> bool:
        return self._block_forward

    @block_forward.setter
    def block_forward(self, value: bool):
        self._block_forward = value

    @property
    def block_output(self) -> bool:
        return self._block_output

    @block_output.setter
    def block_output(self, value: bool):
        self._block_output = value

    @property
    def block_policy(self) -> str:
        return self._block_policy

    @block_policy.setter
    def block_policy(self, value: str):
        self._block_policy = value

    @property
    def chain_forward(self) -> str:
        return self._chain_forward

    @chain_forward.setter
    def chain_forward(self, value: str):
        self._chain_forward = value

    @property
    def chain_output(self) -> str:
        return self._chain_output

    @chain_output.setter
    def chain_output(self, value: str):
        self._chain_output = value

    @property
    def country_exclude_ports(self) -> list[str] | NotProvided:
        return self._country_exclude_ports

    @country_exclude_ports.setter
    def country_exclude_ports(self, value: list[int | str] | None):  # pyright: ignore[reportPropertyTypeMismatch]
        if value == []:
            value = None
        if value:
            # Convert any int values in list to str
            self._country_exclude_ports = ', '.join(map(str, value))  # pyright: ignore[reportAttributeAccessIssue]
            self.country_exclude_ports_rule = Template(
                self.country_exclude_ports_template
            ).substitute(country_exclude_ports=self.country_exclude_ports)
        else:
            self._country_exclude_ports = NOT_PROVIDED
            self.country_exclude_ports_rule = ''

    @property
    def country_exclude_ports_rule(self) -> str:
        return self._country_exclude_ports_rule

    @country_exclude_ports_rule.setter
    def country_exclude_ports_rule(self, value: str):
        self._country_exclude_ports_rule = value

    @property
    def country_list(self) -> list[str] | NotProvided:
        return self._country_list

    @country_list.setter
    def country_list(self, value: list[str] | NotProvided):
        # Correct incorrect YAML parsing of no (Norway)
        # It should be the string 'no', but YAML interprets it as False
        # This is a hack due to the lack of YAML 1.2 support by PyYAML
        # Note that the boolean value False will be conveted to the
        # string 'False' by the Data dataclass in the config_types module.
        if value is not NotProvided:
            while 'False' in value:
                value[value.index('False')] = 'no'
        self._country_list = value

    @property
    def country_list_source(self) -> str | NotProvided:
        return self._country_list_source

    @country_list_source.setter
    def country_list_source(self, value: str | NotProvided):
        self._country_list_source = value

    @property
    def country_policy(self) -> str:
        return self._country_policy

    @country_policy.setter
    def country_policy(self, value: str):
        # TODO: Why does this make sense?
        if value == 'drop':
            self.default_policy = 'accept'
        else:
            self.default_policy = self.block_policy
        self._country_policy = value

    @property
    def default_policy(self) -> str:
        return self._default_policy

    @default_policy.setter
    def default_policy(self, value: str):
        self._default_policy = value

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
    def priority(self, value: int):
        self._priority = value

    @property
    def whitelist(self) -> WHITELIST:
        return self._whitelist

    @whitelist.setter
    def whitelist(self, value: WHITELIST):
        self._whitelist = value

    def _get_bool(self, value: str) -> bool:
        bool_value = self.bool_map.get(value.strip().lower(), False)

        return bool_value

    def _configure(self, _config: Data) -> None:
        # ip_version_support is a required config value
        if not _config.ip_version_support.v4 and not _config.ip_version_support.v6:
            raise NftbConfigError('No ip_version_support is turned on in config file. Exiting...')
        else:
            self.active_ip_versions = _config.ip_version_support

        self.blacklist = _config.blacklist
        self.block_forward = _config.block_forward
        self.block_output = _config.block_output
        self.block_policy = _config.block_policy or 'block'
        self.country_exclude_ports = _config.country_exclude_ports
        self.country_list = _config.country_list or NOT_PROVIDED
        self.country_list_source = _config.country_list_source or NOT_PROVIDED
        self.country_policy = _config.country_policy or 'block'

        if self.ignore_certs_env is not None:
            self.ignore_certs = self._get_bool(self.ignore_certs_env)
        else:
            self.ignore_certs = _config.ignore_certs
        self.priority = _config.priority
        self.whitelist = _config.whitelist

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
                country_policy=self.country_policy,
                country_ex_ports_rule=self.country_exclude_ports_rule
            )
        else:
            self.chain_forward = ''

    @classmethod
    def _load_config(cls) -> Data | list[Data]:
        try:
            with open(cls.nft_blackhole_config, 'r') as stream:
                data: Data | list[Data] = Data.from_yaml(stream)  # pyright: ignore[reportUnknownMemberType]
        except FileNotFoundError:
            logger.error(f"No config file found at {cls.nft_blackhole_config}. Exiting.")
            sys.exit(78)
        else:
            logger.info(f"Config loaded from {cls.nft_blackhole_config}")
            return data

    @override
    def __str__(self):
        config = f"""
        blacklist: {self.blacklist}
        block_forward: {self.block_forward}
        block_policy: {self.block_policy}
        block_output: {self.block_output}
        country_list: {self.country_list}
        country_list_source: {self.country_list_source}
        country_policy: {self.country_policy}
        country_exclude_ports: {self.country_exclude_ports}
        default_policy: {self.default_policy}
        ignore_certs: {self.ignore_certs}
        ip_version_support: {self.active_ip_versions}
        priority: {self.priority}
        whitelist: {self.whitelist}
        """
        return dedent(config)

