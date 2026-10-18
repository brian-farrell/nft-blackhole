
import os
from string import Template
import sys
from textwrap import dedent
from typing import override

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .config_types import Data, BLACKLIST, IPVERSIONS, WHITELIST
from .logger import logger

class Config(object):
    """The Config object holds all configuration values.
    The user is able to customize settings in /usr/local/etc/nft-blackhole.yaml.
    """
    COUNTRY_EX_PORTS_TEMPLATE: str = 'meta l4proto { tcp, udp } th dport { ${country_exclude_ports} } counter accept'
    IP_VERSIONS: list[str] = ['v4', 'v6']
    NFT_BLACKHOLE_CONFIG: str = os.getenv('NFT_BLACKHOLE_CONFIG_PATH', '/usr/local/etc/nft-blackhole.yaml')
    NFT_TEMPLATE: str = '/usr/local/share/nft-blackhole/nft-blackhole.template'

    OUTPUT_TEMPLATE: str = (
        '\tchain output {\n\t\ttype filter hook output priority ${priority}; policy accept;\n'
        '\t\tip daddr @whitelist-v4 counter accept\n'
        '\t\tip6 daddr @whitelist-v6 counter accept\n'
        '\t\tip daddr @blacklist-v4 counter ${block_policy}\n'
        '\t\tip6 daddr @blacklist-v6 counter ${block_policy}\n\t}'
    ).expandtabs()


    def __init__(self):
        self._active_ip_versions: list[str] = list()
        self._blacklist: BLACKLIST
        self._block_forward: bool
        self._block_output: bool
        self._block_policy: str
        self._chain_output: str
        self._chain_forward: str
        self._country_exclude_ports: list[str] | None
        self._country_exclude_ports_rule: str
        self._country_list: list[str] | None
        self._country_list_source: str
        self._country_policy: str
        self._default_policy: str
        self._priority: str
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
    def active_ip_versions(self, value: IPVERSIONS):  # pyright: ignore[reportPropertyTypeMismatch]
        for ip_v in self.IP_VERSIONS:
            try:
                getattr(value, ip_v)
                self._active_ip_versions.append(ip_v)
            except AttributeError:
                logger.info(f'No value found for {ip_v} in IP_VERSIONS of config file.')

    @property
    def block_policy(self) -> str:
        return self._block_policy

    @block_policy.setter
    def block_policy(self, value: str):
        self._block_policy = value

    @property
    def block_output(self) -> bool:
        return self._block_output

    @block_output.setter
    def block_output(self, value: bool):
        if value:
            self.chain_output = Template(self.OUTPUT_TEMPLATE).substitute(block_policy=self.block_policy)
        else:
            self.chain_output = ''
        self._block_output = value

    @property
    def chain_output(self) -> str:
        return self._chain_output

    @chain_output.setter
    def chain_output(self, value: str):
        self._chain_output = value

    @property
    def chain_forward(self) -> str:
        return self._chain_forward

    @chain_forward.setter
    def chain_forward(self, value: str):
        self._chain_forward = value

    @property
    def default_policy(self) -> str:
        return self._default_policy

    @default_policy.setter
    def default_policy(self, value: str):
        self._default_policy = value

    @property
    def whitelist(self) -> WHITELIST:
        return self._whitelist

    @whitelist.setter
    def whitelist(self, value: WHITELIST):
        self._whitelist = value

    @property
    def blacklist(self) -> BLACKLIST:
        return self._blacklist

    @blacklist.setter
    def blacklist(self, value: BLACKLIST):
        self._blacklist = value

    @property
    def country_list(self) -> list[str] | None:
        return self._country_list

    @country_list.setter
    def country_list(self, value: list[str] | None):
        # Correct incorrect YAML parsing of no (Norway)
        # It should be the string 'no', but YAML interprets it as False
        # This is a hack due to the lack of YAML 1.2 support by PyYAML
        # Note that the boolean value False will be conveted to the
        # string 'False' by the Data dataclass in the config_types module.
        if value:
            while 'False' in value:
                value[value.index('False')] = 'no'
            self._country_list = value

    @property
    def country_policy(self) -> str:
        return self._country_policy

    @country_policy.setter
    def country_policy(self, value: str):
        if value == 'drop':
            self.default_policy = 'accept'
        else:
            self.default_policy = self.block_policy
        self._country_policy = value

    @property
    def country_exclude_ports(self) -> list[str] | None:
        return self._country_exclude_ports

    @country_exclude_ports.setter
    def country_exclude_ports(self, value: list[int | str] | None):  # pyright: ignore[reportPropertyTypeMismatch]
        if value:
            # Convert any int values in list to str
            self._country_exclude_ports = ', '.join(map(str, value))  # pyright: ignore[reportAttributeAccessIssue]
            self.country_exclude_ports_rule = Template(
                self.COUNTRY_EX_PORTS_TEMPLATE
            ).substitute(country_exclude_ports=self.country_exclude_ports)
        else:
            self._country_exclude_ports = None
            self.country_exclude_ports_rule = ''

    @property
    def country_exclude_ports_rule(self) -> str:
        return self._country_exclude_ports_rule

    @country_exclude_ports_rule.setter
    def country_exclude_ports_rule(self, value: str):
        self._country_exclude_ports_rule = value

    @property
    def priority(self):
        return self._priority

    @priority.setter
    def priority(self, value: str):
        self._priority = value

    def _configure(self, _config: Data) -> None:
        # IP_VERSIONS is a required config value
        if active_ip_versions := _config.IP_VERSIONS:
            self.active_ip_versions = active_ip_versions
        else:
            logger.error("The config file does not specify IP_VERSIONS. Exiting.")
            sys.exit(78)

        self.block_policy = _config.BLOCK_POLICY or 'drop'
        self.block_output = _config.BLOCK_OUTPUT or False
        self.whitelist = _config.WHITELIST
        self.blacklist = _config.BLACKLIST
        self.country_policy = _config.COUNTRY_POLICY or 'drop'
        self.country_list = _config.COUNTRY_LIST
        self.country_exclude_ports = _config.COUNTRY_EXCLUDE_PORTS


    @classmethod
    def _load_config(cls) -> Data | list[Data]:
        print(f'Loading config from {cls.NFT_BLACKHOLE_CONFIG}')
        try:
            with open(cls.NFT_BLACKHOLE_CONFIG, 'r') as stream:
                data: Data | list[Data] = Data.from_yaml(stream)  # pyright: ignore[reportUnknownMemberType]
        except FileNotFoundError:
            logger.error(f"No config file found at {cls.NFT_BLACKHOLE_CONFIG}. Exiting.")
            sys.exit(78)
        else:
            logger.info(f"Config loaded from {cls.NFT_BLACKHOLE_CONFIG}")
            return data

    @override
    def __str__(self):
        config = f"""
        IP_VERSIONS: {self.active_ip_versions}
        BLOCK_POLICY: {self.block_policy}
        BLOCK_OUTPUT: {self.block_output}
        chain_output: {self.chain_output}
        default_policy: {self.default_policy}
        WHITELIST: {self.whitelist}
        BLACKLIST: {self.blacklist}
        COUNTRY_LIST: {self.country_list}
        COUNTRY_POLICY: {self.country_policy}
        COUNTRY_EXCLUDE_PORTS: {self.country_exclude_ports}
        country_exclude_exports_rule: {self.country_exclude_ports_rule}
        """
        return dedent(config)

