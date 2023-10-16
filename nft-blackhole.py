#!/usr/bin/env python

"""Script to create blocking IP in nftables by country and black lists"""

__author__ = "Tomasz Cebula <tomasz.cebula@gmail.com>"
__credits__ = ["Brian Farrell <brian.farrell@me.com>"]
__license__ = "MIT"
__version__ = "1.2.1"

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import os
import re
import ssl
from string import Template
from subprocess import run
import sys
from textwrap import dedent
from urllib.error import HTTPError
import urllib.request

from jinja2 import Environment, FileSystemLoader, select_autoescape
from systemd.journal import JournalHandler
from yaml import safe_load

app_name = 'nft-blackhole'


"""
LOGGING
"""
logger = logging.getLogger(app_name)

# Get logging level from environment variable if set
DEBUG_MODE = (os.environ.get('NFT_BH_DEBUG_MODE', 'False') == 'True')
if DEBUG_MODE:
    logger.setLevel(logging.DEBUG)
else:
    logger.setLevel(logging.INFO)

journal_handler = JournalHandler(SYSLOG_IDENTIFIER=app_name)
stderr_handler = logging.StreamHandler(stream=sys.stderr)

log_formatter = logging.Formatter(
    '%(asctime)s.%(msecs)03d - %(levelname)s - %(module)s line %(lineno)d: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

journal_handler.setFormatter(log_formatter)
stderr_handler.setFormatter(log_formatter)

logger.addHandler(journal_handler)
logger.addHandler(stderr_handler)


"""
urllib config
"""
ctx = ssl.create_default_context()
IGNORE_CERTIFICATE = False
if IGNORE_CERTIFICATE:
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

https_handler = urllib.request.HTTPSHandler(context=ctx)

opener = urllib.request.build_opener(https_handler)
# opener.addheaders = [('User-agent', 'Mozilla/5.0 (X11; Linux x86_64)')]
opener.addheaders = [('User-agent', 'Mozilla/5.0 (compatible; nft-blackhole/0.1.0; '
                      '+https://github.com/tomasz-c/nft-blackhole)')]
urllib.request.install_opener(opener)


class Config(object):
    """The Config object holds all configuration values.

    The user is able to customize settings via the ``nft-blackhole.yaml`` file, which
    is located at /usr/local/etc/nft-blackhole.yaml.
    """
    COUNTRY_EX_PORTS_TEMPLATE = 'meta l4proto { tcp, udp } th dport { ${country_exclude_ports} } counter accept'
    IP_VERSIONS = ['v4', 'v6']
    NFT_BLACKHOLE_CONFIG = '/usr/local/etc/nft-blackhole.yaml'
    NFT_TEMPLATE = '/usr/local/share/nft-blackhole/nft-blackhole.template'

    OUTPUT_TEMPLATE = (
        '\tchain output {\n\t\ttype filter hook output priority -1; policy accept;\n'
        '\t\tip daddr @whitelist-v4 counter accept\n'
        '\t\tip6 daddr @whitelist-v6 counter accept\n'
        '\t\tip daddr @blacklist-v4 counter ${block_policy}\n'
        '\t\tip6 daddr @blacklist-v6 counter ${block_policy}\n\t}'
    ).expandtabs()

    SET_TEMPLATE = (
        'table inet blackhole {\n\tset ${set_name} {\n\t\ttype ${ip_version}_addr\n'
        '\t\tflags interval\n\t\tauto-merge\n\t\telements = { ${ip_list} }\n\t}\n}'
    ).expandtabs()

    def __init__(self):
        self._active_ip_versions = list()
        self._block_policy = None
        self._block_output = None
        self._chain_output = None
        self._default_policy = None
        self._whitelist = None
        self._blacklist = None
        self._country_list = None
        self._country_policy = None
        self._country_exclude_ports = None
        self._country_exclude_ports_rule = None

        _config = Config._load_config()
        self._configure(_config)

        self.jinja_env = Environment(
            loader=FileSystemLoader("/usr/local/share/nft-blackhole"),
            autoescape=select_autoescape(),
            trim_blocks=True,
            lstrip_blocks=True
        )

    @property
    def active_ip_versions(self):
        return self._active_ip_versions

    @active_ip_versions.setter
    def active_ip_versions(self, value):
        for ip_v in self.IP_VERSIONS:
            if value[ip_v]:
                self._active_ip_versions.append(ip_v)

    @property
    def block_policy(self):
        return self._block_policy

    @block_policy.setter
    def block_policy(self, value):
        self._block_policy = value

    @property
    def block_output(self):
        return self._block_output

    @block_output.setter
    def block_output(self, value):
        if value:
            self.chain_output = Template(self.OUTPUT_TEMPLATE).substitute(block_policy=self.block_policy)
        else:
            self.chain_output = ''
        self._block_output = value

    @property
    def chain_output(self):
        return self._chain_output

    @chain_output.setter
    def chain_output(self, value):
        self._chain_output = value

    @property
    def default_policy(self):
        return self._default_policy

    @default_policy.setter
    def default_policy(self, value):
        self._default_policy = value

    @property
    def whitelist(self):
        return self._whitelist

    @whitelist.setter
    def whitelist(self, value):
        self._whitelist = value

    @property
    def blacklist(self):
        return self._blacklist

    @blacklist.setter
    def blacklist(self, value):
        self._blacklist = value

    @property
    def country_list(self):
        return self._country_list

    @country_list.setter
    def country_list(self, value):
        # Correct incorrect YAML parsing of NO (Norway)
        # It should be the string 'no', but YAML interprets it as False
        # This is a hack due to the lack of YAML 1.2 support by PyYAML
        while False in value:
            value[value.index(False)] = 'no'
        self._country_list = value

    @property
    def country_policy(self):
        return self._country_policy

    @country_policy.setter
    def country_policy(self, value):
        if value == 'drop':
            self.default_policy = 'accept'
        else:
            self.default_policy = self.block_policy
        self._country_policy = value

    @property
    def country_exclude_ports(self):
        return self._country_exclude_ports

    @country_exclude_ports.setter
    def country_exclude_ports(self, value):
        if value:
            self._country_exclude_ports = ', '.join(map(str, value))
            self.country_exclude_ports_rule = Template(
                self.COUNTRY_EX_PORTS_TEMPLATE
            ).substitute(country_exclude_ports=self.country_exclude_ports)
        else:
            self.country_exclude_ports_rule = ''

    @property
    def country_exclude_ports_rule(self):
        return self._country_exclude_ports_rule

    @country_exclude_ports_rule.setter
    def country_exclude_ports_rule(self, value):
        self._country_exclude_ports_rule = value

    def _configure(self, _config):
        # IP_VERSIONS is a required config value
        if active_ip_versions := _config.get("IP_VERSIONS"):
            self.active_ip_versions = active_ip_versions
        else:
            logger.error("The config file does not specify IP_VERSIONS. Exiting.")
            sys.exit(78)

        self.block_policy = _config.get("BLOCK_POLICY", 'drop')
        self.block_output = _config.get("BLOCK_OUTPUT", False)
        self.whitelist = _config.get("WHITELIST")
        self.blacklist = _config.get("BLACKLIST")
        self.country_policy = _config.get("COUNTRY_POLICY", 'block')
        self.country_list = _config.get("COUNTRY_LIST")
        self.country_exclude_ports = _config.get("COUNTRY_EXCLUDE_PORTS")

    @classmethod
    def _load_config(cls):
        try:
            with open(cls.NFT_BLACKHOLE_CONFIG, 'r') as stream:
                data = safe_load(stream)
        except FileNotFoundError:
            logger.error("No config file found at /usr/local/etc/nft-blackhole.yaml. Exiting.")
            sys.exit(78)
        else:
            logger.info(f"Config loaded from {cls.NFT_BLACKHOLE_CONFIG}")
            return data

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


def stop():
    """Stopping nft-blackhole"""
    run(['nft', 'delete', 'table', 'inet', 'blackhole'], check=True)


def start(config):
    """Starting nft-blackhole"""
    logger.info("Starting blackhole")
    nft_template = config.jinja_env.get_template("nft-blackhole.j2")
    nft_conf = nft_template.render(
        default_policy=config.default_policy,
        block_policy=config.block_policy,
        country_exclude_ports_rule=config.country_exclude_ports_rule,
        country_policy=config.country_policy,
        chain_output=config.chain_output
    )

    run(['nft', '-f', '-'], input=nft_conf.encode(), check=True)


def get_urls(urls, do_filter=False):
    """Download url in threads"""
    logger.info("Getting URLs")
    ip_list_aggregated = []

    def get_url(url):
        try:
            response = urllib.request.urlopen(url, timeout=10)
            content = response.read().decode('utf-8')
        except HTTPError as e:
            logger.error(f"HTTP error {e.code} {e.reason} {e.url}")
            ip_list = []
        else:
            if do_filter:
                content = re.sub(r'^ *(#.*\n?|\n?)', '', content, flags=re.MULTILINE)
            ip_list = content.splitlines()
        return ip_list
    with ThreadPoolExecutor(max_workers=8) as executor:
        do_urls = [executor.submit(get_url, url) for url in urls]
        for out in as_completed(do_urls):
            ip_list = out.result()
            ip_list_aggregated += ip_list
    return ip_list_aggregated


def get_blacklist(blacklist):
    """Get blacklists"""
    urls = []
    for bl_url in blacklist:
        urls.append(bl_url)
    ips = get_urls(urls, do_filter=True)
    return ips


def get_country_ip_list(country_list, ip_version):
    """Get country lists from GitHub @herrbischoff"""
    urls = []
    for country in country_list:
        logger.info(f"Getting blocklist for country: {country}")
        url = (
            f'https://raw.githubusercontent.com/herrbischoff/country-ip-blocks/'
            f'master/ip{ip_version}/{country.lower()}.cidr'
        )
        urls.append(url)
    ips = get_urls(urls)
    return ips


# TODO: This function is not called
def get_country_ip_list2(country_list, ip_version):
    """Get country lists from ipdeny.com"""
    urls = []
    for country in country_list:
        if ip_version == 'v4':
            url = f'http://ipdeny.com/ipblocks/data/aggregated/{country.lower()}-aggregated.zone'
        elif ip_version == 'v6':
            url = f'http://ipdeny.com/ipv6/ipaddresses/aggregated/{country.lower()}-aggregated.zone'
        urls.append(url)
    ips = get_urls(urls)
    return ips


def whitelist_sets(config, reload=False):
    """Create whitelist sets"""
    for ip_version in config.active_ip_versions:
        whitelist = config.whitelist.get(ip_version)
        if whitelist:
            set_name = f'whitelist-{ip_version}'
            set_list = ', '.join(whitelist)
            nft_set = (
                Template(config.SET_TEMPLATE).substitute(
                    ip_version=f'ip{ip_version}', set_name=set_name, ip_list=set_list
                )
            )
            if reload:
                run(['nft', 'flush', 'set', 'inet', 'blackhole', set_name], check=True)
            if config.whitelist[ip_version]:
                run(['nft', '-f', '-'], input=nft_set.encode(), check=True)


def blacklist_sets(config, reload=False):
    """Create blacklist sets"""
    for ip_version in config.active_ip_versions:
        blacklist = config.blacklist.get(ip_version)
        if blacklist:
            set_name = f'blacklist-{ip_version}'
            ip_list = get_blacklist(config.blacklist[ip_version])
            set_list = ', '.join(ip_list)
            nft_set = (
                Template(config.SET_TEMPLATE).substitute(
                    ip_version=f'ip{ip_version}', set_name=set_name, ip_list=set_list
                )
            )
            if reload:
                run(['nft', 'flush', 'set', 'inet', 'blackhole', set_name], check=True)
            if ip_list:
                run(['nft', '-f', '-'], input=nft_set.encode(), check=True)


def country_sets(config, reload=False):
    """Create country sets"""
    country_list = config.country_list
    if country_list:
        for ip_version in config.active_ip_versions:
            set_name = f'country-{ip_version}'
            ip_list = get_country_ip_list(config.country_list, ip_version)
            set_list = ', '.join(ip_list)
            nft_set = (
                Template(config.SET_TEMPLATE).substitute(
                    ip_version=f'ip{ip_version}', set_name=set_name, ip_list=set_list
                )
            )
            if reload:
                run(['nft', 'flush', 'set', 'inet', 'blackhole', set_name], check=True)
            if ip_list:
                run(['nft', '-f', '-'], input=nft_set.encode(), check=True)


def main():
    desc = 'Script to blocking IP in nftables by country and black lists'
    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument('action', choices=('start', 'stop', 'restart', 'reload', 'config'),
                        help='Action to nft-blackhole')
    args = parser.parse_args()
    action = args.action
    config = Config()

    if action == 'start':
        start(config)
        whitelist_sets(config)
        blacklist_sets(config)
        country_sets(config)
    elif action == 'stop':
        stop()
    elif action == 'restart':
        stop()
        start(config)
        whitelist_sets(config)
        blacklist_sets(config)
        country_sets(config)
    elif action == 'reload':
        whitelist_sets(config, reload=True)
        blacklist_sets(config, reload=True)
        country_sets(config, reload=True)
    elif action == 'config':
        print(config)


if __name__ == '__main__':
    main()
