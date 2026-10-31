
"""
whitelist/blacklist IP addresses in nftables
"""

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
from http.client import HTTPResponse
from importlib.metadata import version, PackageNotFoundError
from pathlib import Path
import ssl
from string import Template
from subprocess import run
import sys
import time
from urllib.error import HTTPError
import urllib.request

from . import DEBUG_FLAG, ABSENT, Absent
from .config import Config, AddressList
from .exceptions import NftbError
from .logger import logger

if DEBUG_FLAG:
    from .debug import save_resolved_ips


# TODO: Add copius logging here and in config module

def start(config: Config):
    """Starting nft-blackhole"""
    logger.info('Starting nft-blackhole...')
    # TODO: FIX BELOW
    #####ip_data: dict[str, dict[str, set[str]] | Absent] = fetch_all_lists(config)
    _ = fetch_all_lists(config)

    if DEBUG_FLAG:
        if config.blacklist is not ABSENT:
            logger.debug('Saving blacklist')
            save_resolved_ips(config)  # pyright: ignore[reportPossiblyUnboundVariable]
    
    # TODO: FIX BELOW
    apply_nft_sets(config)

    nft_template = config.jinja_env.get_template("nft-blackhole.j2")
    nft_conf = nft_template.render(
        priority=config.priority,
        default_policy=config.default_policy,
        block_policy=config.block_policy,
        country_exclude_ports_rule=config.country_address_list.country_exclude_ports_rule,
        country_policy=config.country_address_list.country_policy,
        chain_output=config.chain_output,
        chain_forward=config.chain_forward
    )

    if DEBUG_FLAG:
        print(f'nft_conf:\n{nft_conf}\n')
    else:
        _ = run(['nft', '-f', '-'], input=nft_conf.encode(), check=True)


def stop():
    """Stopping nft-blackhole"""
    logger.info('Stopping nft-blackhole...')
    if DEBUG_FLAG:
        print(f'DEBUG_FLAG is {DEBUG_FLAG}. "Stopping nft-blackhole"')
    else:
        _ = run(['nft', 'delete', 'table', 'inet', 'blackhole'], check=True)


def restart():
    logger.info("Re-starting nft-blackhole")


def reload():
    logger.info("Re-loading nft-blackhole sets")


def fetch_all_lists(config: Config) -> None:
    '''Fetch all whitelist, blacklist and country lists with validation'''
    print(f'\n\nHERE IN fetch_all_lists:\n\tWHITELIST: {config.whitelist}\n\tBLACKLIST: {config.blacklist}')
    if config.whitelist is not ABSENT:
        _whitelist_ips = load_ip_sources(config.whitelist)
        _ = config.whitelist.split_ip_versions(_whitelist_ips)

    if config.blacklist is not ABSENT:
        _blacklist_ips = load_ip_sources(config.blacklist)
        _ = config.blacklist.split_ip_versions(_blacklist_ips)

    if config.country_address_list is not ABSENT:
        _country_list_ips = get_country_ips(config)
        _ = config.country_address_list.split_ip_versions(_country_list_ips)


def load_ip_sources(address_list: AddressList | Absent) -> list[str]:
    '''Load IP sources: extract direct IPs, read local files, and fetch URLs, splitting into v4 and v6'''
    # Read local files
    resolved_ips: list[str] = list()

    # Files
    if address_list.files is not ABSENT:
        for path in address_list.files:
            if path.startswith('#'):
                continue
            file_path = Path(path).resolve()
            try:
                with open(file_path, 'r') as f:
                    resolved_ips.extend(f.readlines())
            except OSError:
                logger.error(f'Failed to read local file {file_path}')
                continue
        
    # URLs
    if address_list.urls is not ABSENT:
        clean_urls: list[str] = list()
        url: str
        for url in address_list.urls:
            if url.startswith('#'):
                continue
            else:
                url = url.strip()
                clean_urls.append(url)
        if clean_urls:
            downloaded = get_urls(clean_urls)
            resolved_ips.extend(downloaded)

    return resolved_ips


def get_country_ips(config: Config) -> list[str]:
    '''Fetch country IP lists based on configured source and return dict per IP version'''

    urls: list[str] = []
    url_string: str
    url_templates: dict[str, str | dict[str, str]] = config.country_address_list.url_templates
    print(f'\n\nCOUNTRY LIST TEMPLATES:\n{url_templates}')
    _country_list = config.country_address_list.country_list
    for ip_ver in config.ip_version_support:
        for country in _country_list:
            if config.country_address_list.country_list_source == 'ebrasha':
                country_code = country.upper()
                url_string = url_templates[config.country_address_list.country_list_source]
            elif config.country_address_list.country_list_source == 'ipdeny':
                country_code = country.lower()
                url_string = url_templates[config.country_address_list.country_list_source][ip_ver]  # pyright: ignore[reportArgumentType]
            elif config.country_address_list.country_list_source == 'ipverse':
                country_code = country.lower()
                url_string = url_templates[config.country_address_list.country_list_source]  # pyright: ignore[reportAssignmentType]
            else:
                raise
            url: str = Template(url_string).substitute(country_code=country_code, ip_ver=ip_ver)
            urls.append(url)
            print(f'\n\nURLs:\n{urls}\n\n')

    raw_ips = get_urls(urls)

    return raw_ips


def get_urls(urls: list[str], max_retries: int=3, retry_delay: int=5, timeout: int=10) -> list[str]:
    '''Download url in threads with retry logic'''
    ip_list_aggregated: list[str] = []

    def get_url(url: str):
        for attempt in range(max_retries):
            try:
                response: HTTPResponse = urllib.request.urlopen(url, timeout=timeout)  # pyright: ignore[reportAny]
            except HTTPError as exc:
                if exc.code == 408 and attempt < max_retries - 1:
                    logger.warning(
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
        do_urls = [executor.submit(get_url, url) for url in urls]
        for out in as_completed(do_urls):
            ip_list = out.result()
            if ip_list is None:
                return list()
            ip_list_aggregated += ip_list
    return ip_list_aggregated


def apply_nft_sets(config: Config | Absent, reload: bool=False):
    '''Create all nftables sets (whitelist, blacklist, country)'''
    for address_list in config.active_address_lists:
        for ip_version in config.active_ip_versions:
            set_name = f'{address_list.list_type}-{ip_version}'
            ip_list = address_list.nft_sets[ip_version]
            set_list = ', '.join(ip_list)
            nft_set = (
                Template(config.nft_set_template).substitute(
                    ip_ver=f'ip{ip_version}', set_name=set_name, ip_list=set_list
                )
            )
            if not DEBUG_FLAG:
                if reload:
                    _ = run(['nft', 'flush', 'set', 'inet', 'blackhole', set_name], check=False)
                if ip_list:
                    _ = run(['nft', '-f', '-'], input=nft_set.encode(), check=True)
            else:
                logger.info(f'apply_nft_sets: was going to run nft command, but DEBUG_FLAG is {DEBUG_FLAG}')

                dt = datetime.now()
                mod_path = Path(__file__).resolve()

                file_path = Path(
                    f"{mod_path}/../../debug/{dt.strftime('%Y-%m-%d_%H%M%S')}_{address_list.list_type}_nft_set_{ip_version}.text"
                ).resolve()

                with open(file_path, 'w') as file_handle:
                    _ = file_handle.write(f'{nft_set}\n')



@dataclass
class NftbArgs:
    """
    We use this dataclass to allow us to type hint command line args
    """
    cmd: str
    dry_run: bool
    ignore_certs: bool
    ignore_warnings: bool


def parse_cmd() -> NftbArgs:
    desc: str = 'whitelist/blacklist IP addresses in nftables'
    parser = argparse.ArgumentParser(description=desc)
    
    _ = parser.add_argument(
        'cmd',
        choices=('start', 'stop', 'restart', 'reload', 'config'),
        help='Action to perform with nft-blackhole',
        action='store',
    )

    # TODO: Wire this up!
    _ = parser.add_argument(
        '--dry-run',
        help='Run command and show what would be done without actually doing it',
        action='store_true'
    )

    _ = parser.add_argument(
        '--ignore-certs',
        help='Ignore bad/missing SSL certificates when downloading lists',
        action='store_true',
    )

    # TODO: Wire this up!
    _ = parser.add_argument(
        '--ignore-warnings',
        help='Ignore warnings about configuration issues',
        action='store_true',
    )

    args: NftbArgs = NftbArgs(**vars(parser.parse_args()))

    return args


def main():
    logger.info(f'NFT_BLACKHOLE_DEBUG: {DEBUG_FLAG}')

    try:
        __version__ = version("nft-blackhole")
    except PackageNotFoundError:
        # package is not installed
        __version__ = '2.0.0'

    logger.info(f'RUNNING NFT-BLACKHOLE VERSION: {__version__}')

    args = parse_cmd()
    cmd: str = args.cmd

    try:
        config = Config()
    except NftbError as e:
        logger.error(e)
        sys.exit(e.exit_code)

    if args.ignore_certs:
        config.ignore_certs = args.ignore_certs

    # urllib setup
    ctx = ssl.create_default_context()

    if config.ignore_certs:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    https_handler = urllib.request.HTTPSHandler(context=ctx)
    opener = urllib.request.build_opener(https_handler)
    opener.addheaders = [(
        'User-agent',
        f'Mozilla/5.0 (compatible; nft-blackhole/{__version__}; +https://github.com/brian-farrell/nft-blackhole)'
        )]
    urllib.request.install_opener(opener)

    if cmd == 'start':
        start(config)
    elif cmd == 'stop':
        stop()
    elif cmd == 'restart':
        stop()
        start(config)
    elif cmd == 'reload':
        reload()
    elif cmd == 'config':
        print(config)
