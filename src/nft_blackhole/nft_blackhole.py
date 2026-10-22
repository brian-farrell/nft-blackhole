
"""
whitelist/blacklist IP addresses in nftables
"""

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from http.client import HTTPResponse
from importlib.metadata import version, PackageNotFoundError
import ssl
from string import Template
from subprocess import run
import sys
import time
from urllib.error import HTTPError
import urllib.request

from . import DEBUG_FLAG, NOT_PROVIDED, NotProvided
from .config import Config
from .config_types import WHITELIST, BLACKLIST
from .exceptions import ExitCode, NftbDataError, NftbError, NftbConfigError
from .logger import logger


def start(config: Config):
    """Starting nft-blackhole"""
    logger.info('Starting nft-blackhole...')
    ip_data: dict[str, dict[str, set[str]] | NotProvided] = fetch_all_lists(config)
    apply_nft_sets(config, ip_data)

    nft_template = config.jinja_env.get_template("nft-blackhole.j2")
    nft_conf = nft_template.render(
        priority=config.priority,
        default_policy=config.default_policy,
        block_policy=config.block_policy,
        country_exclude_ports_rule=config.country_exclude_ports_rule,
        country_policy=config.country_policy,
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


def fetch_all_lists(config: Config) -> dict[str, dict[str, set[str]] | NotProvided]:
    '''Fetch all whitelist, blacklist and country lists with validation'''
    whitelist_ips: dict[str, set[str]] | NotProvided = load_ip_sources(config.whitelist)
    blacklist_ips: dict[str, set[str]] | NotProvided = load_ip_sources(config.blacklist)
    country_ips: dict[str, set[str]] | NotProvided = get_country_ips(config)

    ip_sets = {'whitelist': whitelist_ips, 'blacklist': blacklist_ips, 'country': country_ips}

    return ip_sets


def load_ip_sources(config_entry: WHITELIST | BLACKLIST) -> dict[str, set[str]]:
    '''Load IP sources: extract direct IPs, read local files, and fetch URLs, splitting into v4 and v6'''
    raw_ips = []
    file_paths = []
    urls = []

    def to_list(val):
        if not val:
            return []
        if isinstance(val, list):
            return val
        return [val]

    if isinstance(config_entry, dict):
        if any(k in config_entry for k in ('static', 'file', 'url')):
            raw_ips.extend(to_list(config_entry.get('static')))
            file_paths.extend(to_list(config_entry.get('file')))
            urls.extend(to_list(config_entry.get('url')))
        else:
            # BACKWARD COMPATIBILITY: Legacy dictionary format (v4, v6).
            # Remove this block when migrating fully to static/file/url format.
            for key in ['v4', 'v6']:
                for item in to_list(config_entry.get(key)):
                    item_str = str(item).strip()
                    if item_str.startswith(('http://', 'https://')):
                        urls.append(item_str)
                    else:
                        raw_ips.append(item_str)
            # END BACKWARD COMPATIBILITY
    elif isinstance(config_entry, list):
        # BACKWARD COMPATIBILITY: Flat list format.
        # Remove this block when migrating fully to static/file/url format.
        for item in config_entry:
            if not item:
                continue
            item_str = str(item).strip()
            if item_str.startswith(('http://', 'https://')):
                urls.append(item_str)
            else:
                raw_ips.append(item_str)
        # END BACKWARD COMPATIBILITY

    # Read local files
    for filepath in file_paths:
        if not filepath:
            continue
        filepath = str(filepath).strip()
        if not filepath or filepath.startswith('#'):
            continue
        try:
            with open(filepath, 'r') as f:
                raw_ips.extend(f.readlines())
        except OSError as exc:
            print(f'ERROR: Failed to read local file {filepath}: {exc}', file=sys.stderr)
            return None

    # Fetch URLs
    if urls:
        clean_urls = []
        for u in urls:
            if not u:
                continue
            u_str = str(u).strip()
            if u_str and not u_str.startswith('#'):
                clean_urls.append(u_str)
        if clean_urls:
            unique_urls = list(dict.fromkeys(clean_urls))
            downloaded = get_urls(unique_urls)
            if downloaded is None:
                return None
            raw_ips.extend(downloaded)

    return split_ip_versions(raw_ips)


def get_country_ips(config: Config) -> dict[str, set[str]] | NotProvided:
    '''Fetch country IP lists based on configured source and return dict per IP version'''
    if not config.country_list:
        return {'v4': set(), 'v6': set()}

    urls: list[str] = []
    url_string: str
    url_templates: dict[str, str | dict[str, str]] = config.url_templates
    print(f'COUNTRY LIST TEMPLATES:\n{url_templates}')
    for ip_ver in config.ip_version_support:
        for country in config.country_list:
            if config.country_list_source == 'ebrasha':
                country_code = country.upper()
                url_string = url_templates[config.country_list_source]  # pyright: ignore[reportAssignmentType]
            elif config.country_list_source == 'ipdeny':
                country_code = country.lower()
                url_string = url_templates[config.country_list_source][ip_ver]  # pyright: ignore[reportArgumentType]
            elif config.country_list_source == 'ipverse':
                country_code = country.lower()
                url_string = url_templates[config.country_list_source]  # pyright: ignore[reportAssignmentType]
            else:
                raise
            url: str = Template(url_string).substitute(country_code=country_code, ip_ver=ip_ver)
            urls.append(url)

    raw_ips = get_urls(urls)

    if not raw_ips:
        return None

    return split_ip_versions(raw_ips)


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


def split_ip_versions(ip_list) -> dict[str, set[str]]:
    '''Split mixed list into deduplicated IPv4 and IPv6 sets'''
    split_ips: dict[str, set[str]] = {'v4': set(), 'v6': set()}
    v4_add = split_ips['v4'].add
    v6_add = split_ips['v6'].add

    for line in ip_list:
        if '#' in line:
            line = line.partition('#')[0]
        parts = line.split()
        if not parts:
            continue
        entry = parts[0]
        if ':' in entry:
            v6_add(entry)
        elif '.' in entry:
            v4_add(entry)

    return split_ips


def apply_nft_sets(config: Config, ip_data: dict[str, dict[str, set[str]] | NotProvided], reload: bool=False):
    '''Create all nftables sets (whitelist, blacklist, country)'''
    print(f"!!!!! ip_data:\n\n{ip_data}\n\n")
    for set_type in ('whitelist', 'blacklist', 'country'):
        for ip_ver in config.ip_version_support:
            set_name = f'{set_type}-{ip_ver}'
            ip_list = ip_data[set_type][ip_ver]
            set_list = ', '.join(ip_list)
            nft_set = (
                Template(config.nft_set_template).substitute(ip_ver=f'ip{ip_ver}', set_name=set_name, ip_list=set_list)
            )
            if reload:
                _ = run(['nft', 'flush', 'set', 'inet', 'blackhole', set_name], check=False)
            if ip_list:
                _ = run(['nft', '-f', '-'], input=nft_set.encode(), check=True)


@dataclass
class NftbArgs:
    """
    We use this dataclass to allow us to type hint command line args
    """
    cmd: str
    ignore_certs: bool


def parse_cmd() -> NftbArgs:
    desc: str = 'whitelist/blacklist IP addresses in nftables'
    parser = argparse.ArgumentParser(description=desc)
    
    _ = parser.add_argument(
        'cmd',
        choices=('start', 'stop', 'restart', 'reload', 'config'),
        help='Action to nft-blackhole',
        action='store',
    )

    _ = parser.add_argument(
        '--ignore-certs',
        action='store_true',
    )

    args: NftbArgs = NftbArgs(**vars(parser.parse_args()))  # pyright: ignore[reportAny]

    return args


def main():
    logger.info(f'NFT_BLACKHOLE_DEBUG: {DEBUG_FLAG}')

    try:
        __version__ = version("package-name")
    except PackageNotFoundError:
        # package is not installed
        __version__ = '2.0.0'

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


if __name__ == '__main__':
    try:
        main()
    except NtfbError as e:
        logger.error(e)
        sys.exit(ExitCode.EX_CONFIG)
