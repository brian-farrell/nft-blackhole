
"""
whitelist/blacklist IP addresses in nftables
"""

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
import ssl
from string import Template
from subprocess import run
import sys
import time
import urllib.request

from . import DEBUG_FLAG
from .config import Config
from .logger import logger


def start(config: Config):
    """Starting nft-blackhole"""
    logger.info('Starting nft-blackhole...')
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


def get_urls(urls, max_retries=3, retry_delay=5):
    '''Download url in threads with retry logic'''
    ip_list_aggregated = []
    def get_url(url):
        for attempt in range(max_retries):
            try:
                response = urllib.request.urlopen(url, timeout=10)
                content = response.read().decode('utf-8')
            except BaseException as exc:
                if attempt < max_retries - 1:
                    print(f'WARNING: Failed to fetch {url} on attempt {attempt+1}/{max_retries}. Retrying in {retry_delay}s. Error: {exc}', file=sys.stderr)
                    time.sleep(retry_delay)
                    continue
                else:
                    print(f'ERROR: Failed to fetch {url} after {max_retries} attempts. Giving up. Final error: {exc}', file=sys.stderr)
                    return None
            else:
                return content.splitlines()
        return None

    with ThreadPoolExecutor(max_workers=8) as executor:
        do_urls = [executor.submit(get_url, url) for url in urls]
        for out in as_completed(do_urls):
            ip_list = out.result()
            if ip_list is None:
                return list()
            ip_list_aggregated += ip_list
    return ip_list_aggregated


def get_country_ips(config: Config):
    '''Fetch country IP lists based on configured source and return dict per IP version'''
    if not config.country_list:
        return {'v4': set(), 'v6': set()}

    urls = []
    for ip_ver in IP_VER:
        for country in country_list:
            c_lower = country.lower()
            if country_list_source == 'ebrasha':
                c_upper = country.upper()
                url = f'https://raw.githubusercontent.com/ebrasha/cidr-ip-ranges-by-country/refs/heads/master/CIDR/{c_upper}-ip{ip_ver}-Hackers.Zone.txt'
            elif country_list_source == 'ipdeny':
                if ip_ver == 'v4':
                    url = f'https://www.ipdeny.com/ipblocks/data/aggregated/{c_lower}-aggregated.zone'
                else:
                    url = f'https://www.ipdeny.com/ipv6/ipaddresses/aggregated/{c_lower}-aggregated.zone'
            else:  # ipverse
                url = f'https://raw.githubusercontent.com/ipverse/geo-ip-blocks/refs/heads/master/country/{c_lower}/{c_lower}-ip{ip_ver}.txt'
            urls.append(url)

    raw_ips = get_urls(urls)
    if raw_ips is None:
        return None

    return split_ip_versions(raw_ips)


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


def load_ip_sources(config_entry):
    '''Load IP sources: extract direct IPs, read local files, and fetch URLs, splitting into v4 and v6'''
    if not config_entry:
        return {'v4': set(), 'v6': set()}

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


def fetch_all_lists():
    '''Fetch all whitelist, blacklist and country lists with validation'''
    whitelist_ips = load_ip_sources(whitelist)
    if whitelist_ips is None:
        return None

    blacklist_ips = load_ip_sources(blacklist)
    if blacklist_ips is None:
        return None

    country_ips = get_country_ips()
    if country_ips is None:
        return None
    return {'whitelist': whitelist_ips, 'blacklist': blacklist_ips, 'country': country_ips}


def apply_nft_sets(ip_data, reload=False):
    '''Create all nftables sets (whitelist, blacklist, country)'''
    for set_type in ('whitelist', 'blacklist', 'country'):
        for ip_ver in IP_VER:
            set_name = f'{set_type}-{ip_ver}'
            ip_list = ip_data[set_type][ip_ver]
            set_list = ', '.join(ip_list)
            nft_set = (Template(SET_TEMPLATE).substitute(ip_ver=f'ip{ip_ver}', set_name=set_name, ip_list=set_list))
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

    args = parse_cmd()
    cmd: str = args.cmd

    config = Config()

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
        'Mozilla/5.0 (compatible; nft-blackhole/0.1.0; +https://github.com/brian-farrell/nft-blackhole)'
        )]
    urllib.request.install_opener(opener)

    if cmd == 'start':
        logger.info("Starting blackhole")
        start(config)
    elif cmd == 'stop':
        logger.info("Stopping blackhole")
        stop()
    elif cmd == 'restart':
        logger.info("Re-starting blackhole")
        stop()
        start(config)
    elif cmd == 'reload':
        logger.info("Re-loading blackhole sets")
    elif cmd == 'config':
        print(config)

    return 0


if __name__ == '__main__':
    sys.exit(main())
