
"""
whitelist/blacklist IP addresses in nftables
"""

import argparse
from datetime import datetime
from importlib.metadata import version, PackageNotFoundError
from pathlib import Path
import ssl
from subprocess import run
import sys
import urllib.request

from . import ABSENT, DEBUG_FLAG, NftbArgs
from .config import Config
from .exceptions import NftbError
from .logger import logger


# TODO: Add copius logging here and in config module

def start(config: Config):
    """Starting nft-blackhole"""
    _ = logger.info('Starting nft-blackhole...')  # pyright: ignore[reportUnknownVariableType, reportUnknownMemberType, reportAttributeAccessIssue]

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

    if DEBUG_FLAG or config.dry_run:
        dt = datetime.now()
        mod_path = Path(__file__).resolve()
        file_path = Path(
            f"{mod_path}/../../debug/{dt.strftime('%Y-%m-%d_%H%M%S')}_nft_conf.text"
        ).resolve()
        _ = logger.debug(f'Saving DEBUG file to: {file_path}')  # pyright: ignore[reportUnknownVariableType, reportUnknownMemberType, reportAttributeAccessIssue]

        with open(file_path, 'w') as file_handle:
            _ = file_handle.write(nft_conf)
    else:
        _ = run(['nft', '-f', '-'], input=nft_conf.encode(), check=True)

    _ = fetch_all_lists(config)
    _ = config.apply_nft_sets()


def stop(config: Config):
    """Stopping nft-blackhole"""
    _ = logger.info('Stopping nft-blackhole...')  # pyright: ignore[reportUnknownVariableType, reportUnknownMemberType, reportAttributeAccessIssue]
    if DEBUG_FLAG or config.dry_run:
        print(f'DEBUG_FLAG is {DEBUG_FLAG}. "Stopping nft-blackhole"')
    else:
        _ = run(['nft', 'delete', 'table', 'inet', 'blackhole'], check=True)


def restart(config: Config):
    _ = logger.info("Re-starting nft-blackhole")  # pyright: ignore[reportUnknownVariableType, reportUnknownMemberType, reportAttributeAccessIssue]
    stop(config=config)
    start(config=config)


def reload(config: Config):
    _ = logger.info("Re-loading nft-blackhole sets")  # pyright: ignore[reportUnknownVariableType, reportUnknownMemberType, reportAttributeAccessIssue]
    _ = fetch_all_lists(config)
    _ = config.apply_nft_sets(reload=True)


def fetch_all_lists(config: Config) -> None:
    '''Fetch all whitelist, blacklist and country lists with validation'''
    _ = logger.info("Fetching all lists...")  # pyright: ignore[reportUnknownVariableType, reportUnknownMemberType, reportAttributeAccessIssue]
    if DEBUG_FLAG:
        _ = logger.debug(f'Loading IPs for {[str(addr_l.list_type) for addr_l in config.active_address_lists]}')  # pyright: ignore[reportUnknownVariableType, reportUnknownMemberType, reportAttributeAccessIssue]

    for address_list in config.active_address_lists:
        if address_list is not ABSENT:
            ip_addr_count = address_list.load_ip_sources()
            _ = address_list.split_ip_versions(ip_addr_count)


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

    args: NftbArgs = NftbArgs(**vars(parser.parse_args()))  # pyright: ignore[reportAny]

    return args


def main():
    try:
        __version__ = version("nft-blackhole")
    except PackageNotFoundError:
        # package is not installed
        __version__ = '0.0.0'

    _ = logger.info(f'RUNNING NFT-BLACKHOLE VERSION: {__version__}')  # pyright: ignore[reportUnknownVariableType, reportUnknownMemberType, reportAttributeAccessIssue]

    args = parse_cmd()
    cmd: str = args.cmd

    _ = logger.info(f'NFT_BLACKHOLE_DEBUG: {DEBUG_FLAG}')  # pyright: ignore[reportUnknownVariableType, reportUnknownMemberType, reportAttributeAccessIssue]


    try:
        config = Config(args)
    except NftbError as e:
        _ = logger.error(e)  # pyright: ignore[reportUnknownVariableType, reportUnknownMemberType, reportAttributeAccessIssue]
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
        stop(config)
    elif cmd == 'restart':
        stop(config)
        start(config)
    elif cmd == 'reload':
        reload(config)
    elif cmd == 'config':
        print(config)
