
"""
whitelist/blacklist IP addresses in nftables
"""

import argparse
from dataclasses import dataclass
from datetime import datetime
from importlib.metadata import version, PackageNotFoundError
from pathlib import Path
import ssl
from string import Template
from subprocess import run
import sys
import urllib.request

from . import DEBUG_FLAG, ABSENT, Absent
from .config import Config
from .exceptions import NftbError
from .logger import logger

if DEBUG_FLAG:
    from .debug import save_resolved_ips


# TODO: Add copius logging here and in config module

def start(config: Config):
    """Starting nft-blackhole"""
    _ = logger.info('Starting nft-blackhole...')  # pyright: ignore[reportUnknownVariableType, reportUnknownMemberType, reportAttributeAccessIssue]
    _ = logger.debug("Calling fetch_all_lists(config)")  # pyright: ignore[reportUnknownVariableType, reportUnknownMemberType, reportAttributeAccessIssue]
    _ = fetch_all_lists(config)

    if DEBUG_FLAG:
        _ = logger.debug('Saving Resolved IPs')  # pyright: ignore[reportUnknownVariableType, reportUnknownMemberType, reportAttributeAccessIssue]
        save_resolved_ips(config)  # pyright: ignore[reportPossiblyUnboundVariable]
    
    _ = logger.debug("Calling apply_nft_sets(config)")  # pyright: ignore[reportUnknownVariableType, reportUnknownMemberType, reportAttributeAccessIssue]
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
        print(f'\x1b[38;5;166mnft_conf:\n{nft_conf}\n\x1b[0m')
    else:
        _ = run(['nft', '-f', '-'], input=nft_conf.encode(), check=True)


def stop():
    """Stopping nft-blackhole"""
    _ = logger.info('Stopping nft-blackhole...')  # pyright: ignore[reportUnknownVariableType, reportUnknownMemberType, reportAttributeAccessIssue]
    if DEBUG_FLAG:
        print(f'DEBUG_FLAG is {DEBUG_FLAG}. "Stopping nft-blackhole"')
    else:
        _ = run(['nft', 'delete', 'table', 'inet', 'blackhole'], check=True)


def restart():
    _ = logger.info("Re-starting nft-blackhole")  # pyright: ignore[reportUnknownVariableType, reportUnknownMemberType, reportAttributeAccessIssue]


def reload():
    _ = logger.info("Re-loading nft-blackhole sets")  # pyright: ignore[reportUnknownVariableType, reportUnknownMemberType, reportAttributeAccessIssue]


def fetch_all_lists(config: Config) -> None:
    '''Fetch all whitelist, blacklist and country lists with validation'''
    if DEBUG_FLAG:
        _ = logger.debug(f'Loading IPs for {[str(addr_l.list_type) for addr_l in config.active_address_lists]}')  # pyright: ignore[reportUnknownVariableType, reportUnknownMemberType, reportAttributeAccessIssue]

    for address_list in config.active_address_lists:
        if address_list is not ABSENT:
            _ = address_list.load_ip_sources()
            if DEBUG_FLAG:
                _ = logger.debug(f'Loaded  {len(address_list.resolved_ips)} IP Addresses for {str(address_list.list_type)}-> running split_ip_versions')  # pyright: ignore[reportUnknownVariableType, reportUnknownMemberType, reportAttributeAccessIssue, reportUnknownArgumentType]
            _ = address_list.split_ip_versions()


def apply_nft_sets(config: Config | Absent, reload: bool=False):
    '''Create all nftables sets (whitelist, blacklist, country)'''
    for address_list in config.active_address_lists:
        for ip_version in config.active_ip_versions:
            set_name = f'{address_list.list_type}-{ip_version}'
            ip_list = address_list.nft_sets.get('ip_version')
            if ip_list:
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
                    _ = logger.info(f'apply_nft_sets: was going to run nft command for {address_list.list_type}, but DEBUG_FLAG is {DEBUG_FLAG}')  # pyright: ignore[reportUnknownVariableType, reportUnknownMemberType, reportAttributeAccessIssue]

                    dt = datetime.now()
                    mod_path = Path(__file__).resolve()

                    file_path = Path(
                        f"{mod_path}/../../debug/{dt.strftime('%Y-%m-%d_%H%M%S')}_{address_list.list_type}_nft_set_{ip_version}.text"
                    ).resolve()

                    _ = logger.debug(f'Saving DEBUG file to: {file_path}')  # pyright: ignore[reportUnknownVariableType, reportUnknownMemberType, reportAttributeAccessIssue]

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
