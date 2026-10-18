
import logging
import os
import sys

from cysystemd.journal import JournaldLogHandler


app_name = 'nft-blackhole'
logger = logging.getLogger(app_name)

# Get logging level from environment variable if set
DEBUG_FLAG = bool(os.getenv('NFT_BLACKHOLE_DEBUG', 'FALSE'))
if DEBUG_FLAG:
    logger.setLevel(logging.DEBUG)
else:
    logger.setLevel(logging.INFO)


LAUNCHED_BY_SYSTEMD = bool(os.getenv('LAUNCHED_BY_SYSTEMD', False))
if LAUNCHED_BY_SYSTEMD:
    log_handler = JournaldLogHandler(identifier=app_name)
    log_formatter = logging.Formatter('%(levelname)s - %(module)s line %(lineno)d: %(message)s')
else:
    log_handler = logging.StreamHandler(stream=sys.stderr)
    log_formatter = logging.Formatter(
        '%(asctime)s.%(msecs)03d - %(levelname)s - %(module)s line %(lineno)d: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
log_handler.setFormatter(log_formatter)
logger.addHandler(log_handler)
