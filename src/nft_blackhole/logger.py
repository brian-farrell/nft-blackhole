
import logging
import os
import sys
from typing import final, override
from cysystemd.journal import JournaldLogHandler
from nft_blackhole.exceptions import NftbError, ExitCode

from . import DEBUG_FLAG, NftbColorCodes as cc

# Logging formatter supporting colored output
@final
class LogFormatter(logging.Formatter):

    COLOR_CODES = {
        logging.CRITICAL: cc.BB_MAGENTA,
        logging.ERROR:    cc.BB_RED,
        logging.WARNING:  cc.BB_YELLOW,
        logging.INFO:     cc.LIGHT_GRAY,
        logging.DEBUG:    cc.BB_CYAN
    }

    def __init__(self, color, *args, **kwargs):
        super(LogFormatter, self).__init__(*args, **kwargs)
        self.color = color

    @override
    def format(self, record, *args, **kwargs):
        if (self.color == True and record.levelno in self.COLOR_CODES):
            record.color_on  = self.COLOR_CODES[record.levelno]
            record.color_off = cc.RESET
        else:
            record.color_on  = ""
            record.color_off = ""
        return super(LogFormatter, self).format(record, *args, **kwargs)


# Setup logging
def setup_logging(
    console_log_output: str, console_log_level: str, console_log_color,
    logfile_file, logfile_log_level, logfile_log_color,
    log_line_template
    ):

    # Create logger
    # For simplicity, we use the root logger, i.e. call 'logging.getLogger()'
    # without name argument. This way we can simply use module methods for
    # for logging throughout the script. An alternative would be exporting
    # the logger, i.e. 'global logger; logger = logging.getLogger("<name>")'
    logger = logging.getLogger()

    # Set global log level to 'debug' (required for handler levels to work)
    if DEBUG_FLAG:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    # Create console handler
    console_log_output = console_log_output.lower()
    if (console_log_output == "stdout"):
        console_log_output: stdout = sys.stdout  # pyright: ignore[reportRedeclaration]
    elif (console_log_output == "stderr"):
        console_log_output: stderr = sys.stderr
    else:
        print(f'Failed to set console output: invalid output: "{console_log_output}"')
        return False
    console_handler = logging.StreamHandler(console_log_output)

    # Set console log level
    try:
        console_handler.setLevel(console_log_level.upper()) # only accepts uppercase level names
    except:
        print(f'Failed to set console log level: invalid level: "{console_log_level}"')
        return False

    # Create and set formatter, add console handler to logger
    console_formatter = LogFormatter(fmt=log_line_template, color=console_log_color, datefmt='%Y-%m-%d %H:%M:%S')
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    # Create log file handler
    try:
        logfile_handler = logging.FileHandler(logfile_file)
    except Exception as exception:
        print("Failed to set up log file: %s" % str(exception))
        return False

    # Set log file log level
    try:
        logfile_handler.setLevel(logfile_log_level.upper()) # only accepts uppercase level names
    except:
        print("Failed to set log file log level: invalid level: '%s'" % logfile_log_level)
        return False

    # Create and set formatter, add log file handler to logger
    logfile_formatter = LogFormatter(fmt=log_line_template, color=logfile_log_color)
    logfile_handler.setFormatter(logfile_formatter)
    logger.addHandler(logfile_handler)

    # Success
    return logger

app_name = 'nft-blackhole'

LAUNCHED_BY_SYSTEMD = bool(os.getenv('LAUNCHED_BY_SYSTEMD', False))
if LAUNCHED_BY_SYSTEMD:
    log_handler = JournaldLogHandler(identifier=app_name)
    log_formatter = logging.Formatter('%(levelname)s - %(module)s line %(lineno)d: %(message)s')
else:
    # log_handler = logging.StreamHandler(stream=sys.stderr)
    if DEBUG_FLAG:
        _console_log_level = "DEBUG"
    else:
        _console_log_level = "INFO"

    try:
        logger = setup_logging(
            console_log_output="stdout", console_log_level=_console_log_level, console_log_color=True,
            logfile_file=app_name + ".log", logfile_log_level="debug", logfile_log_color=False,
            log_line_template="%(color_on)s[%(asctime)s] [%(levelname)-8s] [%(module)s] [%(funcName)s] line %(lineno)d:  %(message)s%(color_off)s"
        )
    except Exception as e:
        raise NftbError(ExitCode.EX_GENERAL, f"{e}")


##logger = logging.getLogger(app_name)

# Get logging level from environment variable if set


    ### log_formatter = logging.Formatter(
    ###     '%(asctime)s.%(msecs)03d - %(levelname)s - %(module)s line %(lineno)d: %(message)s',
    ###     datefmt='%Y-%m-%d %H:%M:%S'
    ### )
###     log_formatter = LogFormatter()
### log_handler.setFormatter(log_formatter)
### logger.addHandler(log_handler)
