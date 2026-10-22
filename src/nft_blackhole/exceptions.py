
"""
nft-blckhole generates whitelist/blacklist IP addresses for nftables
"""


from enum import IntEnum
from typing import final, override

@final
class ExitCode(IntEnum):
    """Enumeration of exit codes.

    This class implements POSIX error codes, as found in
    /usr/include/sysexits.h on the Linux platform and
    described in the manual page for sysexit on BSD systems,
    including Darwin (macOS).

    Additional information is availble from The Linux Documnetation Project
    at http://tldp.org/LDP/abs/html/exitcodes.html
    """
    EX_SUCCESS = 0  # command exits successfully
    EX_GENERAL = 1  # catchall for general errors
    EX_USAGE = 64  # command line usage error
    EX_DATAERR = 65  # data format error
    EX_NOINPUT = 66  # cannot open input
    EX_NOUSER = 67  # addressee unknown
    EX_NOHOST = 68  # host name unknown
    EX_UNAVAILABLE = 69  # service unavailable
    EX_SOFTWARE = 70  # internal software error
    EX_OSERR = 71  # system error (e.g., can't fork)
    EX_OSFILE = 72  # critical OS file missing
    EX_CANTCREAT = 73  # can't create (user) output file
    EX_IOERR = 74  # input/output error
    EX_TEMPFAIL = 75  # temp failure; user is invited to retry
    EX_PROTOCOL = 76  # remote error in protocol
    EX_NOPERM = 77  # permission denied
    EX_CONFIG = 78  # configuration error
    EX_SIGINT = 130  # keyboard interrupt


class NftbError(Exception):
    def __init__(self, exit_code: int, message: str):
        super(NftbError, self).__init__()
        self.exit_code: int = exit_code
        self.message: str = message

    @override
    def __str__(self):
        return self.message


class NftbConfigError(NftbError):
    def __init__(self, message: str):
        super(NftbConfigError, self).__init__(ExitCode.EX_CONFIG, message)


class NotImplementedException(NftbError):
    def __init__(self, message: str):
        super(NotImplementedException, self).__init__(ExitCode.EX_SOFTWARE, message)


class NftbDataError(NftbError):
    """docstring for NftbDataError"""
    def __init__(self, message: str):
        super(NftbDataError, self).__init__(ExitCode.EX_DATAERR, message)
        