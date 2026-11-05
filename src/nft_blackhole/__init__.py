
from dataclasses import dataclass
from enum import StrEnum
import os
from typing import Any, ClassVar, TypeAlias, override


DEBUG_FLAG = bool(os.getenv('NFT_BLACKHOLE_DEBUG', False))

# TODO: Replace this with a true `sentinel` class when python3.15 is widely availble
# - see https://docs.python.org/3/builtins/functions.html#sentinel
class AbsentSentinel(str):
	"""
	AbsentSentinel is a sentinel to indicate that no value was given by the user.
	This is purposely different from `None` and does not mean that an expected value is missing.
	It simply means that the user does not wish to provide a value, which is completely valid.
	"""
	# TODO: Figure out what needs to be here and what should be in type stub
	instance: ClassVar[_Absent]

	class _Absent(str):
		def __init__(self):
			self.list_type: str = "'Absent'"

		def get(self, item: Any, default: Any = None) -> Any:  # pyright: ignore[reportAny, reportExplicitAny, reportUnusedParameter]
			return None

		def split_ip_versions(self, ip_addr_count: int | None) -> None:
			assert isinstance(ip_addr_count, int | None)

		@override
		def __str__(self) -> str:
			return f"Absent"

	def __new__(cls) -> _Absent:
		if not AbsentSentinel.instance:
			AbsentSentinel.instance = AbsentSentinel._Absent()
		return AbsentSentinel.instance

	def __getattr__(self, attr_name: Any):  # pyright: ignore[reportAny, reportExplicitAny]
		return getattr(self.instance, attr_name)  # pyright: ignore[reportAny]

	@override
	def __setattr__(self, attr_name: Any, value: Any):  # pyright: ignore[reportAny, reportExplicitAny]
		return setattr(self.instance, attr_name, value)  # pyright: ignore[reportAny]

Absent: TypeAlias = AbsentSentinel._Absent  # pyright: ignore[reportPrivateUsage]
ABSENT: Absent = Absent()


@dataclass
class NftbArgs:
    """
    We use this dataclass to allow us to type hint command line args
    """
    cmd: str
    dry_run: bool
    ignore_certs: bool
    ignore_warnings: bool

    def __post_init__(self):
        assert isinstance(self.cmd, str)
        assert isinstance(self.dry_run, bool)
        assert isinstance(self.ignore_certs, bool)
        assert isinstance(self.ignore_warnings, bool)


class NftbColorCodes(StrEnum):
    BB_CYAN = "\x1b[1;38;5;123m"	# bold/bright cyan
    BB_MAGENTA =  "\x1b[1;35m"		# bright/bold magenta (pink)
    BB_RED = "\x1b[1;31m"			# bright/bold red
    BB_YELLOW = "\x1b[1;33m"		# bright/bold yellow
    BB_GREEN = "\x1b[1;92m"			# bright/bold green
    GREEN = "\x1b[0;92m"			# green
    LIGHT_GRAY = "\x1b[0;37m"		# white / light gray
    ORANGE = "\x1b[38;5;166m"		# orange / rust
    RESET = "\x1b[0m"				# reset to default coloring
