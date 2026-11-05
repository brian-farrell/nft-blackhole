
from dataclasses import dataclass
from enum import StrEnum
import os
from typing import Any, ClassVar, TypeAlias, override

from .config import AddressList, AddressListType, CountryAddressList, CountryListSource

DEBUG_FLAG: bool = bool(os.getenv('NFT_BLACKHOLE_DEBUG', False))

class AbsentSentinel(str):
	instance: ClassVar[_Absent]
	class _Absent(str):
		nft_set_template: str
		url_templates: ClassVar[dict[str, str | dict[str, str]]]
		def __init__(self) -> None:
			self.active_address_lists: list[AddressList | CountryAddressList | Absent]
			self.active_ip_versions: list[str]
			self.country_exclude_ports: list[str]
			self.country_exclude_ports_rule: str
			self.country_address_list: CountryAddressList
			self.country_list: list[str]
			self.country_list_source: CountryListSource
			self.country_policy: str
			self.files: list[str]
			self.ips: list[str]
			self.list_type: AddressListType
			self.nft_sets: dict[str, list[str]]
			self.urls: list[str]

		def append(self, value: str | list[str] | None = None) -> None:
			pass

		def get(self, item, default=None) -> None:
			pass

		def load_ip_sources(self) -> None:
			pass

		def split_ip_versions(self, ip_addr_count: int | None) -> None:
			pass

		@override
		def __str__(self) -> str:
			pass

	def __new__(cls) -> _Absent:
		if not AbsentSentinel.instance:
			AbsentSentinel.instance = AbsentSentinel._Absent()

	def split_ip_versions(self, ip_list: list[str]) -> None:
		pass

	def __getattr__(self, attr_name: Any) -> Any:
		pass

	@override
	def __setattr__(self, attr_name: Any, value: Any) -> None:
		pass

Absent: TypeAlias = AbsentSentinel._Absent
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

class NftbColorCodes(StrEnum):
    BB_CYAN = "\x1b[1;38;5;123m"
    BB_MAGENTA =  "\x1b[1;35m"
    BB_RED = "\x1b[1;31m"
    BB_YELLOW = "\x1b[1;33m"
    BB_GREEN = "\x1b[1;92m"
    GREEN = "\x1b[0;92m"
    LIGHT_GRAY = "\x1b[0;37m"
    ORANGE = "\x1b[38;5;166m"
    RESET = "\x1b[0m"
