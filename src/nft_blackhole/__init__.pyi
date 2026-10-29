
import os
from typing import Any, ClassVar, TypeAlias, override

from .config import CountryAddressList

DEBUG_FLAG: bool = bool(os.getenv('NFT_BLACKHOLE_DEBUG', False))

class AbsentSentinel(str):
	instance: ClassVar[_Absent]
	class _Absent(str):
		def __init__(self) -> None:
			self.ips: list[str]
			self.files: list[str]
			self.urls: list[str]
			self.country_exclude_ports: list[str]
			self.country_list: CountryAddressList
			self.country_list_source: str
			self.country_policy: str

		def get(self, item, default=None) -> None:
			pass

		def split_ip_versions(self, ip_list: list[str]) -> None:
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
