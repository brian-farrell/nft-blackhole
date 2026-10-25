
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
	instance: ClassVar[_Absent] | None = None

	class _Absent(str):
		def __init__(self):
			pass

		@override
		def __str__(self) -> str:
			return f"Absent"

	def __new__(cls):
		if not AbsentSentinel.instance:
			AbsentSentinel.instance = AbsentSentinel._Absent()
		return AbsentSentinel.instance

	def __getattr__(self, attr_name: Any):
		return getattr(self.instance, attr_name)

	@override
	def __setattr__(self, attr_name: Any, value: Any):
		return setattr(self.instance, attr_name, value)

Absent: TypeAlias = AbsentSentinel._Absent
ABSENT: Absent = Absent()
