
import os
from typing import Any, ClassVar, TypeAlias, override

from dataclass_wizard import DataclassWizard


DEBUG_FLAG = bool(os.getenv('NFT_BLACKHOLE_DEBUG', False))

# TODO: Replace this with a true `sentinel` class when python3.15 is widely availble
# - see https://docs.python.org/3/builtins/functions.html#sentinel
class NotProvidedSentinel(str, DataclassWizard):
	"""
	NotProvidedSentinel is a sentinel to indicate that no value was given by the user.
	This is purposely different from `None` and does not mean that an expected value is missing.
	It simply means that the user does not wish to provide a value, which is completely valid.
	"""
	instance: ClassVar[_NotProvided] | None = None

	class _NotProvided(str, DataclassWizard):
		def __init__(self):
			pass

		@override
		def __str__(self) -> str:
			return f"Not Provided"

	def __new__(cls):
		if not NotProvidedSentinel.instance:
			NotProvidedSentinel.instance = NotProvidedSentinel._NotProvided()
		return NotProvidedSentinel.instance

	def __getattr__(self, attr_name: Any):  # pyright: ignore[reportAny, reportExplicitAny]
		return getattr(self.instance, attr_name)  # pyright: ignore[reportAny]

	@override
	def __setattr__(self, attr_name: Any, value: Any):  # pyright: ignore[reportAny, reportExplicitAny]
		return setattr(self.instance, attr_name, value)  # pyright: ignore[reportAny]

NotProvided: TypeAlias = NotProvidedSentinel._NotProvided
NOT_PROVIDED: NotProvided = NotProvided()
