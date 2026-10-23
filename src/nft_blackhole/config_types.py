
from dataclasses import dataclass

from dataclass_wizard.mixins.yaml import YAMLWizard


@dataclass
class Data(YAMLWizard):
    """
    Data dataclass

    """
    blacklist: BLACKLIST
    block_forward: bool
    block_output: bool
    block_policy: str
    country_exclude_ports: list[int | str] | None
    country_list: list[str] | None
    country_list_source: str | None
    country_policy: str
    ip_version_support: IPVERSION
    priority: int
    whitelist: WHITELIST
    ignore_certs: bool = False
        

@dataclass
class IPVERSION:
    """
    IPVERSIONS dataclass

    """
    v4: bool = False
    v6: bool = False


@dataclass
class WHITELIST:
    """
    WHITELIST dataclass

    """
    static: list[str] | None
    file: list[str] | None
    url: list[str] | None

    def __iter__(self):
        for field in self.__dataclass_fields__:
            yield getattr(self, field)



@dataclass
class BLACKLIST:
    """
    BLACKLIST dataclass

    """
    static: list[str] | None
    file: list[str] | None
    url: list[str] | None

    def __iter__(self):
        for field in self.__dataclass_fields__:
            yield getattr(self, field)
