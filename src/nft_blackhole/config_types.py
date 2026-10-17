from __future__ import annotations

from dataclasses import dataclass

from dataclass_wizard.mixins.yaml import YAMLWizard


@dataclass
class Data(YAMLWizard):
    """
    Data dataclass

    """
    IP_VERSIONS: IPVERSIONS
    BLOCK_POLICY: str
    BLOCK_OUTPUT: bool
    BLOCK_FORWARD: bool
    PRIORITY: int
    WHITELIST: WHITELIST
    BLACKLIST: BLACKLIST
    COUNTRY_LIST_SOURCE: str | None
    COUNTRY_LIST: list[str] | None
    COUNTRY_POLICY: str
    COUNTRY_EXCLUDE_PORTS: list[int | str] | None


@dataclass
class IPVERSIONS:
    """
    IPVERSIONS dataclass

    """
    v4: bool
    v6: bool


@dataclass
class WHITELIST:
    """
    WHITELIST dataclass

    """
    static: list[str] | None
    file: list[str] | None
    url: list[str] | None


@dataclass
class BLACKLIST:
    """
    BLACKLIST dataclass

    """
    static: list[str] | None
    file: list[str] | None
    url: list[str] | None
