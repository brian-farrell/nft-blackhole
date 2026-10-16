from __future__ import annotations

from dataclasses import dataclass
from typing import override
from urllib import parse

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

@dataclass(init=False)
class URL:
    scheme: str
    netloc: str
    path: str
    query: str
    fragment: str

    def __init__(self, url_string: str) -> None:
        addr = parse.urlsplit(url_string)
        self.scheme = addr.scheme
        self.netloc = addr.netloc
        self.path = addr.path
        self.query = addr.query
        self.fragment = addr.fragment

    def __post_init__(self):
        assert all([self.scheme, self.netloc, self.path])
        assert self.scheme == 'https'

    @override
    def __str__(self) -> str:
        if self.scheme:
            return self.scheme + '://' + self.netloc + self.path + self.query + self.fragment
        else:
            return self.netloc + self.path + self.query + self.fragment
