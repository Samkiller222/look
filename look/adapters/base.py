"""The interface every public-record source implements."""

from __future__ import annotations

import json
import os
import re
import unicodedata
import urllib.parse
import urllib.request
from abc import ABC, abstractmethod
from typing import Any, Callable

from ..models import CheckType, Finding, Subject


class SourceNotConfigured(Exception):
    """The adapter needs credentials or an endpoint that has not been set."""


class SourceError(Exception):
    """The source could not be queried."""


class SourceAdapter(ABC):
    """A single official record source for one check type.

    Adapters return Findings. The screening service scrubs every finding's
    details of prohibited fields (see guardrails.PROHIBITED_FIELDS) before
    storing them, but adapters should also avoid requesting such fields.
    """

    check_type: CheckType
    name: str

    @abstractmethod
    def search(self, subject: Subject) -> list[Finding]:
        ...


# HTTP helpers --------------------------------------------------------------

Fetcher = Callable[[str, dict[str, str]], bytes]


def default_fetch(url: str, headers: dict[str, str]) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "look-screening/0.1", **headers})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read()
    except Exception as e:  # noqa: BLE001 - surface any transport error uniformly
        raise SourceError(f"{url.split('?')[0]}: {e}") from e


def get_json(fetch: Fetcher, base: str, params: dict[str, Any], headers: dict[str, str]) -> Any:
    url = base + ("&" if "?" in base else "?") + urllib.parse.urlencode(params)
    raw = fetch(url, headers)
    try:
        return json.loads(raw)
    except ValueError as e:
        raise SourceError(f"{base}: response was not JSON") from e


def env(name: str) -> str | None:
    value = os.environ.get(name)
    return value.strip() if value else None


# Name matching -------------------------------------------------------------


def normalize_name(name: str) -> str:
    """Lowercase, strip accents and punctuation, and sort tokens.

    "DOE, John A." and "john a doe" both become "a doe john".
    """
    s = unicodedata.normalize("NFKD", name)
    s = "".join(c for c in s if not unicodedata.combining(c)).lower()
    tokens = re.findall(r"[a-z0-9]+", s)
    return " ".join(sorted(tokens))


def names_match(a: str, b: str) -> bool:
    """True when every token of the shorter name appears in the longer one.

    This tolerates middle names and initials but needs at least two tokens
    in common, so a lone surname never counts as a match.
    """
    ta, tb = set(normalize_name(a).split()), set(normalize_name(b).split())
    small, large = (ta, tb) if len(ta) <= len(tb) else (tb, ta)
    return len(small) >= 2 and small <= large
