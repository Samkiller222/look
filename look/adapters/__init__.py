from .base import SourceAdapter, SourceError, SourceNotConfigured, names_match, normalize_name
from .corporate import OpenCorporatesAdapter
from .courts import CourtListenerAdapter
from .http_registry import JsonRegistryAdapter, LicenseBoardAdapter, SexOffenderRegistryAdapter
from .mock import MockAdapter, mock_adapters
from .ofac import OfacSdnAdapter


def default_adapters() -> list[SourceAdapter]:
    """The real public-record adapters, configured from environment variables."""
    return [
        OfacSdnAdapter(),
        SexOffenderRegistryAdapter(),
        CourtListenerAdapter(),
        OpenCorporatesAdapter(),
        LicenseBoardAdapter(),
    ]


__all__ = [
    "SourceAdapter",
    "SourceError",
    "SourceNotConfigured",
    "names_match",
    "normalize_name",
    "OfacSdnAdapter",
    "CourtListenerAdapter",
    "OpenCorporatesAdapter",
    "JsonRegistryAdapter",
    "SexOffenderRegistryAdapter",
    "LicenseBoardAdapter",
    "MockAdapter",
    "mock_adapters",
    "default_adapters",
]
