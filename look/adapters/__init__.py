from .base import SourceAdapter, SourceError, SourceNotConfigured, names_match, normalize_name
from .corporate import OpenCorporatesAdapter
from .courts import CourtListenerAdapter
from .http_registry import JsonRegistryAdapter, LicenseBoardAdapter, SexOffenderRegistryAdapter
from .eu_sanctions import EuSanctionsAdapter
from .mock import MockAdapter, mock_adapters
from .ofac import OfacSdnAdapter


def default_adapters(region: str = "us") -> list[SourceAdapter]:
    """The real public-record adapters, configured from environment variables.

    "eu" uses the EU sanctions list as well as OFAC, and leaves out the
    US-only court and sex-offender sources. Criminal-data checks in the EU
    also need a legal-obligation basis (see guardrails.check_eu_rules).
    """
    if region == "eu":
        return [
            EuSanctionsAdapter(),
            OfacSdnAdapter(),
            OpenCorporatesAdapter(),
            LicenseBoardAdapter(),
        ]
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
    "EuSanctionsAdapter",
    "CourtListenerAdapter",
    "OpenCorporatesAdapter",
    "JsonRegistryAdapter",
    "SexOffenderRegistryAdapter",
    "LicenseBoardAdapter",
    "MockAdapter",
    "mock_adapters",
    "default_adapters",
]
