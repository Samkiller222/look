"""Adapters for registries that are reached through a configured JSON API.

Sex-offender registries and professional license boards are run by each
state (and, in the US, federated through the DOJ's NSOPW). Bulk or automated
access is normally granted through an official API agreement or a licensed
screening provider, so these adapters take the endpoint and key from
configuration rather than scraping public search pages.

The endpoint must accept GET query parameters and return JSON shaped like:

    {"results": [{"name": "...", "summary": "...", "reference": "...",
                  "date_of_birth": "YYYY-MM-DD", ...other detail fields}]}

Write a small dedicated adapter instead if your provider's format differs.
"""

from __future__ import annotations

from typing import Any

from ..models import CheckType, Finding, Subject
from .base import Fetcher, SourceAdapter, SourceNotConfigured, default_fetch, env, get_json, names_match


class JsonRegistryAdapter(SourceAdapter):
    def __init__(
        self,
        *,
        check_type: CheckType,
        name: str,
        endpoint: str | None,
        api_key: str | None,
        env_prefix: str,
        fetch: Fetcher = default_fetch,
    ) -> None:
        self.check_type = check_type
        self.name = name
        self.endpoint = endpoint
        self.api_key = api_key
        self.env_prefix = env_prefix
        self.fetch = fetch

    def query_params(self, subject: Subject) -> dict[str, Any]:
        params: dict[str, Any] = {"name": subject.full_name}
        if subject.date_of_birth:
            params["date_of_birth"] = subject.date_of_birth.isoformat()
        if subject.jurisdiction:
            params["jurisdiction"] = subject.jurisdiction
        return params

    def keep(self, subject: Subject, rec: dict[str, Any]) -> tuple[bool, list[str]]:
        if not names_match(subject.full_name, rec.get("name", "")):
            return False, []
        basis = ["full_name"]
        dob = rec.get("date_of_birth")
        if dob and subject.date_of_birth:
            if dob != subject.date_of_birth.isoformat():
                return False, []
            basis.append("date_of_birth")
        return True, basis

    def search(self, subject: Subject) -> list[Finding]:
        if not self.endpoint or not self.api_key:
            raise SourceNotConfigured(
                f"Set {self.env_prefix}_URL and {self.env_prefix}_API_KEY to use {self.name}."
            )
        data = get_json(
            self.fetch,
            self.endpoint,
            self.query_params(subject),
            {"Authorization": f"Bearer {self.api_key}"},
        )
        findings = []
        for i, rec in enumerate(data.get("results") or []):
            ok, basis = self.keep(subject, rec)
            if not ok:
                continue
            details = {k: v for k, v in rec.items() if k not in ("summary", "reference")}
            findings.append(
                Finding(
                    check_type=self.check_type,
                    source=self.name,
                    summary=rec.get("summary") or f"Possible {self.check_type.value} record",
                    record_reference=rec.get("reference") or f"{self.name}:{i}",
                    match_basis=basis,
                    details=details,
                )
            )
        return findings


class SexOffenderRegistryAdapter(JsonRegistryAdapter):
    """Official sex-offender registry API (state registry or NSOPW partner access)."""

    def __init__(self, *, endpoint: str | None = None, api_key: str | None = None, fetch: Fetcher = default_fetch):
        super().__init__(
            check_type=CheckType.SEX_OFFENDER_REGISTRY,
            name="sex-offender-registry",
            endpoint=endpoint or env("LOOK_SOR_URL"),
            api_key=api_key or env("LOOK_SOR_API_KEY"),
            env_prefix="LOOK_SOR",
            fetch=fetch,
        )


class LicenseBoardAdapter(JsonRegistryAdapter):
    """Professional license verification through a licensing board's API.

    Unlike the other checks this one confirms a license the subject told you
    about, so it matches on license number as well as name.
    """

    def __init__(self, *, endpoint: str | None = None, api_key: str | None = None, fetch: Fetcher = default_fetch):
        super().__init__(
            check_type=CheckType.PROFESSIONAL_LICENSE,
            name="license-board",
            endpoint=endpoint or env("LOOK_LICENSE_URL"),
            api_key=api_key or env("LOOK_LICENSE_API_KEY"),
            env_prefix="LOOK_LICENSE",
            fetch=fetch,
        )

    def query_params(self, subject: Subject) -> dict[str, Any]:
        params = super().query_params(subject)
        params.pop("date_of_birth", None)
        params["license_number"] = subject.license_number
        if subject.license_type:
            params["license_type"] = subject.license_type
        return params

    def keep(self, subject: Subject, rec: dict[str, Any]) -> tuple[bool, list[str]]:
        ok, basis = super().keep(subject, rec)
        if not ok or str(rec.get("license_number", "")) != str(subject.license_number):
            return False, []
        return True, basis + ["license_number"]
