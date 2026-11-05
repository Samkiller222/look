"""Company officer and director roles through the OpenCorporates API.

Docs: https://api.opencorporates.com/documentation/API-Reference
Set LOOK_OPENCORPORATES_TOKEN to an API token.

OpenCorporates officer records sometimes include a service address. The
adapter does not copy it, and the screening service scrubs it anyway.
"""

from __future__ import annotations

from ..models import CheckType, Finding, Subject
from .base import Fetcher, SourceAdapter, SourceNotConfigured, default_fetch, env, get_json, names_match

SEARCH_URL = "https://api.opencorporates.com/v0.4/officers/search"


class OpenCorporatesAdapter(SourceAdapter):
    check_type = CheckType.CORPORATE_REGISTRY
    name = "opencorporates"

    def __init__(self, *, token: str | None = None, fetch: Fetcher = default_fetch):
        self.token = token or env("LOOK_OPENCORPORATES_TOKEN")
        self.fetch = fetch

    def search(self, subject: Subject) -> list[Finding]:
        if not self.token:
            raise SourceNotConfigured("Set LOOK_OPENCORPORATES_TOKEN to search corporate registries.")
        params = {"q": subject.full_name, "api_token": self.token, "per_page": 30}
        if subject.jurisdiction:
            params["jurisdiction_code"] = subject.jurisdiction.lower().replace("-", "_")
        data = get_json(self.fetch, SEARCH_URL, params, {})
        officers = ((data.get("results") or {}).get("officers")) or []
        findings = []
        for wrapper in officers:
            o = wrapper.get("officer") or {}
            if not names_match(subject.full_name, o.get("name", "")):
                continue
            company = o.get("company") or {}
            findings.append(
                Finding(
                    check_type=self.check_type,
                    source=self.name,
                    summary=f"{o.get('position') or 'Officer'} of {company.get('name', 'unknown company')}",
                    record_reference=o.get("opencorporates_url") or str(o.get("id")),
                    match_basis=["full_name"],
                    details={
                        "listed_name": o.get("name"),
                        "position": o.get("position"),
                        "start_date": o.get("start_date"),
                        "end_date": o.get("end_date"),
                        "company_name": company.get("name"),
                        "company_number": company.get("company_number"),
                        "company_jurisdiction": company.get("jurisdiction_code"),
                    },
                )
            )
        return findings
