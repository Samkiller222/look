"""Federal court records through the CourtListener (Free Law Project) API.

Docs: https://www.courtlistener.com/help/api/rest/
Set LOOK_COURTLISTENER_TOKEN to an API token from a free CourtListener account.

Federal dockets only. State criminal records vary by state and are usually
reached through a licensed provider; add another adapter for those.
"""

from __future__ import annotations

from ..models import CheckType, Finding, Subject
from .base import Fetcher, SourceAdapter, SourceNotConfigured, default_fetch, env, get_json

SEARCH_URL = "https://www.courtlistener.com/api/rest/v4/search/"


class CourtListenerAdapter(SourceAdapter):
    check_type = CheckType.COURT_RECORDS
    name = "courtlistener"

    def __init__(self, *, token: str | None = None, fetch: Fetcher = default_fetch, max_results: int = 20):
        self.token = token or env("LOOK_COURTLISTENER_TOKEN")
        self.fetch = fetch
        self.max_results = max_results

    def search(self, subject: Subject) -> list[Finding]:
        if not self.token:
            raise SourceNotConfigured("Set LOOK_COURTLISTENER_TOKEN to search court records.")
        data = get_json(
            self.fetch,
            SEARCH_URL,
            {"type": "r", "q": f'party:("{subject.full_name}")'},
            {"Authorization": f"Token {self.token}"},
        )
        findings = []
        for item in (data.get("results") or [])[: self.max_results]:
            case = item.get("caseName") or "Unnamed case"
            url = item.get("absolute_url") or ""
            findings.append(
                Finding(
                    check_type=self.check_type,
                    source=self.name,
                    summary=f"Possible party in federal case: {case}",
                    record_reference=("https://www.courtlistener.com" + url) if url else str(item.get("docket_id")),
                    match_basis=["full_name"],
                    details={
                        "case_name": case,
                        "docket_number": item.get("docketNumber"),
                        "court": item.get("court"),
                        "date_filed": item.get("dateFiled"),
                        "date_terminated": item.get("dateTerminated"),
                        "nature_of_suit": item.get("suitNature"),
                    },
                )
            )
        return findings
