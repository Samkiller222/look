"""EU Consolidated Financial Sanctions List (European Commission).

Public data: https://data.europa.eu/data/datasets/consolidated-list-of-persons-groups-and-entities-subject-to-eu-financial-sanctions
The adapter downloads the semicolon-separated CSV (or reads a local copy
from LOOK_EU_SANCTIONS_PATH) and matches people by name, and by date of
birth when both sides have one. Each person appears on several rows (one per
alias, birth date, etc.), so rows are grouped by Entity_LogicalId.
"""

from __future__ import annotations

import csv
import io
from collections import defaultdict

from ..models import CheckType, Finding, Subject
from .base import Fetcher, SourceAdapter, default_fetch, env, names_match

EU_SANCTIONS_CSV_URL = (
    "https://webgate.ec.europa.eu/fsd/fsf/public/files/csvFullSanctionsList_1_1/content?token=dG9rZW4tMjAxNw"
)


class EuSanctionsAdapter(SourceAdapter):
    check_type = CheckType.SANCTIONS
    name = "eu-sanctions"

    def __init__(
        self,
        *,
        path: str | None = None,
        url: str | None = None,
        fetch: Fetcher = default_fetch,
    ) -> None:
        self.path = path or env("LOOK_EU_SANCTIONS_PATH")
        self.url = url or env("LOOK_EU_SANCTIONS_URL") or EU_SANCTIONS_CSV_URL
        self.fetch = fetch
        self._people: list[dict] | None = None

    def _load(self) -> list[dict]:
        if self._people is not None:
            return self._people
        if self.path:
            with open(self.path, encoding="utf-8-sig") as f:
                text = f.read()
        else:
            text = self.fetch(self.url, {}).decode("utf-8-sig")
        grouped: dict[str, dict] = defaultdict(lambda: {"names": set(), "dobs": set()})
        for row in csv.DictReader(io.StringIO(text), delimiter=";"):
            if (row.get("Entity_SubjectType_ClassificationCode") or "").strip().lower() != "person":
                continue
            eid = (row.get("Entity_LogicalId") or "").strip()
            if not eid:
                continue
            p = grouped[eid]
            p["id"] = eid
            p["eu_ref"] = (row.get("Entity_EU_ReferenceNumber") or "").strip()
            p["programme"] = (row.get("Entity_Regulation_Programme") or "").strip()
            p["regulation"] = (row.get("Entity_Regulation_NumberTitle") or "").strip()
            name = (row.get("NameAlias_WholeName") or "").strip()
            if name:
                p["names"].add(name)
            dob = (row.get("BirthDate_BirthDate") or "").strip()
            if dob:
                p["dobs"].add(dob)
        self._people = list(grouped.values())
        return self._people

    def search(self, subject: Subject) -> list[Finding]:
        findings = []
        for p in self._load():
            matched = next((n for n in sorted(p["names"]) if names_match(subject.full_name, n)), None)
            if not matched:
                continue
            basis = ["full_name"]
            if p["dobs"] and subject.date_of_birth:
                if subject.date_of_birth.isoformat() not in p["dobs"]:
                    continue
                basis.append("date_of_birth")
            findings.append(
                Finding(
                    check_type=self.check_type,
                    source=self.name,
                    summary=f"Possible EU sanctions match: {matched} (programme {p['programme'] or 'n/a'})",
                    record_reference=f"EU sanctions entity {p['id']}" + (f" / {p['eu_ref']}" if p["eu_ref"] else ""),
                    match_basis=basis,
                    details={
                        "listed_name": matched,
                        "programme": p["programme"],
                        "regulation": p["regulation"],
                        "listed_birth_dates": sorted(p["dobs"]),
                    },
                )
            )
        return findings
