"""US Treasury OFAC Specially Designated Nationals (SDN) list.

The SDN list is published as public data by the US government:
https://ofac.treasury.gov/specially-designated-nationals-and-blocked-persons-list-sdn-human-readable-lists

The adapter downloads sdn.csv once (or reads a local copy) and matches
individual entries by name. Set LOOK_OFAC_SDN_PATH to use a local file.
"""

from __future__ import annotations

import csv
import io

from ..models import CheckType, Finding, Subject
from .base import Fetcher, SourceAdapter, default_fetch, env, names_match

SDN_CSV_URL = "https://www.treasury.gov/ofac/downloads/sdn.csv"

# sdn.csv has no header row; these are its documented columns.
SDN_COLUMNS = [
    "ent_num",
    "sdn_name",
    "sdn_type",
    "program",
    "title",
    "call_sign",
    "vess_type",
    "tonnage",
    "grt",
    "vess_flag",
    "vess_owner",
    "remarks",
]


class OfacSdnAdapter(SourceAdapter):
    check_type = CheckType.SANCTIONS
    name = "ofac-sdn"

    def __init__(
        self,
        *,
        path: str | None = None,
        url: str = SDN_CSV_URL,
        fetch: Fetcher = default_fetch,
    ) -> None:
        self.path = path or env("LOOK_OFAC_SDN_PATH")
        self.url = url
        self.fetch = fetch
        self._rows: list[dict[str, str]] | None = None

    def _load(self) -> list[dict[str, str]]:
        if self._rows is None:
            if self.path:
                with open(self.path, encoding="latin-1") as f:
                    text = f.read()
            else:
                text = self.fetch(self.url, {}).decode("latin-1")
            reader = csv.reader(io.StringIO(text))
            rows = []
            for raw in reader:
                if len(raw) < len(SDN_COLUMNS):
                    continue
                row = {k: (v.strip() if v.strip() != "-0-" else "") for k, v in zip(SDN_COLUMNS, raw)}
                if row["sdn_type"].lower() == "individual":
                    rows.append(row)
            self._rows = rows
        return self._rows

    def search(self, subject: Subject) -> list[Finding]:
        findings = []
        for row in self._load():
            if not names_match(subject.full_name, row["sdn_name"]):
                continue
            findings.append(
                Finding(
                    check_type=self.check_type,
                    source=self.name,
                    summary=f"Possible OFAC SDN match: {row['sdn_name']} (program {row['program']})",
                    record_reference=f"OFAC SDN entity #{row['ent_num']}",
                    match_basis=["full_name"],
                    details={
                        "listed_name": row["sdn_name"],
                        "program": row["program"],
                        "title": row["title"],
                        # Remarks hold the listing's own identifiers such as DOB,
                        # which a reviewer uses to confirm or rule out a match.
                        "remarks": row["remarks"],
                    },
                )
            )
        return findings
