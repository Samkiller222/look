"""In-memory adapters for tests and demos. They never touch the network."""

from __future__ import annotations

from typing import Any

from ..models import CheckType, Finding, Subject
from .base import SourceAdapter, SourceError, names_match


class MockAdapter(SourceAdapter):
    """Matches the subject against a fixed list of records.

    Each record is a dict with at least "name" and "summary"; it may carry
    "date_of_birth" (ISO string), "reference", and any other detail fields.
    """

    def __init__(
        self,
        check_type: CheckType,
        records: list[dict[str, Any]] | None = None,
        *,
        name: str | None = None,
        fail_with: str | None = None,
    ) -> None:
        self.check_type = check_type
        self.name = name or f"mock-{check_type.value}"
        self.records = records or []
        self.fail_with = fail_with
        self.calls: list[Subject] = []

    def search(self, subject: Subject) -> list[Finding]:
        self.calls.append(subject)
        if self.fail_with:
            raise SourceError(self.fail_with)
        findings = []
        for i, rec in enumerate(self.records):
            if not names_match(subject.full_name, rec["name"]):
                continue
            basis = ["full_name"]
            rec_dob = rec.get("date_of_birth")
            if rec_dob and subject.date_of_birth:
                if rec_dob != subject.date_of_birth.isoformat():
                    continue
                basis.append("date_of_birth")
            details = {k: v for k, v in rec.items() if k not in ("summary", "reference")}
            findings.append(
                Finding(
                    check_type=self.check_type,
                    source=self.name,
                    summary=rec["summary"],
                    record_reference=rec.get("reference", f"{self.name}:{i}"),
                    match_basis=basis,
                    details=details,
                )
            )
        return findings


def mock_adapters(records: dict[CheckType, list[dict[str, Any]]] | None = None) -> list[SourceAdapter]:
    """One mock adapter per check type, all clear unless records are given."""
    records = records or {}
    return [MockAdapter(ct, records.get(ct, [])) for ct in CheckType]
