"""Core data types for consent-based background screening."""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from datetime import date, datetime, timezone
from enum import Enum
from typing import Any


def now() -> datetime:
    return datetime.now(timezone.utc)


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


class PermissiblePurpose(str, Enum):
    """Purposes modelled on FCRA section 604 (15 U.S.C. 1681b).

    A check can only run for one of these. There is deliberately no
    "curiosity", "personal", or "locate a person" purpose.
    """

    EMPLOYMENT = "employment"
    TENANT_SCREENING = "tenant_screening"
    PROFESSIONAL_LICENSING = "professional_licensing"
    VOLUNTEER_SCREENING = "volunteer_screening"
    BUSINESS_TRANSACTION_INITIATED_BY_SUBJECT = "business_transaction_initiated_by_subject"
    SUBJECT_SELF_REQUEST = "subject_self_request"


class CheckType(str, Enum):
    SANCTIONS = "sanctions"
    SEX_OFFENDER_REGISTRY = "sex_offender_registry"
    COURT_RECORDS = "court_records"
    CORPORATE_REGISTRY = "corporate_registry"
    PROFESSIONAL_LICENSE = "professional_license"


@dataclass
class Subject:
    """The person being screened.

    Only the identifiers needed to match official records are stored. There
    are intentionally no fields for home address, phone number, relatives,
    location history, or social media handles.
    """

    full_name: str
    email: str  # used only to deliver the report and dispute link to the subject
    date_of_birth: date | None = None
    jurisdiction: str | None = None  # e.g. "US-CA", for registry / license lookups
    license_number: str | None = None
    license_type: str | None = None
    subject_id: str = field(default_factory=lambda: new_id("subj"))

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["date_of_birth"] = self.date_of_birth.isoformat() if self.date_of_birth else None
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Subject":
        d = dict(d)
        if d.get("date_of_birth"):
            d["date_of_birth"] = date.fromisoformat(d["date_of_birth"])
        return cls(**d)


@dataclass
class Consent:
    """A record that the subject authorised specific checks for a specific purpose."""

    subject_id: str
    purpose: PermissiblePurpose
    authorized_checks: list[CheckType]
    signed_name: str
    disclosure_text: str
    signed_at: datetime = field(default_factory=now)
    expires_at: datetime | None = None
    revoked_at: datetime | None = None
    consent_id: str = field(default_factory=lambda: new_id("cons"))

    def is_active(self, at: datetime | None = None) -> bool:
        at = at or now()
        if self.revoked_at is not None and self.revoked_at <= at:
            return False
        if self.expires_at is not None and self.expires_at <= at:
            return False
        return self.signed_at <= at

    def to_dict(self) -> dict[str, Any]:
        return {
            "consent_id": self.consent_id,
            "subject_id": self.subject_id,
            "purpose": self.purpose.value,
            "authorized_checks": [c.value for c in self.authorized_checks],
            "signed_name": self.signed_name,
            "disclosure_text": self.disclosure_text,
            "signed_at": self.signed_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "revoked_at": self.revoked_at.isoformat() if self.revoked_at else None,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Consent":
        return cls(
            consent_id=d["consent_id"],
            subject_id=d["subject_id"],
            purpose=PermissiblePurpose(d["purpose"]),
            authorized_checks=[CheckType(c) for c in d["authorized_checks"]],
            signed_name=d["signed_name"],
            disclosure_text=d["disclosure_text"],
            signed_at=datetime.fromisoformat(d["signed_at"]),
            expires_at=datetime.fromisoformat(d["expires_at"]) if d.get("expires_at") else None,
            revoked_at=datetime.fromisoformat(d["revoked_at"]) if d.get("revoked_at") else None,
        )


@dataclass
class Finding:
    """One possible record match from an official source.

    Findings are always "possible matches" until a human reviewer confirms
    them, because name-based matching produces false positives.
    """

    check_type: CheckType
    source: str
    summary: str
    record_reference: str  # the source's own ID / URL so the subject can verify it
    match_basis: list[str]  # which identifiers matched, e.g. ["full_name", "date_of_birth"]
    details: dict[str, Any] = field(default_factory=dict)
    verified: bool = False
    finding_id: str = field(default_factory=lambda: new_id("find"))

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["check_type"] = self.check_type.value
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Finding":
        d = dict(d)
        d["check_type"] = CheckType(d["check_type"])
        return cls(**d)


class CheckStatus(str, Enum):
    CLEAR = "clear"  # every source answered, no possible matches
    NEEDS_REVIEW = "needs_review"  # at least one possible match
    INCOMPLETE = "incomplete"  # a source failed or was not configured


@dataclass
class SourceResult:
    check_type: CheckType
    source: str
    ok: bool
    error: str | None = None
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_type": self.check_type.value,
            "source": self.source,
            "ok": self.ok,
            "error": self.error,
            "findings": [f.to_dict() for f in self.findings],
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "SourceResult":
        return cls(
            check_type=CheckType(d["check_type"]),
            source=d["source"],
            ok=d["ok"],
            error=d.get("error"),
            findings=[Finding.from_dict(f) for f in d.get("findings", [])],
        )


@dataclass
class Report:
    report_id: str
    subject_id: str
    consent_id: str
    requester: str
    purpose: PermissiblePurpose
    created_at: datetime
    results: list[SourceResult]
    access_token: str  # given to the subject so they can view and dispute the report

    @property
    def status(self) -> CheckStatus:
        if any(not r.ok for r in self.results):
            return CheckStatus.INCOMPLETE
        if any(r.findings for r in self.results):
            return CheckStatus.NEEDS_REVIEW
        return CheckStatus.CLEAR

    def all_findings(self) -> list[Finding]:
        return [f for r in self.results for f in r.findings]

    def to_dict(self) -> dict[str, Any]:
        return {
            "report_id": self.report_id,
            "subject_id": self.subject_id,
            "consent_id": self.consent_id,
            "requester": self.requester,
            "purpose": self.purpose.value,
            "created_at": self.created_at.isoformat(),
            "results": [r.to_dict() for r in self.results],
            "access_token": self.access_token,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Report":
        return cls(
            report_id=d["report_id"],
            subject_id=d["subject_id"],
            consent_id=d["consent_id"],
            requester=d["requester"],
            purpose=PermissiblePurpose(d["purpose"]),
            created_at=datetime.fromisoformat(d["created_at"]),
            results=[SourceResult.from_dict(r) for r in d["results"]],
            access_token=d["access_token"],
        )


class DisputeStatus(str, Enum):
    OPEN = "open"
    UPHELD = "upheld"  # the subject was right; the finding is removed from the report
    REJECTED = "rejected"  # the finding was re-verified and stands


@dataclass
class Dispute:
    report_id: str
    finding_id: str | None  # None means the subject disputes the report as a whole
    reason: str
    opened_at: datetime = field(default_factory=now)
    status: DisputeStatus = DisputeStatus.OPEN
    resolution_note: str | None = None
    resolved_by: str | None = None
    resolved_at: datetime | None = None
    dispute_id: str = field(default_factory=lambda: new_id("disp"))

    def to_dict(self) -> dict[str, Any]:
        return {
            "dispute_id": self.dispute_id,
            "report_id": self.report_id,
            "finding_id": self.finding_id,
            "reason": self.reason,
            "opened_at": self.opened_at.isoformat(),
            "status": self.status.value,
            "resolution_note": self.resolution_note,
            "resolved_by": self.resolved_by,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Dispute":
        return cls(
            dispute_id=d["dispute_id"],
            report_id=d["report_id"],
            finding_id=d.get("finding_id"),
            reason=d["reason"],
            opened_at=datetime.fromisoformat(d["opened_at"]),
            status=DisputeStatus(d["status"]),
            resolution_note=d.get("resolution_note"),
            resolved_by=d.get("resolved_by"),
            resolved_at=datetime.fromisoformat(d["resolved_at"]) if d.get("resolved_at") else None,
        )
