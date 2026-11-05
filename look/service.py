"""The screening workflow: consent, check, report, dispute.

Every entry point writes to the audit log, and nothing runs a source
adapter except run_check, which goes through guardrails.authorize_check.
"""

from __future__ import annotations

import hmac
import secrets
from datetime import datetime, timedelta

from .adapters import SourceAdapter, SourceNotConfigured
from .guardrails import GuardrailError, authorize_check, scrub
from .models import (
    CheckType,
    Consent,
    Dispute,
    DisputeStatus,
    Finding,
    PermissiblePurpose,
    Report,
    SourceResult,
    Subject,
    new_id,
    now,
)
from .store import Store

DEFAULT_CONSENT_DAYS = 90

STANDARD_DISCLOSURE = (
    "You are authorising {requester} to obtain a background screening report about you "
    "for the purpose of {purpose}. The report will search only these official public "
    "records: {checks}. It will not collect your home address, phone number, family "
    "members, location history, or social media. You will receive a copy of the report "
    "and may dispute anything in it you believe is inaccurate or incomplete. You may "
    "revoke this authorisation at any time before the check runs."
)


class AccessDenied(Exception):
    pass


class NotFound(Exception):
    pass


class ScreeningService:
    def __init__(self, store: Store, adapters: list[SourceAdapter]) -> None:
        self.store = store
        self.adapters: dict[CheckType, list[SourceAdapter]] = {}
        for a in adapters:
            self.adapters.setdefault(a.check_type, []).append(a)

    # subjects and consent ---------------------------------------------------

    @staticmethod
    def disclosure_for(requester: str, purpose: PermissiblePurpose, checks: list[CheckType]) -> str:
        return STANDARD_DISCLOSURE.format(
            requester=requester,
            purpose=purpose.value.replace("_", " "),
            checks=", ".join(c.value.replace("_", " ") for c in checks),
        )

    def register_subject(self, subject: Subject, *, actor: str) -> Subject:
        self.store.save_subject(subject)
        self.store.audit(actor, "subject.registered", subject.subject_id)
        return subject

    def record_consent(
        self,
        *,
        subject_id: str,
        requester: str,
        purpose: PermissiblePurpose,
        checks: list[CheckType],
        signed_name: str,
        valid_days: int = DEFAULT_CONSENT_DAYS,
        signed_at: datetime | None = None,
    ) -> Consent:
        subject = self._subject(subject_id)
        if not signed_name.strip():
            raise GuardrailError("The subject must sign the consent.")
        signed_at = signed_at or now()
        consent = Consent(
            subject_id=subject.subject_id,
            purpose=purpose,
            authorized_checks=list(checks),
            signed_name=signed_name.strip(),
            disclosure_text=self.disclosure_for(requester, purpose, checks),
            signed_at=signed_at,
            expires_at=signed_at + timedelta(days=valid_days),
        )
        self.store.save_consent(consent)
        self.store.audit(
            requester,
            "consent.recorded",
            subject.subject_id,
            consent_id=consent.consent_id,
            purpose=purpose.value,
            checks=[c.value for c in checks],
            signed_name=consent.signed_name,
        )
        return consent

    def revoke_consent(self, consent_id: str, *, actor: str) -> Consent:
        consent = self.store.get_consent(consent_id)
        if consent is None:
            raise NotFound(consent_id)
        consent.revoked_at = now()
        self.store.save_consent(consent)
        self.store.audit(actor, "consent.revoked", consent.subject_id, consent_id=consent_id)
        return consent

    # running a check --------------------------------------------------------

    def run_check(
        self,
        *,
        subject_id: str,
        consent_id: str,
        requester: str,
        purpose: PermissiblePurpose,
        purpose_statement: str,
        checks: list[CheckType],
    ) -> Report:
        subject = self._subject(subject_id)
        consent = self.store.get_consent(consent_id)
        try:
            authorize_check(
                subject=subject,
                consent=consent,
                requester=requester,
                purpose=purpose,
                purpose_statement=purpose_statement,
                checks=checks,
            )
        except GuardrailError as e:
            self.store.audit(
                requester or "<anonymous>",
                "check.denied",
                subject_id,
                consent_id=consent_id,
                purpose=purpose.value,
                purpose_statement=purpose_statement,
                checks=[c.value for c in checks],
                reason=str(e),
            )
            raise

        results: list[SourceResult] = []
        for check in checks:
            adapters = self.adapters.get(check, [])
            if not adapters:
                results.append(SourceResult(check, "<none>", ok=False, error="No source configured for this check."))
                continue
            for adapter in adapters:
                results.append(self._query(adapter, subject))

        report = Report(
            report_id=new_id("rpt"),
            subject_id=subject.subject_id,
            consent_id=consent_id,
            requester=requester,
            purpose=purpose,
            created_at=now(),
            results=results,
            access_token=secrets.token_urlsafe(24),
        )
        self.store.save_report(report)
        self.store.audit(
            requester,
            "check.run",
            subject.subject_id,
            report_id=report.report_id,
            consent_id=consent_id,
            purpose=purpose.value,
            purpose_statement=purpose_statement,
            checks=[c.value for c in checks],
            sources=[r.source for r in results],
            status=report.status.value,
        )
        return report

    @staticmethod
    def _query(adapter: SourceAdapter, subject: Subject) -> SourceResult:
        try:
            raw = adapter.search(subject)
        except SourceNotConfigured as e:
            return SourceResult(adapter.check_type, adapter.name, ok=False, error=f"Not configured: {e}")
        except Exception as e:  # noqa: BLE001 - a failing source must not abort the whole check
            return SourceResult(adapter.check_type, adapter.name, ok=False, error=str(e))
        findings = [
            Finding(
                check_type=f.check_type,
                source=f.source,
                summary=f.summary,
                record_reference=f.record_reference,
                match_basis=list(f.match_basis),
                details=scrub(f.details),
                verified=False,
                finding_id=f.finding_id,
            )
            for f in raw
        ]
        return SourceResult(adapter.check_type, adapter.name, ok=True, findings=findings)

    # viewing ----------------------------------------------------------------

    def report_for_requester(self, report_id: str, *, requester: str) -> Report:
        report = self._report(report_id)
        if requester != report.requester:
            self.store.audit(requester, "report.access_denied", report.subject_id, report_id=report_id)
            raise AccessDenied("Only the requester who ran this check can view it.")
        self.store.audit(requester, "report.viewed_by_requester", report.subject_id, report_id=report_id)
        return report

    def report_for_subject(self, report_id: str, *, access_token: str) -> Report:
        report = self._subject_report(report_id, access_token)
        self.store.audit("subject", "report.viewed_by_subject", report.subject_id, report_id=report_id)
        return report

    def subject_access_log(self, report_id: str, *, access_token: str) -> list[dict]:
        """Everything the audit log holds about the subject: who checked them and why."""
        report = self._subject_report(report_id, access_token)
        return [e.to_dict() for e in self.store.audit_entries(report.subject_id)]

    def effective_findings(self, report: Report) -> list[tuple[Finding, Dispute | None]]:
        """Findings that still stand, each with any open or rejected dispute.

        Findings whose dispute was upheld are dropped, and if a whole-report
        dispute was upheld, nothing stands.
        """
        disputes = self.store.disputes_for_report(report.report_id)
        if any(d.finding_id is None and d.status == DisputeStatus.UPHELD for d in disputes):
            return []
        by_finding: dict[str, Dispute] = {}
        for d in disputes:
            if d.finding_id:
                by_finding[d.finding_id] = d
        out = []
        for f in report.all_findings():
            d = by_finding.get(f.finding_id)
            if d and d.status == DisputeStatus.UPHELD:
                continue
            out.append((f, d))
        return out

    # disputes ---------------------------------------------------------------

    def open_dispute(self, report_id: str, *, access_token: str, reason: str, finding_id: str | None = None) -> Dispute:
        report = self._subject_report(report_id, access_token)
        if not reason.strip():
            raise ValueError("Say what is wrong so a reviewer can check it.")
        if finding_id and finding_id not in {f.finding_id for f in report.all_findings()}:
            raise NotFound(finding_id)
        dispute = Dispute(report_id=report_id, finding_id=finding_id, reason=reason.strip())
        self.store.save_dispute(dispute)
        self.store.audit(
            "subject",
            "dispute.opened",
            report.subject_id,
            report_id=report_id,
            dispute_id=dispute.dispute_id,
            finding_id=finding_id,
        )
        return dispute

    def resolve_dispute(self, dispute_id: str, *, reviewer: str, upheld: bool, note: str) -> Dispute:
        dispute = self.store.get_dispute(dispute_id)
        if dispute is None:
            raise NotFound(dispute_id)
        if dispute.status != DisputeStatus.OPEN:
            raise ValueError("Dispute is already resolved.")
        if not note.strip():
            raise ValueError("Explain the outcome; the subject will see this note.")
        report = self._report(dispute.report_id)
        dispute.status = DisputeStatus.UPHELD if upheld else DisputeStatus.REJECTED
        dispute.resolution_note = note.strip()
        dispute.resolved_by = reviewer
        dispute.resolved_at = now()
        self.store.save_dispute(dispute)
        self.store.audit(
            reviewer,
            "dispute.resolved",
            report.subject_id,
            dispute_id=dispute_id,
            report_id=dispute.report_id,
            outcome=dispute.status.value,
        )
        return dispute

    # helpers ----------------------------------------------------------------

    def _subject(self, subject_id: str) -> Subject:
        s = self.store.get_subject(subject_id)
        if s is None:
            raise NotFound(subject_id)
        return s

    def _report(self, report_id: str) -> Report:
        r = self.store.get_report(report_id)
        if r is None:
            raise NotFound(report_id)
        return r

    def _subject_report(self, report_id: str, access_token: str) -> Report:
        report = self._report(report_id)
        if not hmac.compare_digest(report.access_token, access_token or ""):
            self.store.audit("<unknown>", "report.subject_access_denied", report.subject_id, report_id=report_id)
            raise AccessDenied("Invalid report access code.")
        return report
