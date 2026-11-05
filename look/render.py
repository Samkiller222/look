"""Plain-text rendering of reports for the subject and the requester."""

from __future__ import annotations

from .models import DisputeStatus, Region, Report, Subject
from .service import ScreeningService

SUBJECT_RIGHTS = """\
YOUR RIGHTS
- This report was prepared only because you gave written consent.
- Every result above is a POSSIBLE match from an official public record. It has
  not been confirmed, and nobody should treat it as confirmed until a reviewer
  has checked it against the record.
- If anything is wrong or incomplete, you can dispute it, free of charge:
    look dispute open --report {report_id} --code <your access code> \\
        [--finding <finding id>] --reason "what is wrong"
  A reviewer must look into it and tell you the outcome. A finding you dispute
  successfully is removed from the report.
- You can see everyone who has run a check on you, and why:
    look report access-log --report {report_id} --code <your access code>
- If you are in the US, this mirrors your rights under the Fair Credit Reporting
  Act (FCRA). See https://www.consumerfinance.gov/consumer-tools/background-checks/
"""

EU_SUBJECT_RIGHTS = """\
YOUR RIGHTS UNDER THE GDPR
- Access (Art. 15): this report and the access log show everything held about you.
- Rectification (Art. 16): dispute anything inaccurate:
    look dispute open --report {report_id} --code <your access code> \\
        [--finding <finding id>] --reason "what is wrong"
- Erasure (Art. 17): delete everything held about you:
    look report erase --report {report_id} --code <your access code>
- Objection (Art. 21) and complaint: you can object to this processing and complain
  to your national data protection authority (see https://edpb.europa.eu/about-edpb/about-edpb/members_en).
- Every result above is a POSSIBLE match from an official public record and has not
  been confirmed. No decision about you should be based on it without human review.
- This report is deleted automatically after the retention period.
"""


def subject_rights_text(region: Region, report_id: str) -> str:
    return (EU_SUBJECT_RIGHTS if region == Region.EU else SUBJECT_RIGHTS).format(report_id=report_id)


def render_report(service: ScreeningService, report: Report, subject: Subject, *, for_subject: bool) -> str:
    lines = [
        f"BACKGROUND SCREENING REPORT {report.report_id}",
        f"Subject:   {subject.full_name}",
        f"Requester: {report.requester}",
        f"Purpose:   {report.purpose.value.replace('_', ' ')}",
        f"Created:   {report.created_at:%Y-%m-%d %H:%M} UTC",
        f"Status:    {report.status.value.replace('_', ' ').upper()}",
        "",
        "SOURCES SEARCHED",
    ]
    for r in report.results:
        state = "searched" if r.ok else f"NOT SEARCHED ({r.error})"
        lines.append(f"- {r.check_type.value} via {r.source}: {state}")

    lines += ["", "POSSIBLE MATCHES"]
    standing = service.effective_findings(report)
    if not standing:
        lines.append("None.")
    for f, dispute in standing:
        lines.append(f"- [{f.finding_id}] {f.summary}")
        lines.append(f"    Source record: {f.record_reference}")
        lines.append(f"    Matched on: {', '.join(f.match_basis)}  (unverified)")
        for k, v in f.details.items():
            if v not in (None, ""):
                lines.append(f"    {k}: {v}")
        if dispute and dispute.status == DisputeStatus.OPEN:
            lines.append("    DISPUTED by the subject; under review. Do not rely on this finding.")
        elif dispute and dispute.status == DisputeStatus.REJECTED:
            lines.append(f"    Disputed; reviewer kept it: {dispute.resolution_note}")

    disputes = service.store.disputes_for_report(report.report_id)
    if disputes:
        lines += ["", "DISPUTES"]
        for d in disputes:
            target = d.finding_id or "whole report"
            lines.append(f"- [{d.dispute_id}] {target}: {d.status.value}. Reason: {d.reason}")
            if d.resolution_note:
                lines.append(f"    Outcome: {d.resolution_note}")

    lines.append("")
    if for_subject:
        consent = service.store.get_consent(report.consent_id)
        lines.append(subject_rights_text(consent.region if consent else Region.US, report.report_id))
    else:
        lines.append(
            "REQUESTER NOTICE: possible matches are not verified. Before taking any adverse\n"
            "action based on this report, give the subject a copy of it, a summary of their\n"
            "rights, and a reasonable chance to dispute it."
        )
    return "\n".join(lines)
