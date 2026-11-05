"""Command line interface: `python -m look ...`."""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import date

from .adapters import default_adapters, mock_adapters
from .guardrails import GuardrailError
from .models import CheckType, PermissiblePurpose, Subject
from .render import render_report
from .service import AccessDenied, NotFound, ScreeningService
from .store import Store


def _checks(value: str) -> list[CheckType]:
    try:
        return [CheckType(v.strip()) for v in value.split(",") if v.strip()]
    except ValueError as e:
        raise argparse.ArgumentTypeError(f"{e}. Choose from: {', '.join(c.value for c in CheckType)}")


def _purpose(value: str) -> PermissiblePurpose:
    try:
        return PermissiblePurpose(value)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"'{value}' is not a permissible purpose. Choose from: "
            + ", ".join(p.value for p in PermissiblePurpose)
        )


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="look", description="Consent-based background screening.")
    p.add_argument("--db", default=os.environ.get("LOOK_DB", "look.db"), help="SQLite file (default look.db)")
    p.add_argument("--mock", action="store_true", help="use mock sources instead of real public records")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("subject", help="register the person to be screened").add_subparsers(dest="sub", required=True)
    sa = s.add_parser("add")
    sa.add_argument("--name", required=True)
    sa.add_argument("--email", required=True, help="where the subject receives their report")
    sa.add_argument("--dob", type=date.fromisoformat)
    sa.add_argument("--jurisdiction", help='e.g. "US-CA"')
    sa.add_argument("--license-number")
    sa.add_argument("--license-type")
    sa.add_argument("--actor", required=True, help="who is entering this")

    c = sub.add_parser("consent", help="record or revoke the subject's consent").add_subparsers(dest="sub", required=True)
    cd = c.add_parser("disclosure", help="print the disclosure the subject must read and sign")
    cd.add_argument("--requester", required=True)
    cd.add_argument("--purpose", required=True, type=_purpose)
    cd.add_argument("--checks", required=True, type=_checks)
    cr = c.add_parser("record")
    cr.add_argument("--subject", required=True)
    cr.add_argument("--requester", required=True)
    cr.add_argument("--purpose", required=True, type=_purpose)
    cr.add_argument("--checks", required=True, type=_checks)
    cr.add_argument("--signed-name", required=True, help="the subject's signature")
    cr.add_argument("--days", type=int, default=90, help="how long the consent is valid")
    cv = c.add_parser("revoke")
    cv.add_argument("--consent", required=True)
    cv.add_argument("--actor", required=True)

    k = sub.add_parser("check", help="run a screening check").add_subparsers(dest="sub", required=True)
    kr = k.add_parser("run")
    kr.add_argument("--subject", required=True)
    kr.add_argument("--consent", required=True)
    kr.add_argument("--requester", required=True)
    kr.add_argument("--purpose", required=True, type=_purpose)
    kr.add_argument("--why", required=True, help="why this check is needed, e.g. the role or lease")
    kr.add_argument("--checks", required=True, type=_checks)

    r = sub.add_parser("report", help="view a report").add_subparsers(dest="sub", required=True)
    rs = r.add_parser("show", help="requester's view")
    rs.add_argument("--report", required=True)
    rs.add_argument("--requester", required=True)
    rv = r.add_parser("view", help="subject's view, with their rights and how to dispute")
    rv.add_argument("--report", required=True)
    rv.add_argument("--code", required=True, help="the access code given to the subject")
    rl = r.add_parser("access-log", help="subject: everyone who checked you, and why")
    rl.add_argument("--report", required=True)
    rl.add_argument("--code", required=True)

    d = sub.add_parser("dispute", help="dispute a report or resolve a dispute").add_subparsers(dest="sub", required=True)
    do = d.add_parser("open")
    do.add_argument("--report", required=True)
    do.add_argument("--code", required=True)
    do.add_argument("--finding", help="the finding id; leave out to dispute the whole report")
    do.add_argument("--reason", required=True)
    dr = d.add_parser("resolve")
    dr.add_argument("--dispute", required=True)
    dr.add_argument("--reviewer", required=True)
    g = dr.add_mutually_exclusive_group(required=True)
    g.add_argument("--upheld", action="store_true", help="the subject is right; remove the finding")
    g.add_argument("--rejected", action="store_true", help="the record was re-verified and stands")
    dr.add_argument("--note", required=True)

    a = sub.add_parser("audit", help="inspect the audit log").add_subparsers(dest="sub", required=True)
    al = a.add_parser("list")
    al.add_argument("--subject")
    a.add_parser("verify", help="check that the log has not been tampered with")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    store = Store(args.db)
    svc = ScreeningService(store, mock_adapters() if args.mock else default_adapters())
    try:
        return _dispatch(args, svc, store)
    except (GuardrailError, AccessDenied) as e:
        print(f"Refused: {e}", file=sys.stderr)
        return 2
    except (NotFound, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def _dispatch(args: argparse.Namespace, svc: ScreeningService, store: Store) -> int:
    cmd = (args.cmd, args.sub)
    if cmd == ("subject", "add"):
        s = svc.register_subject(
            Subject(
                full_name=args.name,
                email=args.email,
                date_of_birth=args.dob,
                jurisdiction=args.jurisdiction,
                license_number=args.license_number,
                license_type=args.license_type,
            ),
            actor=args.actor,
        )
        print(s.subject_id)
    elif cmd == ("consent", "disclosure"):
        print(svc.disclosure_for(args.requester, args.purpose, args.checks))
    elif cmd == ("consent", "record"):
        c = svc.record_consent(
            subject_id=args.subject,
            requester=args.requester,
            purpose=args.purpose,
            checks=args.checks,
            signed_name=args.signed_name,
            valid_days=args.days,
        )
        print(c.consent_id)
    elif cmd == ("consent", "revoke"):
        svc.revoke_consent(args.consent, actor=args.actor)
        print("revoked")
    elif cmd == ("check", "run"):
        rpt = svc.run_check(
            subject_id=args.subject,
            consent_id=args.consent,
            requester=args.requester,
            purpose=args.purpose,
            purpose_statement=args.why,
            checks=args.checks,
        )
        print(f"report:      {rpt.report_id}")
        print(f"status:      {rpt.status.value}")
        print(f"access code: {rpt.access_token}  (send this to the subject with their report)")
    elif cmd == ("report", "show"):
        rpt = svc.report_for_requester(args.report, requester=args.requester)
        print(render_report(svc, rpt, store.get_subject(rpt.subject_id), for_subject=False))
    elif cmd == ("report", "view"):
        rpt = svc.report_for_subject(args.report, access_token=args.code)
        print(render_report(svc, rpt, store.get_subject(rpt.subject_id), for_subject=True))
    elif cmd == ("report", "access-log"):
        for e in svc.subject_access_log(args.report, access_token=args.code):
            why = e["detail"].get("purpose_statement", "")
            print(f"{e['ts']}  {e['actor']:<24} {e['action']:<28} {why}")
    elif cmd == ("dispute", "open"):
        dsp = svc.open_dispute(args.report, access_token=args.code, finding_id=args.finding, reason=args.reason)
        print(dsp.dispute_id)
    elif cmd == ("dispute", "resolve"):
        dsp = svc.resolve_dispute(args.dispute, reviewer=args.reviewer, upheld=args.upheld, note=args.note)
        print(dsp.status.value)
    elif cmd == ("audit", "list"):
        for e in store.audit_entries(args.subject):
            print(json.dumps(e.to_dict()))
    elif cmd == ("audit", "verify"):
        ok = store.verify_audit_chain()
        print("audit log intact" if ok else "AUDIT LOG HAS BEEN TAMPERED WITH")
        return 0 if ok else 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
