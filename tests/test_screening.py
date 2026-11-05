import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import date, timedelta

from look.adapters import (
    CourtListenerAdapter,
    LicenseBoardAdapter,
    MockAdapter,
    OfacSdnAdapter,
    OpenCorporatesAdapter,
    SexOffenderRegistryAdapter,
    mock_adapters,
    names_match,
)
from look.cli import main
from look.guardrails import GuardrailError
from look.models import CheckStatus, CheckType, DisputeStatus, PermissiblePurpose, Subject, now
from look.render import render_report
from look.service import AccessDenied, ScreeningService
from look.store import Store

EMP = PermissiblePurpose.EMPLOYMENT
WHY = "Pre-hire screening for the warehouse supervisor role"


def setup(adapters=None, checks=(CheckType.SANCTIONS, CheckType.COURT_RECORDS)):
    store = Store()
    svc = ScreeningService(store, adapters if adapters is not None else mock_adapters())
    subj = svc.register_subject(
        Subject(full_name="Jane Q Doe", email="jane@example.com", date_of_birth=date(1990, 1, 2)),
        actor="hr@acme",
    )
    consent = svc.record_consent(
        subject_id=subj.subject_id, requester="hr@acme", purpose=EMP, checks=list(checks), signed_name="Jane Q Doe"
    )
    return store, svc, subj, consent


def run(svc, subj, consent, **kw):
    args = dict(
        subject_id=subj.subject_id,
        consent_id=consent.consent_id,
        requester="hr@acme",
        purpose=EMP,
        purpose_statement=WHY,
        checks=[CheckType.SANCTIONS],
    )
    args.update(kw)
    return svc.run_check(**args)


class GuardrailTests(unittest.TestCase):
    def test_clear_check_runs_with_consent(self):
        store, svc, subj, consent = setup()
        report = run(svc, subj, consent)
        self.assertEqual(report.status, CheckStatus.CLEAR)

    def test_no_consent_refused_and_audited(self):
        store, svc, subj, _ = setup()
        with self.assertRaises(GuardrailError):
            run(svc, subj, type("C", (), {"consent_id": "cons_missing"})())
        self.assertEqual(store.audit_entries()[-1].action, "check.denied")

    def test_wrong_purpose_refused(self):
        _, svc, subj, consent = setup()
        with self.assertRaisesRegex(GuardrailError, "Consent was given for"):
            run(svc, subj, consent, purpose=PermissiblePurpose.TENANT_SCREENING)

    def test_check_outside_consent_refused(self):
        _, svc, subj, consent = setup()
        with self.assertRaisesRegex(GuardrailError, "did not consent"):
            run(svc, subj, consent, checks=[CheckType.SEX_OFFENDER_REGISTRY])

    def test_purpose_statement_required(self):
        _, svc, subj, consent = setup()
        with self.assertRaisesRegex(GuardrailError, "why this check"):
            run(svc, subj, consent, purpose_statement="because")

    def test_requester_required(self):
        _, svc, subj, consent = setup()
        with self.assertRaises(GuardrailError):
            run(svc, subj, consent, requester="  ")

    def test_revoked_consent_refused(self):
        _, svc, subj, consent = setup()
        svc.revoke_consent(consent.consent_id, actor="jane")
        with self.assertRaisesRegex(GuardrailError, "expired or revoked"):
            run(svc, subj, consent)

    def test_expired_consent_refused(self):
        store, svc, subj, _ = setup()
        old = svc.record_consent(
            subject_id=subj.subject_id,
            requester="hr@acme",
            purpose=EMP,
            checks=[CheckType.SANCTIONS],
            signed_name="Jane Q Doe",
            valid_days=30,
            signed_at=now() - timedelta(days=31),
        )
        with self.assertRaisesRegex(GuardrailError, "expired"):
            run(svc, subj, old)

    def test_purpose_limits_checks(self):
        store = Store()
        svc = ScreeningService(store, mock_adapters())
        subj = svc.register_subject(Subject(full_name="Jane Doe", email="j@x"), actor="a")
        p = PermissiblePurpose.BUSINESS_TRANSACTION_INITIATED_BY_SUBJECT
        c = svc.record_consent(
            subject_id=subj.subject_id, requester="a", purpose=p,
            checks=[CheckType.SEX_OFFENDER_REGISTRY], signed_name="Jane Doe",
        )
        with self.assertRaisesRegex(GuardrailError, "Not permitted for purpose"):
            svc.run_check(subject_id=subj.subject_id, consent_id=c.consent_id, requester="a",
                          purpose=p, purpose_statement=WHY, checks=[CheckType.SEX_OFFENDER_REGISTRY])

    def test_adapters_not_called_when_refused(self):
        adapter = MockAdapter(CheckType.SANCTIONS)
        _, svc, subj, consent = setup([adapter])
        with self.assertRaises(GuardrailError):
            run(svc, subj, consent, purpose_statement="")
        self.assertEqual(adapter.calls, [])

    def test_prohibited_fields_scrubbed(self):
        records = [{
            "name": "Doe, Jane", "summary": "hit", "home_address": "1 Main St", "phone": "555",
            "relatives": ["John"], "facebook": "fb.com/jane", "nested": {"latitude": 1, "case": "X"},
            "program": "SDGT",
        }]
        store, svc, subj, consent = setup([MockAdapter(CheckType.SANCTIONS, records)])
        report = run(svc, subj, consent)
        details = report.all_findings()[0].details
        self.assertEqual(details, {"name": "Doe, Jane", "nested": {"case": "X"}, "program": "SDGT"})
        stored = json.dumps(store.get_report(report.report_id).to_dict())
        for bad in ("1 Main St", "555", "John", "fb.com"):
            self.assertNotIn(bad, stored)

    def test_subject_has_no_locator_fields(self):
        fields = set(Subject.__dataclass_fields__)
        for bad in ("address", "phone", "relatives", "location", "social_media"):
            self.assertFalse(any(bad in f for f in fields), bad)


class CheckAndReportTests(unittest.TestCase):
    def test_match_needs_review_and_dob_mismatch_excluded(self):
        records = [
            {"name": "DOE, Jane Q", "summary": "SDN hit", "date_of_birth": "1990-01-02"},
            {"name": "Jane Doe", "summary": "other Jane", "date_of_birth": "1950-05-05"},
        ]
        _, svc, subj, consent = setup([MockAdapter(CheckType.SANCTIONS, records)])
        report = run(svc, subj, consent)
        self.assertEqual(report.status, CheckStatus.NEEDS_REVIEW)
        [f] = report.all_findings()
        self.assertEqual(f.summary, "SDN hit")
        self.assertEqual(f.match_basis, ["full_name", "date_of_birth"])
        self.assertFalse(f.verified)

    def test_failed_source_is_incomplete_not_clear(self):
        _, svc, subj, consent = setup([MockAdapter(CheckType.SANCTIONS, fail_with="timeout")])
        self.assertEqual(run(svc, subj, consent).status, CheckStatus.INCOMPLETE)

    def test_missing_source_is_incomplete(self):
        _, svc, subj, consent = setup([])
        self.assertEqual(run(svc, subj, consent).status, CheckStatus.INCOMPLETE)

    def test_only_requester_and_subject_can_view(self):
        _, svc, subj, consent = setup()
        report = run(svc, subj, consent)
        svc.report_for_requester(report.report_id, requester="hr@acme")
        with self.assertRaises(AccessDenied):
            svc.report_for_requester(report.report_id, requester="someone@else")
        svc.report_for_subject(report.report_id, access_token=report.access_token)
        with self.assertRaises(AccessDenied):
            svc.report_for_subject(report.report_id, access_token="guess")

    def test_subject_sees_who_checked_and_why(self):
        _, svc, subj, consent = setup()
        report = run(svc, subj, consent)
        log = svc.subject_access_log(report.report_id, access_token=report.access_token)
        run_entry = next(e for e in log if e["action"] == "check.run")
        self.assertEqual(run_entry["actor"], "hr@acme")
        self.assertEqual(run_entry["detail"]["purpose_statement"], WHY)

    def test_subject_report_explains_rights(self):
        store, svc, subj, consent = setup()
        report = run(svc, subj, consent)
        text = render_report(svc, report, subj, for_subject=True)
        self.assertIn("YOUR RIGHTS", text)
        self.assertIn("dispute open", text)


class DisputeTests(unittest.TestCase):
    def _report_with_hit(self):
        records = [{"name": "Jane Q Doe", "summary": "possible hit"}]
        store, svc, subj, consent = setup([MockAdapter(CheckType.SANCTIONS, records)])
        return store, svc, subj, run(svc, subj, consent)

    def test_upheld_dispute_removes_finding(self):
        store, svc, subj, report = self._report_with_hit()
        f = report.all_findings()[0]
        d = svc.open_dispute(report.report_id, access_token=report.access_token,
                             finding_id=f.finding_id, reason="Not me, different DOB")
        text = render_report(svc, report, subj, for_subject=False)
        self.assertIn("DISPUTED by the subject", text)
        svc.resolve_dispute(d.dispute_id, reviewer="reviewer@acme", upheld=True, note="DOB on listing differs")
        self.assertEqual(svc.effective_findings(report), [])

    def test_rejected_dispute_keeps_finding_with_note(self):
        store, svc, subj, report = self._report_with_hit()
        f = report.all_findings()[0]
        d = svc.open_dispute(report.report_id, access_token=report.access_token, finding_id=f.finding_id, reason="wrong")
        r = svc.resolve_dispute(d.dispute_id, reviewer="rev", upheld=False, note="Identifiers match the listing")
        self.assertEqual(r.status, DisputeStatus.REJECTED)
        self.assertEqual(len(svc.effective_findings(report)), 1)

    def test_dispute_requires_access_code(self):
        _, svc, _, report = self._report_with_hit()
        with self.assertRaises(AccessDenied):
            svc.open_dispute(report.report_id, access_token="nope", reason="x")


class AuditTests(unittest.TestCase):
    def test_chain_verifies_and_detects_tampering(self):
        store, svc, subj, consent = setup()
        run(svc, subj, consent)
        self.assertTrue(store.verify_audit_chain())
        store.db.execute("DROP TRIGGER audit_no_update")
        store.db.execute("UPDATE audit SET actor = 'nobody' WHERE action = 'check.run'")
        self.assertFalse(store.verify_audit_chain())

    def test_log_is_append_only(self):
        store, svc, subj, consent = setup()
        with self.assertRaises(Exception):
            store.db.execute("DELETE FROM audit")


def fake_fetch(payload):
    calls = []

    def fetch(url, headers):
        calls.append((url, headers))
        return payload if isinstance(payload, bytes) else json.dumps(payload).encode()

    fetch.calls = calls
    return fetch


class RealAdapterParsingTests(unittest.TestCase):
    subj = Subject(full_name="Jane Q Doe", email="j@x", date_of_birth=date(1990, 1, 2),
                   license_number="RN123", jurisdiction="US-CA")

    def test_names_match(self):
        self.assertTrue(names_match("DOE, Jane", "Jane Q. Doe"))
        self.assertTrue(names_match("José Álvarez", "jose alvarez"))
        self.assertFalse(names_match("Doe", "Jane Doe"))
        self.assertFalse(names_match("John Doe", "Jane Doe"))

    def test_ofac_csv(self):
        csv_text = (
            '36,"DOE, Jane","individual","SDGT","-0-","-0-","-0-","-0-","-0-","-0-","-0-","DOB 02 Jan 1990."\n'
            '37,"DOE TRADING LLC","-0-","SDGT","-0-","-0-","-0-","-0-","-0-","-0-","-0-","-0-"\n'
        ).encode("latin-1")
        [f] = OfacSdnAdapter(fetch=fake_fetch(csv_text)).search(self.subj)
        self.assertEqual(f.record_reference, "OFAC SDN entity #36")
        self.assertEqual(f.details["title"], "")

    def test_courtlistener(self):
        fetch = fake_fetch({"results": [{"caseName": "US v. Doe", "absolute_url": "/docket/1/", "docketNumber": "1:20"}]})
        [f] = CourtListenerAdapter(token="t", fetch=fetch).search(self.subj)
        self.assertIn("US v. Doe", f.summary)
        self.assertEqual(fetch.calls[0][1]["Authorization"], "Token t")

    def test_opencorporates_drops_address(self):
        fetch = fake_fetch({"results": {"officers": [{"officer": {
            "name": "JANE Q DOE", "position": "director", "address": "1 Main St",
            "company": {"name": "Acme Ltd", "company_number": "1", "jurisdiction_code": "us_ca"}}}]}})
        [f] = OpenCorporatesAdapter(token="t", fetch=fetch).search(self.subj)
        self.assertNotIn("1 Main St", json.dumps(f.details))

    def test_license_requires_number_match(self):
        fetch = fake_fetch({"results": [
            {"name": "Jane Doe", "license_number": "RN123", "summary": "RN, active"},
            {"name": "Jane Doe", "license_number": "RN999", "summary": "other"},
        ]})
        [f] = LicenseBoardAdapter(endpoint="https://x/api", api_key="k", fetch=fetch).search(self.subj)
        self.assertEqual(f.summary, "RN, active")
        self.assertIn("license_number=RN123", fetch.calls[0][0])

    def test_unconfigured_sources_report_incomplete(self):
        store = Store()
        adapters = [SexOffenderRegistryAdapter(endpoint=None, api_key=None)]
        svc = ScreeningService(store, adapters)
        subj = svc.register_subject(Subject(full_name="Jane Doe", email="j@x"), actor="a")
        c = svc.record_consent(subject_id=subj.subject_id, requester="a", purpose=EMP,
                               checks=[CheckType.SEX_OFFENDER_REGISTRY], signed_name="Jane Doe")
        r = svc.run_check(subject_id=subj.subject_id, consent_id=c.consent_id, requester="a", purpose=EMP,
                          purpose_statement=WHY, checks=[CheckType.SEX_OFFENDER_REGISTRY])
        self.assertEqual(r.status, CheckStatus.INCOMPLETE)
        self.assertIn("LOOK_SOR_URL", r.results[0].error)


class CliTests(unittest.TestCase):
    def cli(self, db, *args):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(["--db", db, "--mock", *args])
        return code, out.getvalue().strip(), err.getvalue()

    def test_end_to_end(self):
        import tempfile, os
        with tempfile.TemporaryDirectory() as d:
            db = os.path.join(d, "t.db")
            _, sid, _ = self.cli(db, "subject", "add", "--name", "Jane Doe", "--email", "j@x", "--actor", "hr")
            code, _, err = self.cli(db, "check", "run", "--subject", sid, "--consent", "none", "--requester", "hr",
                                    "--purpose", "employment", "--why", WHY, "--checks", "sanctions")
            self.assertEqual(code, 2)
            self.assertIn("Refused", err)
            _, cid, _ = self.cli(db, "consent", "record", "--subject", sid, "--requester", "hr",
                                 "--purpose", "employment", "--checks", "sanctions", "--signed-name", "Jane Doe")
            code, out, _ = self.cli(db, "check", "run", "--subject", sid, "--consent", cid, "--requester", "hr",
                                    "--purpose", "employment", "--why", WHY, "--checks", "sanctions")
            self.assertEqual(code, 0)
            rid = out.split()[1]
            token = out.splitlines()[2].split()[2]
            code, out, _ = self.cli(db, "report", "view", "--report", rid, "--code", token)
            self.assertIn("YOUR RIGHTS", out)
            code, out, _ = self.cli(db, "audit", "verify")
            self.assertEqual(out, "audit log intact")


if __name__ == "__main__":
    unittest.main()
