import json
import os
import re
import tempfile
import unittest
from datetime import date, timedelta

from look.adapters import EuSanctionsAdapter, MockAdapter, mock_adapters
from look.guardrails import GuardrailError
from look.models import CheckType, LawfulBasis, PermissiblePurpose, Region, Subject, now
from look.service import AccessDenied, ScreeningService
from look.store import Store

EMP = PermissiblePurpose.EMPLOYMENT
WHY = "Pre-hire screening for the finance controller role"


def eu_setup(checks, basis, legal_reference=None, adapters=None):
    store = Store()
    svc = ScreeningService(store, adapters or mock_adapters())
    subj = svc.register_subject(Subject(full_name="Anna Schmidt", email="a@x", date_of_birth=date(1988, 3, 4)), actor="hr")
    c = svc.record_consent(
        subject_id=subj.subject_id, requester="hr", purpose=EMP, checks=checks, signed_name="Anna Schmidt",
        region=Region.EU, lawful_basis=basis, legal_reference=legal_reference,
    )
    return store, svc, subj, c


def run(svc, subj, c, checks):
    return svc.run_check(subject_id=subj.subject_id, consent_id=c.consent_id, requester="hr",
                         purpose=EMP, purpose_statement=WHY, checks=checks)


class EuGuardrailTests(unittest.TestCase):
    def test_sanctions_with_legitimate_interests_runs(self):
        _, svc, subj, c = eu_setup([CheckType.SANCTIONS], LawfulBasis.LEGITIMATE_INTERESTS)
        run(svc, subj, c, [CheckType.SANCTIONS])

    def test_lawful_basis_required(self):
        _, svc, subj, c = eu_setup([CheckType.SANCTIONS], None)
        with self.assertRaisesRegex(GuardrailError, "lawful basis"):
            run(svc, subj, c, [CheckType.SANCTIONS])

    def test_consent_basis_rejected_for_employment(self):
        _, svc, subj, c = eu_setup([CheckType.SANCTIONS], LawfulBasis.CONSENT)
        with self.assertRaisesRegex(GuardrailError, "imbalance of power"):
            run(svc, subj, c, [CheckType.SANCTIONS])

    def test_criminal_data_needs_legal_obligation(self):
        _, svc, subj, c = eu_setup([CheckType.COURT_RECORDS], LawfulBasis.LEGITIMATE_INTERESTS)
        with self.assertRaisesRegex(GuardrailError, "Article 10"):
            run(svc, subj, c, [CheckType.COURT_RECORDS])

    def test_legal_obligation_needs_citation(self):
        _, svc, subj, c = eu_setup([CheckType.COURT_RECORDS], LawfulBasis.LEGAL_OBLIGATION)
        with self.assertRaisesRegex(GuardrailError, "Cite the law"):
            run(svc, subj, c, [CheckType.COURT_RECORDS])

    def test_criminal_check_with_cited_law_runs(self):
        _, svc, subj, c = eu_setup([CheckType.COURT_RECORDS], LawfulBasis.LEGAL_OBLIGATION, "§ 30a BZRG")
        run(svc, subj, c, [CheckType.COURT_RECORDS])

    def test_eu_disclosure_mentions_rights(self):
        _, _, _, c = eu_setup([CheckType.SANCTIONS], LawfulBasis.LEGITIMATE_INTERESTS)
        self.assertIn("erased", c.disclosure_text)
        self.assertIn("data protection authority", c.disclosure_text)


class ErasureTests(unittest.TestCase):
    def test_subject_erasure_keeps_only_pseudonymous_audit(self):
        store, svc, subj, c = eu_setup([CheckType.SANCTIONS], LawfulBasis.LEGITIMATE_INTERESTS)
        report = run(svc, subj, c, [CheckType.SANCTIONS])
        svc.erase_my_data(report.report_id, access_token=report.access_token)
        self.assertIsNone(store.get_subject(subj.subject_id))
        self.assertIsNone(store.get_report(report.report_id))
        self.assertIsNone(store.get_consent(c.consent_id))
        dump = json.dumps([e.to_dict() for e in store.audit_entries()])
        self.assertNotIn("Anna", dump)
        self.assertTrue(store.verify_audit_chain())

    def test_purge_after_retention(self):
        store, svc, subj, c = eu_setup([CheckType.SANCTIONS], LawfulBasis.LEGITIMATE_INTERESTS)
        report = run(svc, subj, c, [CheckType.SANCTIONS])
        self.assertEqual(svc.purge_expired(retention_days=30), 0)
        report.created_at = now() - timedelta(days=31)
        store.save_report(report)
        self.assertEqual(svc.purge_expired(retention_days=30), 1)
        self.assertIsNone(store.get_subject(subj.subject_id))


EU_CSV = (
    "fileGenerationDate;Entity_LogicalId;Entity_EU_ReferenceNumber;Entity_SubjectType_ClassificationCode;"
    "Entity_Regulation_Programme;Entity_Regulation_NumberTitle;NameAlias_WholeName;BirthDate_BirthDate\n"
    "2026-11-01;101;EU.1.2;person;RUS;Reg 269/2014;Anna SCHMIDT;\n"
    "2026-11-01;101;EU.1.2;person;RUS;Reg 269/2014;Anna Maria Schmidt;1988-03-04\n"
    "2026-11-01;102;EU.1.3;person;IRN;Reg 267/2012;Anna Schmidt;1950-01-01\n"
    "2026-11-01;103;EU.1.4;enterprise;RUS;Reg 269/2014;Schmidt Anna GmbH;\n"
)


class EuSanctionsAdapterTests(unittest.TestCase):
    def test_groups_aliases_and_filters_by_dob(self):
        a = EuSanctionsAdapter(fetch=lambda url, h: EU_CSV.encode())
        subj = Subject(full_name="Anna Schmidt", email="a@x", date_of_birth=date(1988, 3, 4))
        [f] = a.search(subj)
        self.assertIn("EU sanctions entity 101", f.record_reference)
        self.assertEqual(f.match_basis, ["full_name", "date_of_birth"])

    def test_without_dob_both_people_match(self):
        a = EuSanctionsAdapter(fetch=lambda url, h: EU_CSV.encode())
        self.assertEqual(len(a.search(Subject(full_name="Anna Schmidt", email="a@x"))), 2)


class WebTests(unittest.TestCase):
    def setUp(self):
        from look.web import add_user, create_app

        self.tmp = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.tmp.name, "w.db")
        hits = {CheckType.SANCTIONS: [{"name": "Anna Schmidt", "summary": "Possible sanctions hit", "phone": "555-1234"}]}
        self.app = create_app(db_path=self.db, region="eu", adapters=mock_adapters(hits), secret_key="test")
        self.app.config["SESSION_COOKIE_SECURE"] = False
        store = Store(self.db)
        add_user(store, "hr", "correct horse battery", "requester")
        add_user(store, "rev", "correct horse battery", "reviewer")
        store.db.close()

    def tearDown(self):
        self.tmp.cleanup()

    def csrf(self, client):
        client.get("/login")
        with client.session_transaction() as s:
            return s["csrf"]

    def login(self, client, user):
        t = self.csrf(client)
        r = client.post("/login", data={"username": user, "password": "correct horse battery", "csrf": t})
        self.assertEqual(r.status_code, 302)
        return t

    def test_post_without_csrf_rejected(self):
        c = self.app.test_client()
        self.assertEqual(c.post("/login", data={"username": "hr", "password": "x"}).status_code, 400)

    def test_dashboard_needs_login(self):
        r = self.app.test_client().get("/dashboard")
        self.assertEqual(r.status_code, 302)

    def test_full_flow(self):
        hr = self.app.test_client()
        t = self.login(hr, "hr")
        form = {
            "csrf": t, "full_name": "Anna Schmidt", "email": "anna@example.com", "dob": "1988-03-04",
            "purpose": "employment", "checks": ["sanctions"], "purpose_statement": WHY,
            "lawful_basis": "legitimate_interests",
        }
        r = hr.post("/requests/new", data=form)
        self.assertEqual(r.status_code, 302)
        page = hr.get(r.headers["Location"]).get_data(as_text=True)
        token = re.search(r"/consent/([\w-]+)", page).group(1)
        request_path = r.headers["Location"]

        # Running before the subject signs is refused
        hr.post(request_path + "/run", data={"csrf": t})
        self.assertIn("not signed", hr.get(request_path).get_data(as_text=True))

        subj = self.app.test_client()
        st = self.csrf(subj)
        self.assertIn("lawful basis of legitimate interests", subj.get(f"/consent/{token}").get_data(as_text=True))
        r = subj.post(f"/consent/{token}/sign", data={"csrf": st, "signed_name": "someone else"})
        self.assertEqual(r.status_code, 302)  # wrong name, back to the form
        r = subj.post(f"/consent/{token}/sign", data={"csrf": st, "signed_name": "anna schmidt"})
        self.assertIn("Thank you", r.get_data(as_text=True))

        r = hr.post(request_path + "/run", data={"csrf": t})
        self.assertEqual(r.status_code, 302)
        report_page = hr.get(r.headers["Location"]).get_data(as_text=True)
        self.assertIn("Possible sanctions hit", report_page)
        self.assertNotIn("555-1234", report_page)
        m = re.search(r"/my/(rpt_\w+)/([\w-]+)", report_page)
        rid, code = m.group(1), m.group(2)

        # Another requester cannot see it
        other = self.app.test_client()
        self.assertEqual(other.get(f"/reports/{rid}").status_code, 302)

        # Subject view, dispute, reviewer resolves
        page = subj.get(f"/my/{rid}/{code}").get_data(as_text=True)
        self.assertIn("Who has checked you", page)
        self.assertIn(WHY, page)
        fid = re.search(r'name="finding_id" value="(\w+)"', page).group(1)
        subj.post(f"/my/{rid}/{code}/dispute", data={"csrf": st, "finding_id": fid, "reason": "Not me"})
        self.assertIn("under review", subj.get(f"/my/{rid}/{code}").get_data(as_text=True))
        self.assertEqual(subj.get(f"/my/{rid}/wrong-code").status_code, 403)

        rev = self.app.test_client()
        rt = self.login(rev, "rev")
        page = rev.get("/review").get_data(as_text=True)
        did = re.search(r"/review/(disp_\w+)", page).group(1)
        rev.post(f"/review/{did}", data={"csrf": rt, "outcome": "upheld", "note": "Different birth date"})
        page = subj.get(f"/my/{rid}/{code}").get_data(as_text=True)
        self.assertNotIn("Possible sanctions hit", page)
        self.assertIn("Different birth date", page)

        # Erasure
        r = subj.post(f"/my/{rid}/{code}/erase", data={"csrf": st, "confirm": "yes"})
        self.assertIn("deleted", r.get_data(as_text=True))
        self.assertEqual(subj.get(f"/my/{rid}/{code}").status_code, 404)

    def test_decline_erases(self):
        hr = self.app.test_client()
        t = self.login(hr, "hr")
        r = hr.post("/requests/new", data={
            "csrf": t, "full_name": "Anna Schmidt", "email": "anna@example.com", "purpose": "employment",
            "checks": ["sanctions"], "purpose_statement": WHY, "lawful_basis": "legitimate_interests",
        })
        token = re.search(r"/consent/([\w-]+)", hr.get(r.headers["Location"]).get_data(as_text=True)).group(1)
        subj = self.app.test_client()
        st = self.csrf(subj)
        self.assertIn("deleted", subj.post(f"/consent/{token}/decline", data={"csrf": st}).get_data(as_text=True))
        self.assertEqual(subj.get(f"/consent/{token}").status_code, 404)

    def test_eu_criminal_check_refused_in_form(self):
        hr = self.app.test_client()
        t = self.login(hr, "hr")
        r = hr.post("/requests/new", data={
            "csrf": t, "full_name": "Anna Schmidt", "email": "anna@example.com", "purpose": "employment",
            "checks": ["court_records"], "purpose_statement": WHY, "lawful_basis": "legitimate_interests",
        })
        self.assertEqual(r.status_code, 200)
        self.assertIn("Article 10", r.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
