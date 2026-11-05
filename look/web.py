"""Web app: `python -m look serve`.

Three kinds of user:
- requesters (log in) create screening requests and read their own reports;
- subjects (no account) sign or decline through a private link, then read,
  dispute, or erase their report through another private link;
- reviewers (log in) resolve disputes.
"""

from __future__ import annotations

import os
import secrets
from datetime import date
from functools import wraps

from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for
from jinja2 import DictLoader
from werkzeug.security import check_password_hash, generate_password_hash

from .adapters import SourceAdapter, default_adapters
from .guardrails import PURPOSE_ALLOWED_CHECKS, GuardrailError
from .models import CheckType, LawfulBasis, PermissiblePurpose, Region, Subject
from .service import AccessDenied, NotFound, ScreeningService
from .store import Store

ROLES = ("requester", "reviewer")


def add_user(store: Store, username: str, password: str, role: str) -> None:
    if role not in ROLES:
        raise ValueError(f"role must be one of {ROLES}")
    if len(password) < 10:
        raise ValueError("Use a password of at least 10 characters.")
    store.save_user(username, role, generate_password_hash(password))
    store.audit("admin", "user.saved", None, username=username, role=role)


def bootstrap_users(store: Store, spec: str) -> None:
    """Create first logins from LOOK_BOOTSTRAP_USERS="alice:requester,bob:reviewer".

    Each missing user gets a random password, printed once to the server log.
    Users who already exist are left alone, so restarts change nothing.
    """
    for item in filter(None, (x.strip() for x in spec.split(","))):
        username, _, role = item.partition(":")
        if role not in ROLES:
            print(f"[look] skipping bootstrap user {item!r}: role must be one of {ROLES}", flush=True)
            continue
        password = secrets.token_urlsafe(12)
        if store.create_user_if_missing(username, role, generate_password_hash(password)):
            store.audit("bootstrap", "user.saved", None, username=username, role=role)
            print(f"[look] created {role} login '{username}' with password {password} (change it at /account)", flush=True)


def label(value: str) -> str:
    return value.replace("_", " ").capitalize()


def create_app(
    *,
    db_path: str | None = None,
    region: Region | str | None = None,
    adapters: list[SourceAdapter] | None = None,
    secret_key: str | None = None,
) -> Flask:
    app = Flask(__name__)
    app.jinja_loader = DictLoader(TEMPLATES)
    app.jinja_env.filters["label"] = label
    app.config.update(
        DB=db_path or os.environ.get("LOOK_DB", "look.db"),
        REGION=Region(region or os.environ.get("LOOK_REGION", "us")),
        SECRET_KEY=secret_key or os.environ.get("LOOK_SECRET_KEY") or secrets.token_hex(32),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("LOOK_INSECURE_COOKIES") != "1",
    )
    if os.environ.get("LOOK_BEHIND_PROXY") == "1":
        # Trust the reverse proxy's X-Forwarded-* headers so links use https.
        from werkzeug.middleware.proxy_fix import ProxyFix

        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    if os.environ.get("LOOK_BOOTSTRAP_USERS"):
        st = Store(app.config["DB"])
        bootstrap_users(st, os.environ["LOOK_BOOTSTRAP_USERS"])
        st.db.close()
    adapter_list = adapters if adapters is not None else default_adapters(app.config["REGION"].value)

    def svc() -> ScreeningService:
        if "svc" not in g:
            g.svc = ScreeningService(Store(app.config["DB"]), adapter_list)
        return g.svc

    @app.teardown_appcontext
    def _close(_exc):
        s = g.pop("svc", None)
        if s is not None:
            s.store.db.close()

    retention = os.environ.get("LOOK_RETENTION_DAYS")
    last_purge = {"at": 0.0}

    @app.before_request
    def _daily_purge():
        # Hosts without a cron job still delete reports past the retention period.
        import time

        if retention and time.time() - last_purge["at"] > 86400:
            last_purge["at"] = time.time()
            svc().purge_expired(retention_days=int(retention), actor="retention")

    @app.before_request
    def _csrf():
        session.setdefault("csrf", secrets.token_urlsafe(16))
        if request.method == "POST" and request.form.get("csrf") != session["csrf"]:
            abort(400, "Form expired. Go back and try again.")

    @app.after_request
    def _headers(resp):
        # Links carry private codes, so never leak them in the Referer header.
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'unsafe-inline'; form-action 'self'"
        resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.context_processor
    def _ctx():
        return {"user": session.get("user"), "role": session.get("role"),
                "csrf": session.get("csrf"), "region": app.config["REGION"].value}

    def login_required(role: str):
        def deco(fn):
            @wraps(fn)
            def inner(*a, **kw):
                if session.get("role") != role:
                    return redirect(url_for("login", next=request.path))
                return fn(*a, **kw)
            return inner
        return deco

    @app.errorhandler(NotFound)
    def _nf(e):
        return render_template("message.html", title="Not found", body=str(e) or "Not found."), 404

    @app.errorhandler(AccessDenied)
    def _ad(e):
        return render_template("message.html", title="Access denied", body=str(e)), 403

    # public / auth ----------------------------------------------------------

    @app.get("/")
    def home():
        if session.get("role") == "requester":
            return redirect(url_for("dashboard"))
        if session.get("role") == "reviewer":
            return redirect(url_for("review"))
        return render_template("home.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            row = svc().store.get_user(username)
            if row and check_password_hash(row[1], request.form.get("password", "")):
                csrf = session.get("csrf")
                session.clear()
                session.update(user=username, role=row[0], csrf=csrf)
                svc().store.audit(username, "user.login", None)
                nxt = request.args.get("next", "")
                return redirect(nxt if nxt.startswith("/") and not nxt.startswith("//") else url_for("home"))
            svc().store.audit(username or "<blank>", "user.login_failed", None)
            flash("Wrong username or password.")
        return render_template("login.html")

    @app.post("/logout")
    def logout():
        session.clear()
        return redirect(url_for("home"))

    @app.route("/account", methods=["GET", "POST"])
    def account():
        if not session.get("user"):
            return redirect(url_for("login", next="/account"))
        if request.method == "POST":
            st = svc().store
            role, pw_hash = st.get_user(session["user"])
            new = request.form.get("new_password", "")
            if not check_password_hash(pw_hash, request.form.get("current_password", "")):
                flash("Your current password is wrong.")
            elif len(new) < 10:
                flash("Use a new password of at least 10 characters.")
            else:
                st.save_user(session["user"], role, generate_password_hash(new))
                st.audit(session["user"], "user.password_changed", None)
                flash("Password changed.")
        return render_template("account.html")

    # requester --------------------------------------------------------------

    @app.get("/dashboard")
    @login_required("requester")
    def dashboard():
        s = svc()
        rows = []
        for r in reversed(s.store.requests_for(session["user"])):
            subj = s.store.get_subject(r.subject_id)
            rows.append({"req": r, "name": subj.full_name if subj else "(erased)"})
        return render_template("dashboard.html", rows=rows)

    @app.route("/requests/new", methods=["GET", "POST"])
    @login_required("requester")
    def new_request():
        region = app.config["REGION"]
        form = request.form
        if request.method == "POST":
            try:
                dob = date.fromisoformat(form["dob"]) if form.get("dob") else None
                subject = Subject(
                    full_name=form.get("full_name", "").strip(),
                    email=form.get("email", "").strip(),
                    date_of_birth=dob,
                    jurisdiction=form.get("jurisdiction", "").strip() or None,
                    license_number=form.get("license_number", "").strip() or None,
                    license_type=form.get("license_type", "").strip() or None,
                )
                if not subject.full_name or "@" not in subject.email:
                    raise ValueError("Enter the person's full name and email.")
                basis = form.get("lawful_basis") or None
                req = svc().create_request(
                    requester=session["user"],
                    subject=subject,
                    purpose=PermissiblePurpose(form.get("purpose")),
                    checks=[CheckType(c) for c in form.getlist("checks")],
                    purpose_statement=form.get("purpose_statement", ""),
                    region=region,
                    lawful_basis=LawfulBasis(basis) if basis else None,
                    legal_reference=form.get("legal_reference", "").strip() or None,
                )
                return redirect(url_for("request_detail", request_id=req.request_id))
            except (GuardrailError, ValueError) as e:
                flash(str(e))
        return render_template(
            "new_request.html",
            form=form,
            purposes=list(PermissiblePurpose),
            allowed={p.value: [c.value for c in CheckType if c in PURPOSE_ALLOWED_CHECKS[p]] for p in PermissiblePurpose},
            checks=list(CheckType),
            bases=list(LawfulBasis),
        )

    def _own_request(request_id):
        req = svc().store.get_request(request_id)
        if req is None or req.requester != session["user"]:
            raise NotFound("No such request.")
        return req

    @app.get("/requests/<request_id>")
    @login_required("requester")
    def request_detail(request_id):
        req = _own_request(request_id)
        subj = svc().store.get_subject(req.subject_id)
        sign_url = url_for("consent_page", token=req.consent_token, _external=True)
        return render_template("request.html", req=req, subj=subj, sign_url=sign_url)

    @app.post("/requests/<request_id>/run")
    @login_required("requester")
    def run_request(request_id):
        try:
            report = svc().run_request(request_id, requester=session["user"])
        except GuardrailError as e:
            flash(str(e))
            return redirect(url_for("request_detail", request_id=request_id))
        return redirect(url_for("requester_report", report_id=report.report_id))

    @app.get("/reports/<report_id>")
    @login_required("requester")
    def requester_report(report_id):
        s = svc()
        report = s.report_for_requester(report_id, requester=session["user"])
        subject_url = url_for("subject_report", report_id=report_id, code=report.access_token, _external=True)
        return render_template(
            "report.html", report=report, subj=s.store.get_subject(report.subject_id),
            findings=s.effective_findings(report), disputes=s.store.disputes_for_report(report_id),
            for_subject=False, subject_url=subject_url,
        )

    # subject ----------------------------------------------------------------

    @app.get("/consent/<token>")
    def consent_page(token):
        req, subj, text = svc().request_by_token(token)
        return render_template("consent.html", req=req, subj=subj, text=text, token=token)

    @app.post("/consent/<token>/sign")
    def consent_sign(token):
        try:
            svc().sign_request(token, signed_name=request.form.get("signed_name", ""))
        except ValueError as e:
            flash(str(e))
            return redirect(url_for("consent_page", token=token))
        return render_template(
            "message.html", title="Thank you",
            body="Your authorisation is recorded. You will receive a link to your report once the check is done.",
        )

    @app.post("/consent/<token>/decline")
    def consent_decline(token):
        svc().decline_request(token)
        return render_template(
            "message.html", title="Declined",
            body="You declined. No check will run, and the details entered about you have been deleted.",
        )

    @app.get("/my/<report_id>/<code>")
    def subject_report(report_id, code):
        s = svc()
        report = s.report_for_subject(report_id, access_token=code)
        consent = s.store.get_consent(report.consent_id)
        eu = consent is not None and consent.region == Region.EU
        log = s.subject_access_log(report_id, access_token=code)
        return render_template(
            "report.html", report=report, subj=s.store.get_subject(report.subject_id),
            findings=s.effective_findings(report), disputes=s.store.disputes_for_report(report_id),
            for_subject=True, code=code, eu=eu, log=log,
        )

    @app.post("/my/<report_id>/<code>/dispute")
    def subject_dispute(report_id, code):
        try:
            svc().open_dispute(
                report_id, access_token=code,
                finding_id=request.form.get("finding_id") or None,
                reason=request.form.get("reason", ""),
            )
            flash("Your dispute was sent to a reviewer.")
        except ValueError as e:
            flash(str(e))
        return redirect(url_for("subject_report", report_id=report_id, code=code))

    @app.post("/my/<report_id>/<code>/erase")
    def subject_erase(report_id, code):
        if request.form.get("confirm") != "yes":
            flash("Tick the box to confirm.")
            return redirect(url_for("subject_report", report_id=report_id, code=code))
        svc().erase_my_data(report_id, access_token=code)
        return render_template("message.html", title="Erased", body="Everything held about you has been deleted.")

    # reviewer ---------------------------------------------------------------

    @app.get("/review")
    @login_required("reviewer")
    def review():
        s = svc()
        items = []
        for d in s.store.open_disputes():
            report = s.store.get_report(d.report_id)
            finding = next((f for f in report.all_findings() if f.finding_id == d.finding_id), None) if report else None
            items.append({"d": d, "report": report, "finding": finding})
        s.store.audit(session["user"], "disputes.viewed", None, count=len(items))
        return render_template("review.html", items=items)

    @app.post("/review/<dispute_id>")
    @login_required("reviewer")
    def resolve(dispute_id):
        try:
            svc().resolve_dispute(
                dispute_id, reviewer=session["user"],
                upheld=request.form.get("outcome") == "upheld",
                note=request.form.get("note", ""),
            )
        except ValueError as e:
            flash(str(e))
        return redirect(url_for("review"))

    return app


TEMPLATES = {
    "base.html": """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{% block title %}look{% endblock %} · look screening</title>
<style>
:root{--bg:#f7f7f5;--fg:#1c1c1a;--muted:#6b6b66;--card:#fff;--line:#e2e1dc;--accent:#2f5d50;--warn:#9a4a12;--warnbg:#fdf3e8}
@media (prefers-color-scheme:dark){:root{--bg:#171716;--fg:#ecebe6;--muted:#a3a29b;--card:#22221f;--line:#3a3935;--accent:#7fb7a5;--warn:#f0a868;--warnbg:#3a2a1a}}
*{box-sizing:border-box}body{margin:0;font:16px/1.5 system-ui,sans-serif;background:var(--bg);color:var(--fg)}
header{display:flex;justify-content:space-between;align-items:center;padding:12px 16px;border-bottom:1px solid var(--line)}
header a{color:var(--fg);text-decoration:none;font-weight:600}main{max-width:820px;margin:0 auto;padding:24px 16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;margin:0 0 16px}
label{display:block;margin:12px 0 4px;font-weight:500}input[type=text],input[type=email],input[type=date],input[type=password],select,textarea{width:100%;padding:8px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--fg);font:inherit}
button{background:var(--accent);color:#fff;border:0;border-radius:6px;padding:8px 14px;font:inherit;cursor:pointer}button.link{background:none;color:var(--accent);padding:0}
.muted{color:var(--muted);font-size:14px}.flash{background:var(--warnbg);color:var(--warn);padding:10px 12px;border-radius:6px;margin-bottom:16px}
.warn{color:var(--warn)}table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:8px 6px;border-bottom:1px solid var(--line);vertical-align:top}
code{word-break:break-all;background:var(--bg);padding:2px 4px;border-radius:4px}.checks label{font-weight:400;margin:4px 0}
.pill{display:inline-block;padding:1px 8px;border-radius:99px;border:1px solid var(--line);font-size:13px}
</style></head><body>
<header><a href="/">look</a>
{% if user %}<form method="post" action="/logout" style="margin:0"><input type="hidden" name="csrf" value="{{ csrf }}"><a class="muted" href="/account" style="font-weight:400">{{ user }}</a><span class="muted"> · </span><button class="link">Log out</button></form>{% endif %}
</header><main>
{% with msgs = get_flashed_messages() %}{% for m in msgs %}<div class="flash">{{ m }}</div>{% endfor %}{% endwith %}
{% block body %}{% endblock %}</main></body></html>""",
    "message.html": """{% extends "base.html" %}{% block title %}{{ title }}{% endblock %}
{% block body %}<div class="card"><h1>{{ title }}</h1><p>{{ body }}</p></div>{% endblock %}""",
    "home.html": """{% extends "base.html" %}{% block body %}
<h1>Consent-based background screening</h1>
<div class="card"><p>look checks official public records (sanctions lists, company registries, licensing
boards{% if region == 'us' %}, court records and sex-offender registries{% endif %}) about a person
<strong>only after that person has signed</strong> to say they agree, for a stated reason.</p>
<p>It never collects home addresses, phone numbers, family members, location history, or social media.
Every search is logged, and the person can read their report, see who checked them, dispute mistakes{% if region == 'eu' %}, and have their data erased{% endif %}.</p>
<p><a href="/login">Log in</a> to request or review a check.</p></div>{% endblock %}""",
    "login.html": """{% extends "base.html" %}{% block title %}Log in{% endblock %}{% block body %}
<div class="card"><h1>Log in</h1><form method="post"><input type="hidden" name="csrf" value="{{ csrf }}">
<label>Username<input type="text" name="username" autocomplete="username" required></label>
<label>Password<input type="password" name="password" autocomplete="current-password" required></label>
<p><button>Log in</button></p></form></div>{% endblock %}""",
    "account.html": """{% extends "base.html" %}{% block title %}Account{% endblock %}{% block body %}
<div class="card"><h1>Change password</h1><form method="post"><input type="hidden" name="csrf" value="{{ csrf }}">
<label>Current password<input type="password" name="current_password" autocomplete="current-password" required></label>
<label>New password (10 characters or more)<input type="password" name="new_password" autocomplete="new-password" required></label>
<p><button>Change password</button></p></form></div>{% endblock %}""",
    "dashboard.html": """{% extends "base.html" %}{% block title %}Your checks{% endblock %}{% block body %}
<div style="display:flex;justify-content:space-between;align-items:center"><h1>Your checks</h1><a href="/requests/new"><button>New check</button></a></div>
<div class="card">{% if rows %}<table><tr><th>Person</th><th>Purpose</th><th>State</th><th>Created</th></tr>
{% for r in rows %}<tr><td><a href="/requests/{{ r.req.request_id }}">{{ r.name }}</a></td><td>{{ r.req.purpose.value|label }}</td>
<td><span class="pill">{{ r.req.state|label }}</span></td><td class="muted">{{ r.req.created_at.strftime('%Y-%m-%d') }}</td></tr>{% endfor %}</table>
{% else %}<p class="muted">No checks yet.</p>{% endif %}</div>{% endblock %}""",
    "new_request.html": """{% extends "base.html" %}{% block title %}New check{% endblock %}{% block body %}
<h1>New check</h1><form method="post" class="card"><input type="hidden" name="csrf" value="{{ csrf }}">
<p class="muted">The person will get a link to read exactly what you will search, and must sign before anything runs.</p>
<label>Full legal name<input type="text" name="full_name" value="{{ form.full_name }}" required></label>
<label>Email (we only use it to send them their link and report)<input type="email" name="email" value="{{ form.email }}" required></label>
<label>Date of birth (reduces false matches)<input type="date" name="dob" value="{{ form.dob }}"></label>
<label>Jurisdiction, for example {% if region == 'eu' %}DE or FR{% else %}US-CA{% endif %}<input type="text" name="jurisdiction" value="{{ form.jurisdiction }}"></label>
<label>Purpose<select name="purpose">{% for p in purposes %}<option value="{{ p.value }}" {% if form.purpose == p.value %}selected{% endif %}>{{ p.value|label }}</option>{% endfor %}</select></label>
<label>Checks</label><div class="checks">{% for c in checks %}
<label><input type="checkbox" name="checks" value="{{ c.value }}" {% if c.value in form.getlist('checks') %}checked{% endif %}> {{ c.value|label }}</label>{% endfor %}</div>
<p class="muted">Allowed per purpose: {% for p, cs in allowed.items() %}<br>{{ p|label }}: {{ cs|map('label')|join(', ') }}{% endfor %}</p>
<label>License number and type (only for a license check)</label>
<div style="display:flex;gap:8px"><input type="text" name="license_number" placeholder="Number" value="{{ form.license_number }}"><input type="text" name="license_type" placeholder="Type, e.g. RN" value="{{ form.license_type }}"></div>
<label>Why is this check needed? (the role, lease, or contract it is for)<textarea name="purpose_statement" rows="3" required>{{ form.purpose_statement }}</textarea></label>
{% if region == 'eu' %}
<label>GDPR lawful basis<select name="lawful_basis">{% for b in bases %}<option value="{{ b.value }}" {% if (form.lawful_basis or 'legitimate_interests') == b.value %}selected{% endif %}>{{ b.value|label }}</option>{% endfor %}</select></label>
<label>Law that requires or authorises the check (needed for legal obligation and any criminal-record check)<input type="text" name="legal_reference" value="{{ form.legal_reference }}"></label>
<p class="muted">Consent is not a valid basis for employment or housing in the EU. Criminal-record checks are only possible where a specific law authorises them; otherwise ask the person for their own official certificate.</p>
{% endif %}
<p><button>Create and get signing link</button></p></form>{% endblock %}""",
    "request.html": """{% extends "base.html" %}{% block title %}Check{% endblock %}{% block body %}
<h1>{{ subj.full_name if subj else '(erased)' }}</h1>
<div class="card"><p><span class="pill">{{ req.state|label }}</span> · {{ req.purpose.value|label }} · {{ req.checks|map(attribute='value')|map('label')|join(', ') }}</p>
<p class="muted">Reason: {{ req.purpose_statement }}</p>
{% if req.state == 'awaiting_signature' %}<p>Send this private link to <strong>{{ subj.email }}</strong>. Nothing runs until they sign.</p><p><code>{{ sign_url }}</code></p>
{% elif req.state == 'signed' %}<form method="post" action="/requests/{{ req.request_id }}/run"><input type="hidden" name="csrf" value="{{ csrf }}"><p>Signed. You can run the check now.</p><button>Run check</button></form>
{% elif req.state == 'complete' %}<p><a href="/reports/{{ req.report_id }}">Open the report</a></p>{% endif %}
</div>{% endblock %}""",
    "consent.html": """{% extends "base.html" %}{% block title %}Your authorisation{% endblock %}{% block body %}
<h1>Background check request</h1><div class="card">
{% if req.state != 'awaiting_signature' %}<p>You have already answered this request.</p>{% else %}
<p>Hello {{ subj.full_name }}. Please read this before you decide.</p><p>{{ text }}</p>
<form method="post" action="/consent/{{ token }}/sign"><input type="hidden" name="csrf" value="{{ csrf }}">
<label>Type your full name to sign: <strong>{{ subj.full_name }}</strong><input type="text" name="signed_name" required></label>
<p><button>I agree, sign</button></p></form>
<form method="post" action="/consent/{{ token }}/decline"><input type="hidden" name="csrf" value="{{ csrf }}"><button class="link">No, I do not agree</button></form>{% endif %}
</div>{% endblock %}""",
    "report.html": """{% extends "base.html" %}{% block title %}Report{% endblock %}{% block body %}
<h1>{% if for_subject %}Your screening report{% else %}Report: {{ subj.full_name }}{% endif %}</h1>
<div class="card"><p><span class="pill">{{ report.status.value|label }}</span> · {{ report.purpose.value|label }} · requested by {{ report.requester }} on {{ report.created_at.strftime('%Y-%m-%d') }}</p>
<table>{% for r in report.results %}<tr><td>{{ r.check_type.value|label }}</td><td class="muted">{{ r.source }}</td><td>{% if r.ok %}Searched{% else %}<span class="warn">Not searched: {{ r.error }}</span>{% endif %}</td></tr>{% endfor %}</table></div>
<h2>Possible matches</h2>
{% if not findings %}<div class="card"><p>None.</p></div>{% endif %}
{% for f, d in findings %}<div class="card"><p><strong>{{ f.summary }}</strong></p>
<p class="muted">Unverified. Matched on {{ f.match_basis|join(', ') }}. Source record: {{ f.record_reference }}</p>
<table>{% for k, v in f.details.items() if v %}<tr><td class="muted">{{ k|label }}</td><td>{{ v }}</td></tr>{% endfor %}</table>
{% if d and d.status.value == 'open' %}<p class="warn">Disputed by the person and under review. Do not rely on this.</p>
{% elif d and d.status.value == 'rejected' %}<p class="muted">Disputed; the reviewer kept it: {{ d.resolution_note }}</p>{% endif %}
{% if for_subject and not d %}<form method="post" action="/my/{{ report.report_id }}/{{ code }}/dispute"><input type="hidden" name="csrf" value="{{ csrf }}"><input type="hidden" name="finding_id" value="{{ f.finding_id }}">
<label>Is this wrong? Tell us why<textarea name="reason" rows="2" required></textarea></label><button>Dispute this</button></form>{% endif %}
</div>{% endfor %}
{% if disputes %}<h2>Disputes</h2><div class="card"><table>{% for d in disputes %}<tr><td>{{ 'Whole report' if not d.finding_id else 'Finding' }}</td><td>{{ d.reason }}</td><td><span class="pill">{{ d.status.value|label }}</span>{% if d.resolution_note %}<br><span class="muted">{{ d.resolution_note }}</span>{% endif %}</td></tr>{% endfor %}</table></div>{% endif %}
{% if for_subject %}
<div class="card"><form method="post" action="/my/{{ report.report_id }}/{{ code }}/dispute"><input type="hidden" name="csrf" value="{{ csrf }}">
<label>Dispute the report as a whole<textarea name="reason" rows="2" required></textarea></label><button>Send dispute</button></form></div>
<h2>Who has checked you, and why</h2><div class="card"><table>{% for e in log %}<tr><td class="muted">{{ e.ts[:16].replace('T',' ') }}</td><td>{{ e.actor }}</td><td>{{ e.action }}</td><td>{{ e.detail.get('purpose_statement','') }}</td></tr>{% endfor %}</table></div>
<h2>Your rights</h2><div class="card">
{% if eu %}<p>Under the GDPR you can access this data (this page), have mistakes corrected (dispute above), have it erased (below), object to the processing, and complain to your national data protection authority. This report is deleted automatically after the retention period.</p>
{% else %}<p>This report exists only because you consented. Every result is a possible match and must not be treated as confirmed until reviewed. You can dispute anything above free of charge, and a reviewer must tell you the outcome.</p>{% endif %}
<form method="post" action="/my/{{ report.report_id }}/{{ code }}/erase"><input type="hidden" name="csrf" value="{{ csrf }}">
<label><input type="checkbox" name="confirm" value="yes"> Delete everything held about me</label><button>Erase my data</button></form></div>
{% else %}
<div class="card"><p>Send the person this private link to their report, where they can dispute it:</p><p><code>{{ subject_url }}</code></p>
<p class="muted">Possible matches are not verified. Before you act on this report, give the person a copy, tell them their rights, and give them a fair chance to dispute it.</p></div>
{% endif %}{% endblock %}""",
    "review.html": """{% extends "base.html" %}{% block title %}Disputes{% endblock %}{% block body %}
<h1>Open disputes</h1>{% if not items %}<div class="card"><p>None.</p></div>{% endif %}
{% for it in items %}<div class="card"><p><strong>{{ it.finding.summary if it.finding else 'Whole report' }}</strong> <span class="muted">in {{ it.d.report_id }}</span></p>
{% if it.finding %}<p class="muted">Source record: {{ it.finding.record_reference }}</p>{% endif %}
<p>Person says: {{ it.d.reason }}</p>
<form method="post" action="/review/{{ it.d.dispute_id }}"><input type="hidden" name="csrf" value="{{ csrf }}">
<label>Outcome<select name="outcome"><option value="upheld">Upheld: remove it</option><option value="rejected">Rejected: re-verified, it stands</option></select></label>
<label>Note to the person (they will see this)<textarea name="note" rows="2" required></textarea></label><button>Resolve</button></form></div>{% endfor %}
{% endblock %}""",
}
