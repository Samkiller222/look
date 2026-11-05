# look

Consent-based background screening from official public records, in the
style of employment and tenant screening products. Python 3.10+. The core
and command line have no dependencies; the web app needs Flask.

It runs under **US (FCRA-style)** or **EU (GDPR)** rules, chosen with
`--region` or `LOOK_REGION`.

It is deliberately **not** a people-search tool. It cannot run a check on
someone who has not consented, and it never collects where a person lives or
how to contact or find them.

## Guardrails

| Rule | Where it is enforced |
| --- | --- |
| A check runs only with a signed, unexpired, unrevoked consent from the subject that names the purpose and each check type. | `guardrails.authorize_check` |
| Every check needs a named requester, an FCRA-style permissible purpose, and a written reason. Some purposes only allow some checks (no sex-offender search for a business deal, for example). | `guardrails.PURPOSE_ALLOWED_CHECKS` |
| Only official record sources are used, through adapters. Nothing scrapes social media or people-search sites. | `look/adapters/` |
| Home address, phone, relatives, location, social media handles, photos and SSNs are stripped from anything a source returns, and the subject record has no fields for them. | `guardrails.PROHIBITED_FIELDS`, `guardrails.scrub` |
| Every action (consent, check, denied check, view, dispute) goes into an append-only, hash-chained audit log. | `store.Store.audit`, `verify_audit_chain` |
| Results are "possible matches", never verified facts. A failed or unconfigured source makes the report `incomplete`, never `clear`. | `models.Report.status` |
| The subject gets an access code to read their report, see who checked them and why, and dispute any finding. An upheld dispute removes the finding. | `service.open_dispute`, `resolve_dispute` |

### Extra rules in EU mode (`--region eu`)

| Rule | Why |
| --- | --- |
| Every check needs a GDPR Article 6 lawful basis. Consent is refused as the basis for employment, volunteering, and housing. | The EDPB says consent is not freely given where there is an imbalance of power. The person still signs, as an acknowledgement. |
| Criminal-data checks (court records, sex-offender registry) only run on a "legal obligation" basis with the authorising law cited. | GDPR Article 10. Otherwise ask the person for their own official certificate (Führungszeugnis, VOG, extrait de casier judiciaire, and so on). |
| The EU Consolidated Financial Sanctions List is searched as well as OFAC. US-only sources are left out. | |
| The person can erase everything held about them, and declining a request erases it at once. `look purge --days 180` deletes reports past the retention period; run it daily. | Articles 17 and 5(1)(e). The audit log keeps only pseudonymous IDs. |

These guardrails help with compliance but do not replace it. In the EU you are
the data controller: you will also need a privacy notice, a record of
processing, and probably a legitimate interests assessment or DPIA. If you use this
to make real employment or housing decisions in the US you are likely a user
(or provider) of consumer reports under the FCRA, and state and local laws
(ban-the-box, fair-chance housing, and so on) also apply. Get legal advice
before you use it for real.

## Sources

| Check | Adapter | Configuration |
| --- | --- | --- |
| `sanctions` (EU) | EU Consolidated Financial Sanctions List | none; or set `LOOK_EU_SANCTIONS_PATH` to a local copy |
| `sanctions` | OFAC SDN list (US Treasury) | none; downloads `sdn.csv`, or set `LOOK_OFAC_SDN_PATH` to a local copy |
| `court_records` | CourtListener federal dockets | `LOOK_COURTLISTENER_TOKEN` |
| `corporate_registry` | OpenCorporates officer search | `LOOK_OPENCORPORATES_TOKEN` |
| `sex_offender_registry` | official registry API (state or NSOPW partner) | `LOOK_SOR_URL`, `LOOK_SOR_API_KEY` |
| `professional_license` | licensing board API | `LOOK_LICENSE_URL`, `LOOK_LICENSE_API_KEY` |

To add a source, subclass `look.adapters.SourceAdapter` and implement
`search(subject) -> list[Finding]`. `MockAdapter` is there for tests and
demos; pass `--mock` to the CLI to use mocks for every check.

## Web app

```sh
pip install ".[web]"
export LOOK_REGION=eu LOOK_SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
python -m look user add --username hr@acme --role requester
python -m look user add --username reviewer@acme --role reviewer
python -m look --mock serve          # http://127.0.0.1:8000, mock sources
```

How it flows:

1. A requester logs in, fills in **New check** (who, which checks, why, and
   the lawful basis in EU mode) and gets a private signing link.
2. They send that link to the person, who reads exactly what will be
   searched and signs by typing their name, or declines (which deletes them).
3. The requester runs the check and gets a second private link to send the
   person, where they can read their report, see who checked them and why,
   dispute any finding, and erase their data.
4. A reviewer logs in to resolve disputes. An upheld dispute removes the
   finding from the report.

### Putting it online

GitHub Pages only serves static files, so it can't run the app itself: there
is nowhere to keep logins, signatures, the audit log, or API keys. Split it:

- **Public front page on GitHub Pages.** `docs/index.html` is a static page
  explaining the service. In the repo's Settings > Pages, choose "Deploy from a
  branch", pick this branch and the `/docs` folder. Then set `data-app` on the
  "Open the app" button to your app's address.
- **The app on a server in the EU.** `render.yaml` deploys it to Render in
  Frankfurt with a persistent disk (New > Blueprint, then pick this repo).
  Once it is up, open the service's Shell and create logins with
  `python -m look user add --username you@example.com --role requester`.
  `LOOK_RETENTION_DAYS` makes the app delete old reports once a day.

- **Or your own VPS.** On a fresh Ubuntu server in the EU (Hetzner, OVH,
  Scaleway), with your domain's DNS pointing at it, run as root:

  ```sh
  git clone -b claude/project-thread-j1ko5n https://github.com/Samkiller222/look.git /opt/look
  bash /opt/look/deploy/setup.sh check.example.com
  ```

  It installs Docker, a firewall, automatic security updates and fail2ban,
  turns off SSH password logins if you use keys, starts the app behind Caddy
  (automatic HTTPS), and backs the database up daily to `/var/backups/look`.

Any other host that runs Docker works too, behind HTTPS:

```sh
docker build -t look . && docker run -p 8000:8000 -v look-data:/data \
  -e LOOK_REGION=eu -e LOOK_SECRET_KEY=... look
```

Session cookies are marked Secure, so the app must be served over HTTPS
except on your own machine.

## Command line walkthrough

```sh
alias look="python -m look --mock"   # drop --mock to use real sources

SID=$(look subject add --name "Jane Doe" --email jane@example.com --dob 1990-01-02 --actor hr@acme)

# Show the subject the disclosure, then record their signature
look consent disclosure --requester hr@acme --purpose employment --checks sanctions,court_records
CID=$(look consent record --subject $SID --requester hr@acme --purpose employment \
      --checks sanctions,court_records --signed-name "Jane Doe")

look check run --subject $SID --consent $CID --requester hr@acme --purpose employment \
  --why "Pre-hire screening for warehouse supervisor" --checks sanctions,court_records
# prints the report id and an access code to send to the subject

look report show --report <id> --requester hr@acme       # requester's view
look report view --report <id> --code <code>             # subject's view, with their rights
look report access-log --report <id> --code <code>       # subject: who checked me and why
look dispute open --report <id> --code <code> --finding <finding id> --reason "Not me"
look dispute resolve --dispute <id> --reviewer rev@acme --upheld --note "DOB differs"
look audit verify
```

## Tests

```sh
python -m unittest discover -s tests
```
