# look

Consent-based background screening from official public records, in the
style of employment and tenant screening products. Pure Python 3.10+, no
dependencies.

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

These guardrails help with compliance but do not replace it. If you use this
to make real employment or housing decisions in the US you are likely a user
(or provider) of consumer reports under the FCRA, and state and local laws
(ban-the-box, fair-chance housing, and so on) also apply. Get legal advice
before you use it for real.

## Sources

| Check | Adapter | Configuration |
| --- | --- | --- |
| `sanctions` | OFAC SDN list (US Treasury) | none; downloads `sdn.csv`, or set `LOOK_OFAC_SDN_PATH` to a local copy |
| `court_records` | CourtListener federal dockets | `LOOK_COURTLISTENER_TOKEN` |
| `corporate_registry` | OpenCorporates officer search | `LOOK_OPENCORPORATES_TOKEN` |
| `sex_offender_registry` | official registry API (state or NSOPW partner) | `LOOK_SOR_URL`, `LOOK_SOR_API_KEY` |
| `professional_license` | licensing board API | `LOOK_LICENSE_URL`, `LOOK_LICENSE_API_KEY` |

To add a source, subclass `look.adapters.SourceAdapter` and implement
`search(subject) -> list[Finding]`. `MockAdapter` is there for tests and
demos; pass `--mock` to the CLI to use mocks for every check.

## Walkthrough

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
