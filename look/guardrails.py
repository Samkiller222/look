"""Rules every check must pass before and after it touches a data source."""

from __future__ import annotations

from typing import Any

from .models import CheckType, Consent, LawfulBasis, PermissiblePurpose, Region, Subject


class GuardrailError(Exception):
    """Raised when a check is not allowed to run."""


# Fields that must never appear in stored findings, whatever a source returns.
# This keeps the tool a screening product and not a people-locator.
PROHIBITED_FIELDS = frozenset(
    {
        "address",
        "home_address",
        "street",
        "street_address",
        "residence",
        "city",
        "zip",
        "zip_code",
        "postal_code",
        "latitude",
        "longitude",
        "lat",
        "lon",
        "geo",
        "coordinates",
        "location",
        "location_history",
        "phone",
        "phone_number",
        "telephone",
        "mobile",
        "cell",
        "relatives",
        "family",
        "family_members",
        "associates",
        "spouse",
        "children",
        "parents",
        "social_media",
        "social_profiles",
        "facebook",
        "instagram",
        "twitter",
        "tiktok",
        "linkedin",
        "photo",
        "photo_url",
        "image",
        "email",
        "ssn",
        "social_security_number",
    }
)

# Which purposes may use which checks. Sex-offender registry checks, for
# example, are not appropriate for a business transaction.
PURPOSE_ALLOWED_CHECKS: dict[PermissiblePurpose, frozenset[CheckType]] = {
    PermissiblePurpose.EMPLOYMENT: frozenset(CheckType),
    PermissiblePurpose.VOLUNTEER_SCREENING: frozenset(CheckType),
    PermissiblePurpose.SUBJECT_SELF_REQUEST: frozenset(CheckType),
    PermissiblePurpose.TENANT_SCREENING: frozenset(
        {CheckType.SANCTIONS, CheckType.SEX_OFFENDER_REGISTRY, CheckType.COURT_RECORDS}
    ),
    PermissiblePurpose.PROFESSIONAL_LICENSING: frozenset(
        {CheckType.SANCTIONS, CheckType.COURT_RECORDS, CheckType.PROFESSIONAL_LICENSE}
    ),
    PermissiblePurpose.BUSINESS_TRANSACTION_INITIATED_BY_SUBJECT: frozenset(
        {CheckType.SANCTIONS, CheckType.CORPORATE_REGISTRY}
    ),
}

MIN_PURPOSE_STATEMENT_LEN = 20

# Checks that process personal data relating to criminal convictions and
# offences (GDPR Article 10).
CRIMINAL_DATA_CHECKS = frozenset({CheckType.SEX_OFFENDER_REGISTRY, CheckType.COURT_RECORDS})

EU_CRIMINAL_DATA_REFUSAL = (
    "Under GDPR Article 10, criminal record checks are only allowed where a specific "
    "EU or national law authorises them. Choose the 'legal obligation' basis and cite "
    "that law, or ask the candidate to request their own official certificate "
    "(for example a Führungszeugnis, VOG, extrait de casier judiciaire, or certificado "
    "de antecedentes penales) instead."
)

EMPLOYMENT_LIKE = frozenset(
    {
        PermissiblePurpose.EMPLOYMENT,
        PermissiblePurpose.VOLUNTEER_SCREENING,
        PermissiblePurpose.TENANT_SCREENING,
    }
)


def check_eu_rules(consent: Consent, purpose: PermissiblePurpose, checks: list[CheckType]) -> None:
    """GDPR rules on top of the general ones. Raises GuardrailError."""
    if consent.lawful_basis is None:
        raise GuardrailError("EU checks need a GDPR lawful basis (Article 6).")
    if consent.lawful_basis == LawfulBasis.CONSENT and purpose in EMPLOYMENT_LIKE:
        raise GuardrailError(
            "Consent is not a valid GDPR basis where there is an imbalance of power, such as "
            "employment or housing (EDPB Guidelines 05/2020). Use legitimate interests, "
            "contract, or legal obligation; the subject's signature is still recorded."
        )
    if consent.lawful_basis == LawfulBasis.LEGAL_OBLIGATION and not (consent.legal_reference or "").strip():
        raise GuardrailError("Cite the law that creates the legal obligation.")
    if any(c in CRIMINAL_DATA_CHECKS for c in checks):
        if consent.lawful_basis != LawfulBasis.LEGAL_OBLIGATION:
            raise GuardrailError(EU_CRIMINAL_DATA_REFUSAL)


def authorize_check(
    *,
    subject: Subject,
    consent: Consent | None,
    requester: str,
    purpose: PermissiblePurpose,
    purpose_statement: str,
    checks: list[CheckType],
) -> None:
    """Raise GuardrailError unless this check is allowed to run."""
    if not requester or not requester.strip():
        raise GuardrailError("A named requester is required for every check.")
    if consent is None:
        raise GuardrailError("No consent on file for this subject. Record consent first.")
    if consent.subject_id != subject.subject_id:
        raise GuardrailError("Consent belongs to a different subject.")
    if not consent.is_active():
        raise GuardrailError("Consent is expired or revoked.")
    if consent.purpose != purpose:
        raise GuardrailError(
            f"Consent was given for '{consent.purpose.value}', not '{purpose.value}'."
        )
    if len((purpose_statement or "").strip()) < MIN_PURPOSE_STATEMENT_LEN:
        raise GuardrailError(
            "Describe why this check is needed (for example the role or lease it is for)."
        )
    if not checks:
        raise GuardrailError("Choose at least one check to run.")
    not_consented = [c for c in checks if c not in consent.authorized_checks]
    if not_consented:
        raise GuardrailError(
            "Subject did not consent to: " + ", ".join(c.value for c in not_consented)
        )
    not_allowed = [c for c in checks if c not in PURPOSE_ALLOWED_CHECKS[purpose]]
    if not_allowed:
        raise GuardrailError(
            f"Not permitted for purpose '{purpose.value}': "
            + ", ".join(c.value for c in not_allowed)
        )
    if consent.region == Region.EU:
        check_eu_rules(consent, purpose, checks)
    if CheckType.PROFESSIONAL_LICENSE in checks and not subject.license_number:
        raise GuardrailError("A license check needs the subject's license number.")


def scrub(details: Any) -> Any:
    """Recursively drop prohibited fields from data returned by a source."""
    if isinstance(details, dict):
        return {
            k: scrub(v)
            for k, v in details.items()
            if str(k).lower() not in PROHIBITED_FIELDS
        }
    if isinstance(details, list):
        return [scrub(v) for v in details]
    return details
