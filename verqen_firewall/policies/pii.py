"""PII detection policy pack: blocks prompts that carry credentials or personal data."""

from __future__ import annotations

from verqen_firewall.policies.base import PolicyPack, register

PII = register(
    PolicyPack(
        name="pii",
        description="PII and credential detection: SSN, credit cards, emails, API keys.",
        category_options=("none", "pii_extraction", "credential_leak", "pii_request"),
        rules=(
            (
                r"\b\d{3}-\d{2}-\d{4}\b",
                "pii_extraction",
                4,
                "ssn_pattern",
            ),
            (
                r"\b(?:\d[ -]?){13,16}\b",
                "pii_extraction",
                4,
                "credit_card_pattern",
            ),
            (
                r"\b[\w.+-]+@[\w-]+\.[\w.-]{2,}\b",
                "pii_request",
                2,
                "email_pattern",
            ),
            (
                r"\b(?:sk|pk|rk|ghp|xox[baprs])[-_][A-Za-z0-9]{16,}\b",
                "credential_leak",
                5,
                "api_key_pattern",
            ),
            (
                r"(?:my|the\s+user'?s?)\s+"
                r"(?:address|phone|date\s+of\s+birth|dob|passport)\s*[:=]",
                "pii_extraction",
                3,
                "pii_field_declaration",
            ),
        ),
    )
)
