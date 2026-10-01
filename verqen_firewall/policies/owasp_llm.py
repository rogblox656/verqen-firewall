"""OWASP LLM Top-10 inspired policy pack (injection, jailbreak, PII, role overrides)."""

from __future__ import annotations

from verqen_firewall.policies.base import PolicyPack, register

OWASP_LLM = register(
    PolicyPack(
        name="owasp_llm",
        description="OWASP LLM Top-10 oriented checks: injection, jailbreak, PII, role override.",
        category_options=(
            "none",
            "prompt_injection",
            "jailbreak",
            "pii_extraction",
            "role_override",
            "system_override",
        ),
        rules=(
            # LLM01: Prompt Injection
            (
                r"ignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+"
                r"(?:instructions|prompts|rules|messages)",
                "prompt_injection",
                4,
                "ignore_previous_instructions",
            ),
            (
                r"disregard\s+(?:your|the|all)\s+(?:system\s+)?"
                r"(?:prompt|instructions|guidelines|rules)",
                "prompt_injection",
                4,
                "disregard_system_rules",
            ),
            (
                r"(?:you|u)\s+are\s+now\s+(?:in\s+)?(?:developer|dan|jailbreak)\s*mode",
                "jailbreak",
                4,
                "developer_mode_switch",
            ),
            (
                r"\benable\s+(?:developer|dan|jailbreak)\s+mode",
                "jailbreak",
                4,
                "enable_developer_mode",
            ),
            (
                r"(?-i:\bDAN\b)",
                "jailbreak",
                4,
                "dan_persona",
            ),
            # LLM02: Insecure plugin/tool output handling
            (
                r"(?:execute|run)\s+the\s+following\s+(?:as\s+)?(?:shell|command|code)\b",
                "prompt_injection",
                4,
                "instruction_smuggled_as_task",
            ),
            # LLM06: Sensitive information disclosure
            (
                r"(?:reveal|print|show|repeat|output)\s+(?:your|the)\s+"
                r"(?:system\s+prompt|hidden\s+instructions|developer\s+message)",
                "system_override",
                5,
                "system_prompt_exfiltration",
            ),
            (
                r"\b(?:ssn|social\s+security\s+number)\b\s*[:=]?\s*\d{3}-?\d{2}-?\d{4}",
                "pii_extraction",
                4,
                "pii_ssn_literal",
            ),
            (
                r"\b(?:api[_-]?key|secret|token|password)\s*[:=]\s*\S+",
                "pii_extraction",
                4,
                "credential_literal",
            ),
            # LLM07: System prompt leakage via roleplay
            (
                r"pretend\s+(?:you\s+)?(?:have\s+)?no\s+"
                r"(?:restrictions|rules|guidelines|filters)",
                "jailbreak",
                4,
                "unrestricted_roleplay",
            ),
        ),
    )
)
