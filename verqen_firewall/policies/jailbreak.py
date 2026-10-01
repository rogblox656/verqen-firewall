"""Jailbreak policy pack: known bypass phrasings and roleplay escape attempts."""

from __future__ import annotations

from verqen_firewall.policies.base import PolicyPack, register

JAILBREAK = register(
    PolicyPack(
        name="jailbreak",
        description="Jailbreak and roleplay bypass detection (DAN, developer mode, hypotheticals).",
        category_options=("none", "jailbreak", "role_override", "system_override"),
        rules=(
            (
                r"\bDAN\b|\bdo\s+anything\s+now\b",
                "jailbreak",
                5,
                "dan_persona",
            ),
            (
                r"enable\s+developer\s+mode|developer\s+mode\s+(?:is\s+)?enabled",
                "jailbreak",
                5,
                "developer_mode_enable",
            ),
            (
                r"in\s+a?\s*hypothetical\s+world\s+(?:where|in\s+which)\s+"
                r"(?:you\s+)?(?:have|are)\s+no\s+",
                "jailbreak",
                4,
                "hypothetical_escape",
            ),
            (
                r"(?:as|act\s+as)\s+(?:an?\s+)?"
                r"(?:unfiltered|uncensored|unrestricted|without\s+ethics)\s+"
                r"(?:ai|model|assistant|version)",
                "role_override",
                4,
                "unfiltered_persona",
            ),
            (
                r"(?:repeat|print)\s+(?:the\s+)?"
                r"(?:beginning\s+of\s+)?your\s+(?:initial|original|first)\s+"
                r"(?:message|prompt|instruction)",
                "system_override",
                4,
                "first_message_leak",
            ),
            (
                r"from\s+now\s+on\s+(?:you\s+)?(?:will|must)\s+"
                r"(?:always|never)\s+(?:obey|follow|ignore)\s+",
                "role_override",
                4,
                "persistent_instruction_override",
            ),
        ),
    )
)
