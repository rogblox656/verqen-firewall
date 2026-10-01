"""Built-in policy packs for verqen-firewall.

Importing this package registers the built-in packs:

* ``owasp_llm``: injection, jailbreak, PII, role override (default)
* ``pii``: PII and credential detection only
* ``jailbreak``: jailbreak and roleplay bypass detection only
"""

from __future__ import annotations

from verqen_firewall.policies.base import (
    PolicyPack,
    RuleHit,
    load_policy,
    register,
    registered_policies,
)

# Importing the modules registers their packs with the registry.
from verqen_firewall.policies import jailbreak as _jailbreak  # noqa: F401
from verqen_firewall.policies import owasp_llm as _owasp_llm  # noqa: F401
from verqen_firewall.policies import pii as _pii  # noqa: F401

__all__ = [
    "PolicyPack",
    "RuleHit",
    "load_policy",
    "register",
    "registered_policies",
    "available_policies",
]


def available_policies() -> list[str]:
    """Names of every registered policy pack."""
    return registered_policies()
