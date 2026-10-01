"""Policy packs: deterministic rules plus model question sets for the firewall."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

__all__ = ["PolicyPack", "RuleHit", "load_policy"]


@dataclass(frozen=True)
class RuleHit:
    """A deterministic (pre-model) match from a policy pack."""

    category: str
    severity: int
    confidence: float
    rule_name: str


@dataclass(frozen=True)
class PolicyPack:
    """A named policy: regex pre-filter rules plus model question vocabulary.

    Args:
        name: Pack identifier (``"owasp_llm"``, ``"pii"``, ``"jailbreak"``).
        description: Human-readable purpose, shown by ``load_policy`` errors.
        category_options: Option list for the model's category question. The
            first entry must be ``"none"`` (the safe option).
        rules: Compiled regex rules scanned before the model runs. Each rule
            maps ``(pattern, category, severity, rule_name)``.
    """

    name: str
    description: str
    category_options: tuple[str, ...] = ("none",)
    rules: tuple[tuple[str, str, int, str], ...] = field(default_factory=tuple)

    _compiled: tuple[tuple[re.Pattern[str], str, int, str], ...] = ()

    def __post_init__(self) -> None:
        if self.category_options[0] != "none":
            raise ValueError(f'policy "{self.name}": category_options must start with "none"')
        compiled = []
        for pattern, category, severity, rule_name in self.rules:
            severity = int(severity)
            if not 1 <= severity <= 5:
                raise ValueError(
                    f'policy "{self.name}", rule "{rule_name}": '
                    f"severity must be 1..5, got {severity}"
                )
            compiled.append(
                (re.compile(pattern, re.IGNORECASE), category, severity, rule_name)
            )
        object.__setattr__(self, "_compiled", tuple(compiled))

    def scan(self, text: str) -> RuleHit | None:
        """Return the first matching rule, or ``None`` to defer to the model."""
        for pattern, category, severity, rule_name in self._compiled:
            if pattern.search(text):
                return RuleHit(
                    category=category,
                    severity=severity,
                    confidence=0.99,
                    rule_name=rule_name,
                )
        return None


_REGISTRY: dict[str, PolicyPack] = {}


def register(pack: PolicyPack) -> PolicyPack:
    """Add *pack* to the registry (used by the built-in packs)."""
    _REGISTRY[pack.name] = pack
    return pack


def registered_policies() -> list[str]:
    """Names of every registered policy pack (sorted)."""
    return sorted(_REGISTRY)


def load_policy(policy: str | PolicyPack) -> PolicyPack:
    """Resolve a policy pack by name.

    Raises ``ValueError`` listing every available pack when the name is unknown.
    """
    if isinstance(policy, PolicyPack):
        return policy
    try:
        return _REGISTRY[policy]
    except KeyError:
        available = ", ".join(sorted(_REGISTRY)) or "(none registered)"
        raise ValueError(
            f'unknown policy "{policy}"; available policies: {available}'
        ) from None
