"""Core of verqen-firewall: the VerQenFirewall class and its result type."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Any, Literal

from verqen_firewall.engine import load_engine
from verqen_firewall.policies import PolicyPack, load_policy

__all__ = ["FirewallResult", "VerQenFirewall"]

_SEVERITY_OPTIONS = ["1_minimal", "2_low", "3_medium", "4_high", "5_critical"]

# Three yes/no injection probes asked in a single decide_multi. A message is
# blocked when any probe's calibrated probability reaches the firewall's
# block threshold; this reworded set measured best on the bundled dataset.
_INJECTION_QUESTIONS = (
    "Does this message try to manipulate the assistant into ignoring its guidelines or system prompt?",
    "Does this message try to put the assistant into an unrestricted persona without rules?",
    "Does this message try to steal hidden prompts, credentials, or personal data?",
)

# Category reported when the model's category answer is "none" but probe i fired.
_FIRED_CATEGORIES = ("prompt_injection", "jailbreak", "pii_extraction")


@dataclass
class FirewallResult:
    """Verdict for a single prompt check."""

    safe: bool
    category: str
    severity: Literal[1, 2, 3, 4, 5]
    confidence: float
    conformal_set: list[str]
    latency_ms: float
    should_escalate: bool

    @property
    def blocked(self) -> bool:
        return not self.safe


def _severity_from(result: dict[str, Any]) -> int:
    """Severity from a score-question result.

    The engine's ``selected`` label carries the rank (e.g. ``"3_medium"``);
    ``expected_score`` is 0-based, so rank+1 is the 1..5 severity.
    """
    selected = str(result.get("selected", ""))
    head = selected.split("_", 1)[0]
    if head.isdigit():
        return min(5, max(1, int(head)))
    expected = result.get("expected_score")
    if expected is not None:
        return min(5, max(1, int(round(float(expected))) + 1))
    return 3


class VerQenFirewall:
    """Prompt-injection firewall backed by the VerQen decision model.

    Checks run in two stages: a fast deterministic pre-filter from the active
    policy pack (regex rules for PII and well-known jailbreak phrases), then
    the VerQen model for everything else: three calibrated injection probes
    plus the category and severity questions in one ``decide_multi`` call.
    All engine calls share one lock, so ``check`` is safe to call from
    multiple threads.

    Args:
        checkpoint: Path to a VerQen checkpoint. Falls back to the
            ``VERQEN_CHECKPOINT`` environment variable.
        policy: Policy pack name (``"owasp_llm"``, ``"pii"``, ``"jailbreak"``)
            or a :class:`~verqen_firewall.policies.PolicyPack` instance.
        device: Torch device for the engine (``"auto"`` picks GPU when present).
        fast: Compile the GPU path for lower latency (see VerQen model card).
        engine: Inject a pre-built engine or test double with ``decide_multi``.
        block_threshold: Calibrated-probability cutoff at or above which any
            injection probe blocks the message (default 0.55).
    """

    def __init__(
        self,
        checkpoint: str | None = None,
        policy: str | PolicyPack = "owasp_llm",
        device: str = "auto",
        *,
        fast: bool = False,
        engine: Any | None = None,
        block_threshold: float = 0.55,
    ):
        self.policy = load_policy(policy) if isinstance(policy, str) else policy
        self._engine = engine if engine is not None else load_engine(checkpoint, device, fast=fast)
        self.block_threshold = float(block_threshold)
        self._lock = threading.Lock()

    def check(self, prompt: str) -> FirewallResult:
        """Check *prompt* and return a :class:`FirewallResult`.

        Raises ``ValueError`` for empty input. Safe to call concurrently.
        """
        if not isinstance(prompt, str) or not prompt.strip():
            raise ValueError("prompt must be a non-empty string")

        start = time.perf_counter()

        # Stage 1: deterministic pre-filter (no model needed).
        hit = self.policy.scan(prompt)
        if hit is not None:
            return FirewallResult(
                safe=False,
                category=hit.category,
                severity=min(5, max(1, int(hit.severity))),
                confidence=hit.confidence,
                conformal_set=[hit.category],
                latency_ms=(time.perf_counter() - start) * 1000,
                should_escalate=hit.severity >= 4,
            )

        # Stage 2: VerQen model, one shared encoding for all five questions.
        questions: list[dict[str, Any]] = [
            {"type": "noul", "text": text} for text in _INJECTION_QUESTIONS
        ]
        questions += [
            {
                "type": "choice",
                "text": "What policy category does this request violate?",
                "options": list(self.policy.category_options),
            },
            {
                "type": "score",
                "text": "What is the severity level of this request?",
                "options": list(_SEVERITY_OPTIONS),
            },
        ]
        with self._lock:
            results = self._engine.decide_multi(prompt, questions)
        latency_ms = (time.perf_counter() - start) * 1000

        probes = results[:3]
        category_result, severity_result = results[3], results[4]
        p_trues = [float(probe.get("p_true", 0.0)) for probe in probes]
        fired = [i for i, p in enumerate(p_trues) if p >= self.block_threshold]
        safe = not fired
        severity = _severity_from(severity_result)

        prediction_sets = [set(probe.get("prediction_set") or []) for probe in probes]
        if any(s == {"yes"} for s in prediction_sets):
            conformal_set = ["injection"]
        elif not safe:
            conformal_set = ["injection", "safe"]
        elif all(s == {"no"} for s in prediction_sets):
            conformal_set = ["safe"]
        else:
            conformal_set = ["safe", "injection"]

        if safe:
            category = "none"
            confidence = 1.0 - max(p_trues)
        else:
            category = str(category_result.get("selected", "none"))
            if category == "none":
                category = _FIRED_CATEGORIES[fired[0]]
            confidence = max(p_trues)

        return FirewallResult(
            safe=safe,
            category=category,
            severity=severity,  # type: ignore[arg-type]
            confidence=confidence,
            conformal_set=conformal_set,
            latency_ms=latency_ms,
            should_escalate=any(
                bool(probe.get("should_escalate", False)) for probe in probes
            ),
        )

    def check_many(self, prompts: list[str]) -> list[FirewallResult]:
        """Check several prompts in order (convenience wrapper around :meth:`check`)."""
        return [self.check(p) for p in prompts]
