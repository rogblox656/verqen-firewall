"""Shared test fixtures for verqen-firewall.

``FakeEngine`` mimics the real ``VerqenInferenceEngine.decide_multi`` output
shape so the whole suite runs without a GPU, torch or a checkpoint.
"""

from __future__ import annotations

import pytest

from verqen_firewall import VerQenFirewall

class FakeEngine:
    """Deterministic stand-in for the VerQen engine.

    Args:
        verdict: What the three noul injection probes answer: ``"safe"``
            (p_true 0.05, passes), ``"suspicious"`` (0.50 with an ambiguous
            prediction set) or ``"injection"`` (0.95, certified).
        category: Answer for the policy category question (must be in the
            active policy's options, otherwise the first option is used).
        severity: 1..5 severity for the score question (clamped to the range).
        escalate: Value of ``should_escalate`` on the probe answers.
        prediction_set: Override for the probes' ``prediction_set``.
    """

    def __init__(
        self,
        verdict: str = "safe",
        category: str = "none",
        severity: int = 3,
        escalate: bool = False,
        prediction_set: list[str] | None = None,
    ):
        self.verdict = verdict
        self.category = category
        self.severity = severity
        self.escalate = escalate
        self.prediction_set = prediction_set
        self.calls: list[dict] = []

    def decide_multi(self, state: str, questions: list[dict]) -> list[dict]:
        self.calls.append({"state": state, "questions": questions})
        out: list[dict] = []
        for question in questions:
            options = list(question.get("options") or [])
            qtype = question.get("type", "choice")
            if qtype == "noul":
                p_true = {"injection": 0.95, "suspicious": 0.50}.get(self.verdict, 0.05)
                default_set = {"injection": ["yes"], "suspicious": ["no", "yes"]}.get(
                    self.verdict, ["no"]
                )
                selected = "yes" if p_true >= 0.5 else "no"
                item = {
                    "type": "noul",
                    "selected": selected,
                    "value": p_true >= 0.5,
                    "p_true": p_true,
                    "probabilities": {"no": round(1.0 - p_true, 4), "yes": p_true},
                    "p_correct": max(p_true, 1.0 - p_true),
                    "confidence": max(p_true, 1.0 - p_true),
                    "margin": abs(1.0 - 2.0 * p_true),
                    "should_escalate": self.escalate,
                    "prediction_set": list(self.prediction_set or default_set),
                }
            elif qtype == "score":
                index = min(max(self.severity - 1, 0), len(options) - 1)
                selected = options[index]
                probs = {o: 0.0 for o in options}
                probs[selected] = 1.0
                item = {
                    "type": "score",
                    "selected": selected,
                    "probabilities": probs,
                    "expected_score": float(index),
                    "p_correct": 0.9,
                    "confidence": 0.9,
                    "margin": 1.0,
                    "should_escalate": False,
                    "prediction_set": list(options),
                }
            else:  # category question
                selected = self.category if self.category in options else options[0]
                other = 0.1 / max(1, len(options) - 1)
                probs = {o: (0.9 if o == selected else other) for o in options}
                item = {
                    "type": "choice",
                    "selected": selected,
                    "probabilities": probs,
                    "p_correct": 0.9,
                    "confidence": 0.9,
                    "margin": 0.8,
                    "should_escalate": False,
                    "prediction_set": [selected],
                }
            out.append(item)
        return out


@pytest.fixture
def fake_engine_cls():
    return FakeEngine


@pytest.fixture
def make_firewall():
    """Factory: ``make_firewall({"verdict": "injection"}, policy="jailbreak")``."""

    def _make(engine_kwargs: dict | None = None, **firewall_kwargs) -> VerQenFirewall:
        return VerQenFirewall(engine=FakeEngine(**(engine_kwargs or {})), **firewall_kwargs)

    return _make
