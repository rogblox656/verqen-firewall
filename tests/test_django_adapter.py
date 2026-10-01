"""Django middleware adapter tests (needs the ``django`` optional extra)."""

from __future__ import annotations

import json

import pytest

pytest.importorskip(
    "django", reason='install the django extra: pip install "verqen-firewall[django]"'
)

from django.conf import settings

if not settings.configured:
    settings.configure(
        DEBUG=True,
        DEFAULT_CHARSET="utf-8",
        ALLOWED_HOSTS=["*"],
        VERQEN_BLOCK_SEVERITY=3,
    )

from verqen_firewall import VerQenFirewall
from verqen_firewall.adapters.django import DjangoVerQenFirewallMiddleware


class _Request:
    """Django-like request: the middleware only reads body and content_type."""

    def __init__(self, body: bytes, content_type: str = "application/json"):
        self.body = body
        self.content_type = content_type


def _json_body(prompt: str) -> bytes:
    return json.dumps({"messages": [{"role": "user", "content": prompt}]}).encode()


def _view(request) -> dict:
    request.view_ran = True
    return {"status": "ok"}


# --- settings integration ---------------------------------------------------


def test_django_settings_supply_block_severity():
    middleware = DjangoVerQenFirewallMiddleware(_view)
    assert middleware.block_severity == 3
    # An empty body never touches the checkpoint-requiring firewall property.
    assert middleware(_Request(b"")) == {"status": "ok"}


# --- middleware behavior ----------------------------------------------------


def test_django_safe_request_passes(make_firewall):
    request = _Request(_json_body("hello there"))
    response = DjangoVerQenFirewallMiddleware(
        _view, firewall=make_firewall(), block_severity=3
    )(request)
    assert request.verqen_result.safe is True
    assert response["status"] == "ok"
    assert response["X-VerQen-Safe"] == "true"
    assert response["X-VerQen-Category"] == "none"


def test_django_blocked_request_returns_400(make_firewall):
    firewall = make_firewall(
        {"verdict": "injection", "category": "prompt_injection", "severity": 4}
    )
    ran: list = []
    middleware = DjangoVerQenFirewallMiddleware(
        lambda request: ran.append(request), firewall=firewall, block_severity=3
    )
    response = middleware(_Request(_json_body("sneaky")))
    assert ran == []  # view never reached
    assert response.status_code == 400
    payload = json.loads(response.content)
    assert payload["category"] == "prompt_injection"
    assert payload["severity"] == 4
    assert payload["confidence"] > 0
    assert response["X-VerQen-Safe"] == "false"


def test_django_low_severity_not_blocked(make_firewall):
    firewall = make_firewall(
        {"verdict": "injection", "category": "jailbreak", "severity": 2}
    )
    response = DjangoVerQenFirewallMiddleware(
        _view, firewall=firewall, block_severity=3
    )(_Request(_json_body("sneaky but mild")))
    assert response["status"] == "ok"  # view ran
    assert response["X-VerQen-Safe"] == "false"


def test_django_empty_body_skips_check(fake_engine_cls):
    engine = fake_engine_cls()
    middleware = DjangoVerQenFirewallMiddleware(
        _view, firewall=VerQenFirewall(engine=engine), block_severity=3
    )
    response = middleware(_Request(b""))
    assert response == {"status": "ok"}
    assert "X-VerQen-Safe" not in response
    assert engine.calls == []
