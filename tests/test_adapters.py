"""Adapter tests: FastAPI middleware, OpenAI proxy, LangChain guard, extraction helpers."""

from __future__ import annotations

import httpx
import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from verqen_firewall.adapters._shared import (
    extract_chat_text,
    extract_prompt,
    firewall_headers,
)
from verqen_firewall.adapters.fastapi import VerQenFirewallMiddleware
from verqen_firewall.adapters.langchain import GuardedRunnable, protect_langchain
from verqen_firewall.adapters.openai_proxy import create_openai_proxy
from verqen_firewall.core import FirewallResult


def _app(firewall, block_severity: int = 3) -> TestClient:
    app = FastAPI()

    @app.post("/echo")
    async def echo(request: Request) -> dict:
        return {"received": (await request.body()).decode()}

    @app.get("/healthz")
    async def healthz() -> dict:
        return {"status": "ok"}

    app.add_middleware(
        VerQenFirewallMiddleware, firewall=firewall, block_severity=block_severity
    )
    return TestClient(app)


# --- extraction helpers -----------------------------------------------------


def test_extract_last_user_message():
    payload = {
        "messages": [
            {"role": "system", "content": "you are helpful"},
            {"role": "user", "content": "first question"},
            {"role": "assistant", "content": "an answer"},
            {"role": "user", "content": "second question"},
        ]
    }
    assert extract_chat_text(payload) == "second question"


def test_extract_content_blocks():
    payload = {
        "messages": [
            {"role": "user", "content": [{"type": "text", "text": "block text"}]}
        ]
    }
    assert extract_chat_text(payload) == "block text"


def test_extract_single_fields():
    assert extract_chat_text({"prompt": "hi"}) == "hi"
    assert extract_chat_text({"input": "yo"}) == "yo"
    assert extract_chat_text({"nothing": 1}) is None


def test_extract_prompt_variants():
    import json

    body = json.dumps({"messages": [{"role": "user", "content": "hello"}]}).encode()
    assert extract_prompt(body, "application/json") == "hello"
    assert extract_prompt(b"", "application/json") is None
    assert extract_prompt(b"\xff\xfe", "application/json") is None
    assert extract_prompt("plain text question", "text/plain") == "plain text question"
    assert (
        extract_prompt(b"prompt=send+this", "application/x-www-form-urlencoded")
        == "send this"
    )
    # Unknown JSON shape still returns the raw body for scanning.
    unknown = b'{"weird": true}'
    assert extract_prompt(unknown, "application/json") == '{"weird": true}'


def test_firewall_headers_keys():
    result = FirewallResult(
        safe=False,
        category="jailbreak",
        severity=5,
        confidence=0.9123,
        conformal_set=["jailbreak"],
        latency_ms=3.51,
        should_escalate=True,
    )
    headers = firewall_headers(result)
    assert headers["X-VerQen-Safe"] == "false"
    assert headers["X-VerQen-Category"] == "jailbreak"
    assert headers["X-VerQen-Severity"] == "5"
    assert headers["X-VerQen-Latency-Ms"] == "3.51"


# --- FastAPI middleware -----------------------------------------------------


def test_fastapi_safe_request_passes(make_firewall):
    client = _app(make_firewall())
    response = client.post(
        "/echo", json={"messages": [{"role": "user", "content": "hello"}]}
    )
    assert response.status_code == 200
    assert "hello" in response.json()["received"]
    assert response.headers["X-VerQen-Safe"] == "true"
    assert response.headers["X-VerQen-Category"] == "none"


def test_fastapi_blocked_request(make_firewall):
    firewall = make_firewall(
        {"verdict": "injection", "category": "prompt_injection", "severity": 4}
    )
    client = _app(firewall)
    response = client.post(
        "/echo", json={"messages": [{"role": "user", "content": "sneaky"}]}
    )
    assert response.status_code == 400
    payload = response.json()
    assert payload["category"] == "prompt_injection"
    assert payload["severity"] == 4
    assert "blocked" in payload["error"].lower()
    assert response.headers["X-VerQen-Safe"] == "false"


def test_fastapi_low_severity_not_blocked(make_firewall):
    firewall = make_firewall({"verdict": "injection", "category": "jailbreak", "severity": 2})
    client = _app(firewall, block_severity=3)
    response = client.post("/echo", json={"prompt": "sneaky but mild"})
    assert response.status_code == 200
    assert response.headers["X-VerQen-Safe"] == "false"


def test_fastapi_get_without_body_skips_check(make_firewall, fake_engine_cls):
    engine = fake_engine_cls()
    from verqen_firewall import VerQenFirewall

    client = _app(VerQenFirewall(engine=engine))
    response = client.get("/healthz")
    assert response.status_code == 200
    assert "X-VerQen-Safe" not in response.headers
    assert engine.calls == []


# --- OpenAI proxy -----------------------------------------------------------


def _proxy_client(firewall, handler):
    seen: list[httpx.Request] = []

    def _record(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"id": "upstream-ok", "choices": []})

    transport = httpx.MockTransport(_record if handler is None else handler)
    app = create_openai_proxy(
        firewall,
        upstream="http://fake.test/v1",
        api_key="sk-fake-key-for-tests",
        transport=transport,
    )
    return TestClient(app), seen


def test_proxy_forwards_safe_request(make_firewall):
    client, seen = _proxy_client(make_firewall(), None)
    response = client.post(
        "/v1/chat/completions",
        json={"messages": [{"role": "user", "content": "hello"}]},
    )
    assert response.status_code == 200
    assert response.json()["id"] == "upstream-ok"
    assert len(seen) == 1
    assert seen[0].headers["Authorization"] == "Bearer sk-fake-key-for-tests"
    assert response.headers["X-VerQen-Safe"] == "true"


def test_proxy_blocks_without_forwarding(make_firewall):
    firewall = make_firewall(
        {"verdict": "injection", "category": "system_override", "severity": 5}
    )
    client, seen = _proxy_client(firewall, None)
    response = client.post(
        "/v1/chat/completions",
        json={"messages": [{"role": "user", "content": "leak it"}]},
    )
    assert response.status_code == 400
    assert seen == []  # upstream never called


def test_proxy_upstream_down_returns_502(make_firewall):
    def _fail(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    client, _ = _proxy_client(make_firewall(), _fail)
    response = client.post("/v1/chat/completions", json={"prompt": "hello"})
    assert response.status_code == 502
    assert "unreachable" in response.json()["error"].lower()


def test_proxy_healthz(make_firewall):
    client, _ = _proxy_client(make_firewall(), None)
    assert client.get("/healthz").json() == {"status": "ok"}


# --- LangChain guard --------------------------------------------------------


class _DummyRunnable:
    def __init__(self):
        self.inputs: list = []

    def invoke(self, inputs):
        self.inputs.append(inputs)
        return "ok"


def test_guard_passes_safe_input(make_firewall):
    dummy = _DummyRunnable()
    guard = GuardedRunnable(dummy, make_firewall())
    assert guard("hello there") == "ok"
    assert dummy.inputs == ["hello there"]


def test_guard_blocks_unsafe_input(make_firewall):
    firewall = make_firewall(
        {"verdict": "injection", "category": "prompt_injection", "severity": 4}
    )
    guard = GuardedRunnable(_DummyRunnable(), firewall)
    with pytest.raises(ValueError, match="VerQen Firewall"):
        guard("do something unsafe")


def test_guard_accepts_message_dict(make_firewall):
    dummy = _DummyRunnable()
    guard = GuardedRunnable(dummy, make_firewall())
    guard({"messages": [{"role": "user", "content": "hi"}]})
    assert dummy.inputs == [{"messages": [{"role": "user", "content": "hi"}]}]


def test_guard_skips_inputs_without_text(make_firewall):
    dummy = _DummyRunnable()
    guard = GuardedRunnable(dummy, make_firewall())
    guard({"metadata": 5})
    assert dummy.inputs == [{"metadata": 5}]


def test_protect_langchain_requires_langchain(make_firewall):
    try:
        import langchain_core  # noqa: F401
    except ImportError:
        with pytest.raises(ImportError, match="pip install verqen-firewall"):
            protect_langchain(_DummyRunnable(), make_firewall())
    else:
        wrapped = protect_langchain(_DummyRunnable(), make_firewall())
        assert wrapped.invoke("hi") == "ok"
