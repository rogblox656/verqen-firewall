"""Dashboard tests (in-memory stats, no GPU)."""

from __future__ import annotations

from fastapi.testclient import TestClient

from verqen_firewall.dashboard import create_dashboard_app


def _client(make_firewall, **kwargs) -> TestClient:
    return TestClient(create_dashboard_app(make_firewall(), **kwargs))


def test_index_renders(make_firewall):
    client = _client(make_firewall)
    response = client.get("/")
    assert response.status_code == 200
    assert "VerQen Firewall" in response.text


def test_static_css_served(make_firewall):
    client = _client(make_firewall)
    response = client.get("/static/style.css")
    assert response.status_code == 200
    assert "--bg" in response.text


def test_check_get_records_event(make_firewall):
    client = _client(make_firewall)
    response = client.get("/api/check", params={"prompt": "hello world"})
    assert response.status_code == 200
    payload = response.json()
    assert payload["safe"] is True
    assert payload["blocked"] is False

    events = client.get("/api/events").json()
    assert len(events) == 1
    assert events[0]["prompt"] == "hello world"

    stats = client.get("/api/stats").json()
    assert stats["checked"] == 1
    assert stats["blocked"] == 0
    assert stats["block_rate"] == 0.0


def test_check_post_json_body(make_firewall):
    client = _client(make_firewall)
    response = client.post(
        "/api/check", json={"messages": [{"role": "user", "content": "hi there"}]}
    )
    assert response.status_code == 200
    assert client.get("/api/events").json()[0]["prompt"] == "hi there"


def test_check_post_empty_body_rejected(make_firewall):
    client = _client(make_firewall)
    response = client.post(
        "/api/check", content=b"", headers={"content-type": "text/plain"}
    )
    # extract_prompt returns None for empty body, decode yields "", so 400.
    assert response.status_code == 400


def test_blocked_counts_in_stats(make_firewall):
    firewall = make_firewall(
        {"verdict": "injection", "category": "prompt_injection", "severity": 4}
    )
    client = TestClient(create_dashboard_app(firewall))
    client.get("/api/check", params={"prompt": "sneaky"})
    stats = client.get("/api/stats").json()
    assert stats["checked"] == 1
    assert stats["blocked"] == 1
    assert stats["block_rate"] == 1.0
    assert stats["categories"] == {"prompt_injection": 1}


def test_events_since_filter(make_firewall):
    client = _client(make_firewall)
    client.get("/api/check", params={"prompt": "one"})
    first_ts = client.get("/api/events").json()[0]["ts"]
    assert client.get("/api/events", params={"since": first_ts}).json() == []
    assert len(client.get("/api/events", params={"since": 0}).json()) == 1


def test_events_capped_at_max_events(make_firewall):
    client = _client(make_firewall, max_events=3)
    for i in range(5):
        client.get("/api/check", params={"prompt": f"msg {i}"})
    events = client.get("/api/events").json()
    assert len(events) == 3
    assert events[-1]["prompt"] == "msg 4"


def test_form_endpoint_returns_html_fragment(make_firewall):
    client = _client(make_firewall)
    response = client.post("/check", data={"prompt": "hello"})
    assert response.status_code == 200
    assert '<span class="badge ok">SAFE</span>' in response.text
    assert len(client.get("/api/events").json()) == 1


def test_form_endpoint_blocked_fragment(make_firewall):
    firewall = make_firewall(
        {"verdict": "injection", "category": "jailbreak", "severity": 5}
    )
    client = TestClient(create_dashboard_app(firewall))
    response = client.post("/check", data={"prompt": "bypass"})
    assert response.status_code == 200
    assert "BLOCKED" in response.text
    assert "jailbreak" in response.text


def test_form_endpoint_empty_prompt(make_firewall):
    client = _client(make_firewall)
    response = client.post("/check", data={"prompt": ""})
    assert response.status_code == 200
    assert "No prompt" in response.text
    assert client.get("/api/events").json() == []


def test_events_fragment_html(make_firewall):
    client = _client(make_firewall)
    client.get("/api/check", params={"prompt": "first"})
    response = client.get("/events-fragment")
    assert response.status_code == 200
    assert "first" in response.text
    assert 'class="badge ok"' in response.text

    empty = TestClient(create_dashboard_app(make_firewall()))
    assert "No events yet" in empty.get("/events-fragment").text


def test_stats_fragment_html(make_firewall):
    client = _client(make_firewall)
    client.get("/api/check", params={"prompt": "test"})
    response = client.get("/stats-fragment")
    assert response.status_code == 200
    assert "stat-grid" in response.text
    assert "checked" in response.text
