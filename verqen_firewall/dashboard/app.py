"""FastAPI + HTMX dashboard: live view of checks, blocks and stats."""

from __future__ import annotations

import html
import threading
import time
from collections import deque
from dataclasses import asdict, dataclass
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from verqen_firewall.adapters._shared import extract_prompt
from verqen_firewall.core import VerQenFirewall

__all__ = ["create_dashboard_app", "Event"]

_TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
_STATIC = str(Path(__file__).parent / "static")


@dataclass
class Event:
    """One recorded check."""

    ts: float
    prompt: str
    safe: bool
    category: str
    severity: int
    confidence: float
    latency_ms: float
    blocked: bool

    def to_dict(self) -> dict:
        return asdict(self)


def create_dashboard_app(
    firewall: VerQenFirewall,
    *,
    max_events: int = 500,
    block_severity: int = 3,
    prompt_preview: int = 160,
) -> FastAPI:
    """Create a dashboard app around *firewall*.

    Endpoints:

    * ``GET /``: HTMX dashboard page
    * ``GET /api/check?prompt=...``: run a check and record it
    * ``POST /api/check``: same with a JSON or plain-text body
    * ``GET /api/events?since=<ts>``: events newer than *since*
    * ``GET /api/stats``: totals, block rate, category counts

    Requests whose body carries an OpenAI-style prompt (``messages``,
    ``prompt``, ...) are checked too and counted, so you can point traffic at
    this app as a sidecar and watch it live.
    """
    events: deque[Event] = deque(maxlen=max_events)
    lock = threading.Lock()
    totals = {"checked": 0, "blocked": 0}
    categories: dict[str, int] = {}

    def _record(result) -> Event:
        event = Event(
            ts=time.time(),
            prompt="",  # filled by caller
            safe=result.safe,
            category=result.category,
            severity=result.severity,
            confidence=result.confidence,
            latency_ms=result.latency_ms,
            blocked=(not result.safe and result.severity >= block_severity),
        )
        return event

    def _store(event: Event) -> None:
        with lock:
            events.append(event)
            totals["checked"] += 1
            if event.blocked:
                totals["blocked"] += 1
            categories[event.category] = categories.get(event.category, 0) + 1

    def _run(prompt: str) -> tuple[dict, Event]:
        result = firewall.check(prompt)
        event = _record(result)
        event.prompt = prompt[:prompt_preview]
        _store(event)
        payload = {
            "safe": result.safe,
            "category": result.category,
            "severity": result.severity,
            "confidence": round(result.confidence, 4),
            "conformal_set": result.conformal_set,
            "should_escalate": result.should_escalate,
            "latency_ms": round(result.latency_ms, 3),
            "blocked": event.blocked,
        }
        return payload, event

    @staticmethod
    def _verdict_html(payload: dict) -> str:
        badge = "blocked" if payload["blocked"] else "ok"
        label = "BLOCKED" if payload["blocked"] else "SAFE"
        return (
            f'<span class="badge {badge}">{label}</span> '
            f'<span class="ev-meta">{html.escape(payload["category"])}'
            f' &middot; severity {payload["severity"]}'
            f' &middot; confidence {payload["confidence"]:.2f}'
            f' &middot; {payload["latency_ms"]:.2f} ms</span>'
        )

    app = FastAPI(title="VerQen Firewall Dashboard", version="1.0.0")
    app.state.block_severity = block_severity
    app.mount("/static", StaticFiles(directory=_STATIC), name="static")

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request):
        with lock:
            stats = _stats_locked()
        return _TEMPLATES.TemplateResponse(
            request,
            "index.html",
            {"stats": stats, "block_severity": block_severity},
        )

    @app.get("/api/check")
    async def check_get(prompt: str):
        payload, _ = _run(prompt)
        return JSONResponse(payload)

    @app.post("/api/check")
    async def check_post(request: Request):
        body = await request.body()
        content_type = request.headers.get("content-type", "")
        prompt = extract_prompt(body, content_type) or body.decode("utf-8", "replace")
        if not prompt.strip():
            return JSONResponse({"error": "empty prompt"}, status_code=400)
        payload, _ = _run(prompt)
        return JSONResponse(payload)

    @app.post("/check", response_class=HTMLResponse)
    async def check_form(request: Request):
        """Form endpoint for the dashboard page: returns an HTML verdict fragment."""
        body = await request.body()
        prompt = extract_prompt(body, request.headers.get("content-type", ""))
        if not prompt or not prompt.strip():
            return HTMLResponse('<span class="muted">No prompt given.</span>')
        payload, _ = _run(prompt)
        return HTMLResponse(_verdict_html(payload))

    @app.get("/api/events")
    async def get_events(since: float = 0.0):
        with lock:
            return [e.to_dict() for e in events if e.ts > since]

    @app.get("/events-fragment", response_class=HTMLResponse)
    async def events_fragment(limit: int = 50):
        """HTMX fragment: newest events first as ``<li>`` rows."""
        with lock:
            rows = list(events)[-max(1, min(limit, max_events)):]
        if not rows:
            return HTMLResponse('<li class="muted">No events yet.</li>')
        items = []
        for event in reversed(rows):
            badge = "blocked" if event.blocked else "ok"
            label = "BLOCKED" if event.blocked else "SAFE"
            items.append(
                '<li>'
                f'<span class="badge {badge}">{label}</span> '
                f'<span class="ev-prompt">{html.escape(event.prompt)}</span> '
                f'<span class="ev-meta">sev {event.severity}'
                f' &middot; {event.latency_ms:.2f} ms</span>'
                "</li>"
            )
        return HTMLResponse("".join(items))

    def _stats_locked() -> dict:
        checked = totals["checked"]
        return {
            "checked": checked,
            "blocked": totals["blocked"],
            "block_rate": (totals["blocked"] / checked) if checked else 0.0,
            "categories": dict(sorted(categories.items(), key=lambda kv: -kv[1])),
        }

    @app.get("/stats-fragment", response_class=HTMLResponse)
    async def stats_fragment(request: Request):
        with lock:
            stats = _stats_locked()
        return _TEMPLATES.TemplateResponse(
            request,
            "_stats.html",
            {"stats": stats},
        )

    @app.get("/api/stats")
    async def get_stats():
        with lock:
            return _stats_locked()

    return app
