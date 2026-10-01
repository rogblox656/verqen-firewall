"""Drop-in OpenAI-compatible proxy that firewalls chat completions requests."""

from __future__ import annotations

import os

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from verqen_firewall.adapters._shared import extract_chat_text, firewall_headers
from verqen_firewall.core import VerQenFirewall

__all__ = ["create_openai_proxy"]

_DEFAULT_UPSTREAM = "https://api.openai.com/v1"


def create_openai_proxy(
    firewall: VerQenFirewall,
    *,
    upstream: str | None = None,
    api_key: str | None = None,
    block_severity: int = 3,
    timeout: float = 60.0,
    transport: httpx.AsyncBaseTransport | None = None,
) -> FastAPI:
    """Create a FastAPI app that proxies ``POST /v1/chat/completions``.

    Every request's last user message is checked first; unsafe prompts with
    ``severity >= block_severity`` are rejected with 400, safe prompts are
    forwarded to *upstream* (default: ``OPENAI_BASE_URL`` or the OpenAI API).

    Args:
        firewall: The enforcing :class:`~verqen_firewall.core.VerQenFirewall`.
        upstream: Base URL of the real API, e.g. ``https://api.openai.com/v1``.
        api_key: Bearer token for the upstream (default: ``OPENAI_API_KEY``).
        transport: Optional ``httpx`` transport (for tests or custom gateways).

    Point your client at this app's base URL instead of the provider's.
    """
    base = (upstream or os.environ.get("OPENAI_BASE_URL") or _DEFAULT_UPSTREAM).rstrip("/")
    forward_url = base if base.endswith("/chat/completions") else f"{base}/chat/completions"
    key = api_key if api_key is not None else os.environ.get("OPENAI_API_KEY")

    app = FastAPI(title="VerQen Firewall Proxy", version="1.0.0")

    async def _handle(request: Request) -> Response:
        body = await request.json()
        result = None
        if isinstance(body, dict):
            prompt = extract_chat_text(body)
            if prompt is not None:
                result = firewall.check(prompt)
                if (
                    not result.safe
                    and result.severity >= block_severity
                ):
                    return JSONResponse(
                        status_code=400,
                        content={
                            "error": "Request blocked by VerQen Firewall",
                            "category": result.category,
                            "severity": result.severity,
                            "confidence": round(result.confidence, 4),
                        },
                        headers=firewall_headers(result),
                    )

        headers = {"Content-Type": "application/json"}
        if key:
            headers["Authorization"] = f"Bearer {key}"

        try:
            async with httpx.AsyncClient(timeout=timeout, transport=transport) as client:
                upstream_response = await client.post(forward_url, json=body, headers=headers)
        except httpx.HTTPError as exc:
            return JSONResponse(
                status_code=502,
                content={
                    "error": "Upstream API unreachable",
                    "detail": str(exc),
                    "hint": "Check OPENAI_BASE_URL / network connectivity",
                },
            )

        response = Response(
            content=upstream_response.content,
            status_code=upstream_response.status_code,
            media_type=upstream_response.headers.get("content-type", "application/json"),
        )
        if result is not None:
            for header, value in firewall_headers(result).items():
                response.headers[header] = value
        return response

    app.add_api_route("/v1/chat/completions", _handle, methods=["POST"])
    app.add_api_route("/chat/completions", _handle, methods=["POST"])
    app.add_api_route("/healthz", lambda: {"status": "ok"}, methods=["GET"])
    return app
