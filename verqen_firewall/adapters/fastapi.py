"""FastAPI / Starlette middleware adapter."""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from verqen_firewall.adapters._shared import extract_prompt, firewall_headers
from verqen_firewall.core import VerQenFirewall

__all__ = ["VerQenFirewallMiddleware"]


class VerQenFirewallMiddleware(BaseHTTPMiddleware):
    """Check every request body before it reaches your FastAPI endpoints.

    Usage::

        from fastapi import FastAPI
        from verqen_firewall import VerQenFirewall
        from verqen_firewall.adapters import VerQenFirewallMiddleware

        app = FastAPI()
        app.add_middleware(VerQenFirewallMiddleware, firewall=VerQenFirewall(...))

    The last user message of OpenAI-style bodies (``messages``, ``prompt``,
    ``input``, ...) is checked. Unsafe prompts with ``severity >=
    block_severity`` get a 400 JSON error; every checked response carries
    ``X-VerQen-*`` headers with the verdict.
    """

    def __init__(self, app, firewall: VerQenFirewall, block_severity: int = 3):
        super().__init__(app)
        self.firewall = firewall
        self.block_severity = block_severity

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        body = await request.body()
        prompt = extract_prompt(body, request.headers.get("content-type", ""))
        result = self.firewall.check(prompt) if prompt is not None else None

        if result is not None and not result.safe and result.severity >= self.block_severity:
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

        response = await call_next(request)
        if result is not None:
            for key, value in firewall_headers(result).items():
                response.headers[key] = value
        return response
