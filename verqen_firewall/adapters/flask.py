"""Flask adapter: a ``before_request`` hook that enforces the firewall."""

from __future__ import annotations

from verqen_firewall.adapters._shared import extract_prompt, firewall_headers
from verqen_firewall.core import VerQenFirewall

__all__ = ["flask_before_request"]


def flask_before_request(app, firewall: VerQenFirewall, block_severity: int = 3):
    """Register the firewall on a Flask app.

    Usage::

        app = Flask(__name__)
        flask_before_request(app, VerQenFirewall(...))

    Unsafe prompts with ``severity >= block_severity`` return a 400 JSON
    error before any view runs; checked responses get ``X-VerQen-*`` headers.
    The per-request result is also available as ``flask.g.verqen_result``.
    """

    def _check():
        from flask import g, jsonify, request

        raw = request.get_data(cache=True)
        prompt = extract_prompt(raw, request.content_type or "")
        result = firewall.check(prompt) if prompt is not None else None
        g.verqen_result = result
        if result is not None and not result.safe and result.severity >= block_severity:
            response = jsonify(
                {
                    "error": "Request blocked by VerQen Firewall",
                    "category": result.category,
                    "severity": result.severity,
                    "confidence": round(result.confidence, 4),
                }
            )
            response.status_code = 400
            response.headers.update(firewall_headers(result))
            return response
        return None

    def _add_headers(response):
        from flask import g

        result = getattr(g, "verqen_result", None)
        if result is not None:
            response.headers.update(firewall_headers(result))
        return response

    app.before_request(_check)
    app.after_request(_add_headers)
    return firewall
