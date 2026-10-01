"""Django middleware adapter.

Add ``verqen_firewall.adapters.django.DjangoVerQenFirewallMiddleware`` to your
``MIDDLEWARE`` list. Configuration comes from settings::

    VERQEN_CHECKPOINT = "/path/to/verqen-checkpoint"
    VERQEN_POLICY = "owasp_llm"
    VERQEN_BLOCK_SEVERITY = 3

or construct the middleware directly with an explicit firewall (useful in
tests)::

    MIDDLEWARE = ["verqen_firewall.adapters.django.DjangoVerQenFirewallMiddleware"]

Django itself is only imported when the middleware runs, so this module can be
imported (and unit tested) without Django installed.
"""

from __future__ import annotations

from typing import Any, Callable

from verqen_firewall.adapters._shared import extract_prompt, firewall_headers
from verqen_firewall.core import VerQenFirewall

__all__ = ["DjangoVerQenFirewallMiddleware"]


class DjangoVerQenFirewallMiddleware:
    """Block unsafe prompts before they reach a Django view."""

    def __init__(
        self,
        get_response: Callable[[Any], Any],
        firewall: VerQenFirewall | None = None,
        block_severity: int | None = None,
    ):
        self.get_response = get_response
        self._firewall = firewall
        if block_severity is None:
            from django.conf import settings  # only when built by Django

            block_severity = int(getattr(settings, "VERQEN_BLOCK_SEVERITY", 3))
        self.block_severity = block_severity

    @property
    def firewall(self) -> VerQenFirewall:
        if self._firewall is None:
            from django.conf import settings

            self._firewall = VerQenFirewall(
                checkpoint=getattr(settings, "VERQEN_CHECKPOINT", None),
                policy=getattr(settings, "VERQEN_POLICY", "owasp_llm"),
            )
        return self._firewall

    def __call__(self, request) -> Any:
        prompt = extract_prompt(request.body, getattr(request, "content_type", "") or "")
        result = self.firewall.check(prompt) if prompt is not None else None
        request.verqen_result = result

        if result is not None and not result.safe and result.severity >= self.block_severity:
            from django.http import JsonResponse

            return JsonResponse(
                {
                    "error": "Request blocked by VerQen Firewall",
                    "category": result.category,
                    "severity": result.severity,
                    "confidence": round(result.confidence, 4),
                },
                status=400,
                headers=firewall_headers(result),
            )

        response = self.get_response(request)
        if result is not None:
            for key, value in firewall_headers(result).items():
                response[key] = value
        return response
