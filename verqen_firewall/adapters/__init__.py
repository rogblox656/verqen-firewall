"""Framework adapters for verqen-firewall.

Each adapter wraps an application or chain so every user message passes
through :class:`~verqen_firewall.core.VerQenFirewall` before reaching the
downstream LLM. Framework-specific imports stay inside the adapters, so
importing this package never requires Flask, Django or LangChain.
"""

from __future__ import annotations

__all__ = [
    "VerQenFirewallMiddleware",
    "flask_before_request",
    "DjangoVerQenFirewallMiddleware",
    "protect_langchain",
    "create_openai_proxy",
]


def __getattr__(name: str):
    # Lazy re-exports keep optional frameworks optional.
    if name == "VerQenFirewallMiddleware":
        from verqen_firewall.adapters.fastapi import VerQenFirewallMiddleware

        return VerQenFirewallMiddleware
    if name == "flask_before_request":
        from verqen_firewall.adapters.flask import flask_before_request

        return flask_before_request
    if name == "DjangoVerQenFirewallMiddleware":
        from verqen_firewall.adapters.django import DjangoVerQenFirewallMiddleware

        return DjangoVerQenFirewallMiddleware
    if name == "protect_langchain":
        from verqen_firewall.adapters.langchain import protect_langchain

        return protect_langchain
    if name == "create_openai_proxy":
        from verqen_firewall.adapters.openai_proxy import create_openai_proxy

        return create_openai_proxy
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
