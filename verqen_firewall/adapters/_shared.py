"""Shared helpers for framework adapters: request-text extraction and verdict headers."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover
    from verqen_firewall.core import FirewallResult

__all__ = ["extract_prompt", "extract_chat_text", "firewall_headers"]

_TEXT_KEYS = (
    "prompt",
    "input",
    "text",
    "message",
    "query",
    "question",
    "instructions",
    "content",
)


def _join_blocks(value: Any) -> str | None:
    """Flatten a content-block list (``[{"type": "text", "text": "..."}]``) to text."""
    if not isinstance(value, list):
        return None
    parts: list[str] = []
    for block in value:
        if isinstance(block, str):
            parts.append(block)
        elif isinstance(block, dict) and isinstance(block.get("text"), str):
            parts.append(block["text"])
    joined = "\n".join(p for p in parts if p)
    return joined or None


def _message_text(message: dict[str, Any]) -> str | None:
    content = message.get("content")
    if isinstance(content, str):
        return content or None
    return _join_blocks(content)


def extract_chat_text(data: dict[str, Any]) -> str | None:
    """Extract the user text from an OpenAI-style payload.

    Handles ``{"messages": [...]}`` (last user message wins) and the common
    single-field shapes (``prompt``, ``input``, ``text``, ...).
    """
    messages = data.get("messages")
    if isinstance(messages, list):
        fallback: str | None = None
        for message in reversed(messages):
            if not isinstance(message, dict):
                continue
            text = _message_text(message)
            if not text:
                continue
            if message.get("role") == "user":
                return text
            fallback = fallback or text
        if fallback:
            return fallback
    for key in _TEXT_KEYS:
        value = data.get(key)
        if isinstance(value, str) and value.strip():
            return value
        joined = _join_blocks(value)
        if joined:
            return joined
    return None


def extract_prompt(raw: bytes | str | None, content_type: str = "") -> str | None:
    """Best-effort extraction of the user prompt from an HTTP request body.

    Returns ``None`` when no text could be found (empty or unreadable body).
    Unknown JSON shapes fall back to scanning the raw body, so unusual API
    payloads are still checked instead of silently skipped.
    """
    if raw is None:
        return None
    if isinstance(raw, bytes):
        if not raw:
            return None
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return None
    else:
        text = raw
    if not text.strip():
        return None

    ct = (content_type or "").split(";", 1)[0].strip().lower()
    if ct == "application/x-www-form-urlencoded":
        from urllib.parse import parse_qs

        for key, values in parse_qs(text).items():
            if key.lower() in _TEXT_KEYS and values and values[0].strip():
                return values[0]
        return None

    if ct in ("", "application/json", "text/json") or text.lstrip().startswith(("{", "[")):
        try:
            data = json.loads(text)
        except ValueError:
            data = None
        if isinstance(data, dict):
            found = extract_chat_text(data)
            if found:
                return found
        return text
    return text


def firewall_headers(result: "FirewallResult") -> dict[str, str]:
    """Standard ``X-VerQen-*`` response headers for a check result."""
    return {
        "X-VerQen-Safe": "true" if result.safe else "false",
        "X-VerQen-Category": result.category,
        "X-VerQen-Severity": str(result.severity),
        "X-VerQen-Confidence": f"{result.confidence:.4f}",
        "X-VerQen-Latency-Ms": f"{result.latency_ms:.2f}",
    }
