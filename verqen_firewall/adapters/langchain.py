"""LangChain adapter: wrap any Runnable so inputs pass the firewall first."""

from __future__ import annotations

from typing import Any

from verqen_firewall.adapters._shared import extract_chat_text
from verqen_firewall.core import VerQenFirewall

__all__ = ["protect_langchain", "GuardedRunnable"]


def _first_text(inputs: Any) -> str | None:
    if isinstance(inputs, str):
        return inputs or None
    if isinstance(inputs, dict):
        found = extract_chat_text(inputs)
        if found:
            return found
        for value in inputs.values():
            if isinstance(value, str) and value.strip():
                return value
        return None
    return None


class GuardedRunnable:
    """Callable guard: check the input, then invoke the wrapped runnable.

    Pure Python with no LangChain import, so the guard itself is unit
    testable without LangChain installed.
    """

    def __init__(
        self,
        runnable: Any,
        firewall: VerQenFirewall,
        block_severity: int = 3,
        block_message: str = "Prompt blocked by VerQen Firewall",
    ):
        self.runnable = runnable
        self.firewall = firewall
        self.block_severity = block_severity
        self.block_message = block_message

    def __call__(self, inputs: Any) -> Any:
        text = _first_text(inputs)
        if text is not None:
            result = self.firewall.check(text)
            if not result.safe and result.severity >= self.block_severity:
                raise ValueError(
                    f"{self.block_message} "
                    f"(category={result.category}, severity={result.severity})"
                )
        return self.runnable.invoke(inputs)


def protect_langchain(
    runnable: Any,
    firewall: VerQenFirewall,
    *,
    block_severity: int = 3,
    block_message: str = "Prompt blocked by VerQen Firewall",
):
    """Wrap a LangChain Runnable in a firewall-checked ``RunnableLambda``.

    Usage::

        from verqen_firewall.adapters import protect_langchain
        chain = protect_langchain(llm, VerQenFirewall(...))
        chain.invoke("summarize this report")

    Raises ``ImportError`` with an install hint when LangChain is missing.
    """
    guard = GuardedRunnable(
        runnable,
        firewall,
        block_severity=block_severity,
        block_message=block_message,
    )
    try:
        from langchain_core.runnables import RunnableLambda
    except ImportError:
        try:  # LangChain < 0.2
            from langchain.schema.runnable import RunnableLambda
        except ImportError as exc:
            raise ImportError(
                "LangChain is required for protect_langchain(). "
                "Install it with: pip install verqen-firewall[langchain]"
            ) from exc
    return RunnableLambda(guard)
