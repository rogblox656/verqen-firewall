"""OpenAI-compatible proxy example.

Starts a proxy on :8080 that firewalls every chat-completions request and
forwards survivors to the real API (OPENAI_BASE_URL / OPENAI_API_KEY).

Run::

    export VERQEN_CHECKPOINT=/path/to/checkpoint
    export OPENAI_API_KEY=sk-...
    python examples/openai_proxy_example.py

Point a client at it::

    client = OpenAI(base_url="http://localhost:8080/v1")
"""

from __future__ import annotations

from verqen_firewall import VerQenFirewall
from verqen_firewall.adapters import create_openai_proxy


def main() -> None:
    import uvicorn

    app = create_openai_proxy(VerQenFirewall())
    print("VerQen Firewall proxy: http://localhost:8080/v1/chat/completions")
    uvicorn.run(app, host="127.0.0.1", port=8080)


if __name__ == "__main__":
    main()
