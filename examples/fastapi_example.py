"""FastAPI example: middleware-protected chat endpoint.

Run (needs VERQEN_CHECKPOINT and the [dashboard] extra for uvicorn)::

    uvicorn examples.fastapi_example:app --port 8000

Try it::

    curl -X POST localhost:8000/chat -H "content-type: application/json" \\
         -d '{"messages":[{"role":"user","content":"hello"}]}'
"""

from __future__ import annotations

from fastapi import FastAPI, Request

from verqen_firewall import VerQenFirewall
from verqen_firewall.adapters import VerQenFirewallMiddleware

app = FastAPI(title="verqen-firewall FastAPI example")
app.add_middleware(VerQenFirewallMiddleware, firewall=VerQenFirewall())


@app.post("/chat")
async def chat(request: Request) -> dict:
    body = await request.json()
    messages = body.get("messages", [])
    last = messages[-1].get("content", "") if messages else ""
    # In a real app you would call OpenAI/Claude here; the firewall has
    # already rejected unsafe prompts before this handler runs.
    return {"reply": f"Echo: {last}"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
