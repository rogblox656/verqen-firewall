"""Real-time HTMX dashboard for verqen-firewall.

    from verqen_firewall.dashboard import create_dashboard_app
    app = create_dashboard_app(firewall)
    # uvicorn.run(app, host="127.0.0.1", port=8000)
"""

from __future__ import annotations

from verqen_firewall.dashboard.app import create_dashboard_app

__all__ = ["create_dashboard_app"]
