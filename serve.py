# serve.py — AgentOS Entry Point
#
# Exposes Scout, Coder, and the Orchestrator to the online dashboard at os.agno.com.
# Launch command: uv run serve.py
#
# The dashboard connects to this server via:
#   http://<DGX_IP>:7777   (if accessible externally)
#   or via tunnels (e.g. ngrok, cloudflared) if in a private LAN.

from agno.os import AgentOS
from agno.db.sqlite import SqliteDb

# Pre-configured agents and team (with tools, LLM, and instructions)
from core.agents import scout_agent, coder_agent, orchestrator_team, post_exploit_agent

# ── Persistent Storage (Local SQLite) ────────────────────────────────────────
# All sessions and runs are saved in agno.db in the project folder.
# This enables conversation history in the web UI.
db = SqliteDb(db_file="agno.db")

# ── AgentOS ──────────────────────────────────────────────────────────────────
agent_os = AgentOS(
    name="v1 — Offensive Framework",
    description=(
        "Automated offensive security framework running on DGX Spark. "
        "Scout runs reconnaissance (Nmap, Curl, MSF auxiliary). "
        "Coder configures and executes exploits via Metasploit RPC. "
        "Orchestrator coordinates the entire attack chain."
    ),
    db=db,
    # Expose individual agents (interactable separately from the dashboard)
    agents=[scout_agent, coder_agent, post_exploit_agent],
    # Expose the orchestrator team (main entry-point for complete attack flows)
    teams=[orchestrator_team],
    tracing=True,          # Enable run tracing on the dashboard
    telemetry=False,       # Disable anonymous telemetry sharing with Agno
)

# ── FastAPI app (for uvicorn import or testing) ──────────────────────────────
app = agent_os.get_app()

if __name__ == "__main__":
    # Bind to 0.0.0.0 to be reachable from LAN / tunnels
    # The os.agno.com dashboard will connect to http://<this-ip>:7777
    agent_os.serve(
        app="serve:app",
        host="0.0.0.0",
        port=7777,
        reload=False,
    )
