# dashboard.py — THESEUS Attack Graph Dashboard
#
# Standalone FastAPI app on port 8890.
# Does NOT modify serve.py or core/ in any way.
#
# Launch: uv run dashboard.py
# Browse: http://localhost:8890

import json
import os
from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles

# ── Configuration ─────────────────────────────────────────────────────────────

CAMPAIGNS_DIR = Path("campaigns")
DASHBOARD_HOST = "0.0.0.0"
DASHBOARD_PORT = 8890

# Security headers applied to all responses.
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": (
        "default-src 'self'; "
        # D3.js CDN with pinned version
        "script-src 'self' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; "
        "connect-src 'self' ws: wss:; "
        "frame-ancestors 'none'; "
        "object-src 'none';"
    ),
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}

# ── Helpers ───────────────────────────────────────────────────────────────────


def _campaign_path(campaign: str) -> Path:
    """Resolve and validate that campaign stays within CAMPAIGNS_DIR."""
    base = CAMPAIGNS_DIR.resolve()
    target = (base / campaign / "graph.json").resolve()
    # Path traversal guard — target must be inside base
    if not str(target).startswith(str(base) + os.sep):
        raise ValueError("Invalid campaign name")
    return target


def _load_graph(path: Path) -> dict:
    """Load graph.json from disk, return empty graph on any error."""
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"nodes": [], "edges": [], "event_log": []}


def _compute_delta(old: dict, new: dict) -> dict | None:
    """Return newly added nodes and edges, or None if nothing changed."""
    old_node_ids = {n["id"] for n in old.get("nodes", [])}
    old_edge_ids = {e["id"] for e in old.get("edges", [])}
    new_nodes = [n for n in new.get("nodes", []) if n["id"] not in old_node_ids]
    new_edges = [e for e in new.get("edges", []) if e["id"] not in old_edge_ids]
    new_events = new.get("event_log", [])
    old_seqs = {ev["seq"] for ev in old.get("event_log", [])}
    added_events = [ev for ev in new_events if ev["seq"] not in old_seqs]
    if not new_nodes and not new_edges and not added_events:
        return None
    return {"nodes": new_nodes, "edges": new_edges, "event_log": added_events}


# ── WebSocket connection manager ──────────────────────────────────────────────


class ConnectionManager:
    def __init__(self):
        self._connections: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self._connections.append(ws)

    def disconnect(self, ws: WebSocket):
        self._connections = [c for c in self._connections if c is not ws]

    async def send(self, ws: WebSocket, data: dict):
        try:
            await ws.send_json(data)
        except Exception:
            self.disconnect(ws)


manager = ConnectionManager()


# ── FastAPI app ───────────────────────────────────────────────────────────────


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield  # nothing to setup/teardown


from core.knowledge_graph import AttackGraph
from pydantic import BaseModel

app = FastAPI(title="THESEUS Dashboard", lifespan=lifespan)

# Restrict CORS origins in production.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8890", "http://127.0.0.1:8890"],
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)


@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    for k, v in SECURITY_HEADERS.items():
        response.headers[k] = v
    return response


# ── REST endpoints ────────────────────────────────────────────────────────────


@app.get("/api/campaigns")
async def list_campaigns():
    """Return list of campaign folders."""
    if not CAMPAIGNS_DIR.exists():
        return JSONResponse({"campaigns": []})
    names = [
        d.name
        for d in CAMPAIGNS_DIR.iterdir()
        if d.is_dir() and (d / "graph.json").exists()
    ]
    return JSONResponse({"campaigns": sorted(names)})


@app.get("/api/graph")
async def get_graph(campaign: str = "drupal-lab"):
    """Return the full graph JSON for a campaign."""
    try:
        path = _campaign_path(campaign)
    except ValueError:
        return JSONResponse({"error": "Invalid campaign"}, status_code=400)
    graph = _load_graph(path)
    return JSONResponse(graph)


class DeleteNodeRequest(BaseModel):
    campaign: str
    node_id: str


class DeleteEventRequest(BaseModel):
    campaign: str
    seq: int


class UpdateHostStatusRequest(BaseModel):
    campaign: str
    node_id: str | None = None
    ip: str | None = None
    scout_status: str | None = None
    exploit_status: str | None = None
    postexploit_status: str | None = None
    phase: str | None = None
    status: str | None = None


@app.delete("/api/graph/node")
@app.post("/api/graph/node/delete")
async def delete_node_endpoint(req: DeleteNodeRequest = None, campaign: str = None, node_id: str = None):
    c_name = (req.campaign if req else None) or campaign
    n_id = (req.node_id if req else None) or node_id
    if not c_name or not n_id:
        return JSONResponse({"error": "Missing campaign or node_id parameter"}, status_code=400)

    try:
        _ = _campaign_path(c_name)
    except ValueError:
        return JSONResponse({"error": "Invalid campaign"}, status_code=400)

    g = AttackGraph.load_or_create(c_name, campaign_dir=str(CAMPAIGNS_DIR))
    success = g.delete_node(n_id)
    if success:
        return JSONResponse({"status": "ok", "message": f"Node '{n_id}' deleted successfully."})
    return JSONResponse({"status": "error", "message": f"Node '{n_id}' not found."}, status_code=404)


@app.delete("/api/graph/event")
@app.post("/api/graph/event/delete")
async def delete_event_endpoint(req: DeleteEventRequest = None, campaign: str = None, seq: int = None):
    c_name = (req.campaign if req else None) or campaign
    s_num = (req.seq if req else None) or seq
    if not c_name or s_num is None:
        return JSONResponse({"error": "Missing campaign or seq parameter"}, status_code=400)

    try:
        _ = _campaign_path(c_name)
    except ValueError:
        return JSONResponse({"error": "Invalid campaign"}, status_code=400)

    g = AttackGraph.load_or_create(c_name, campaign_dir=str(CAMPAIGNS_DIR))
    success = g.delete_event(int(s_num))
    if success:
        return JSONResponse({"status": "ok", "message": f"Event #{s_num} deleted successfully."})
    return JSONResponse({"status": "error", "message": f"Event #{s_num} not found."}, status_code=404)


@app.post("/api/graph/host/status")
@app.post("/api/graph/node/status")
@app.patch("/api/graph/host/status")
async def update_host_status_endpoint(req: UpdateHostStatusRequest):
    if not req.campaign or (not req.node_id and not req.ip):
        return JSONResponse({"error": "Missing campaign or node_id/ip parameter"}, status_code=400)

    try:
        _ = _campaign_path(req.campaign)
    except ValueError:
        return JSONResponse({"error": "Invalid campaign"}, status_code=400)

    g = AttackGraph.load_or_create(req.campaign, campaign_dir=str(CAMPAIGNS_DIR))

    # Resolve Host node
    node = None
    if req.node_id and req.node_id in g._nodes:
        node = g._nodes[req.node_id]
    elif req.ip:
        can_id = g._resolve_canonical_host_id(req.ip)
        node = g._nodes.get(can_id)
    elif req.node_id and req.node_id.startswith("host-"):
        ip = req.node_id.replace("host-", "")
        can_id = g._resolve_canonical_host_id(ip)
        node = g._nodes.get(can_id)

    if not node or node.type != "Host":
        return JSONResponse({"error": f"Host node not found for id={req.node_id}, ip={req.ip}"}, status_code=404)

    updated = {}
    if req.scout_status is not None:
        node.properties["scout_status"] = req.scout_status.lower()
        updated["scout_status"] = node.properties["scout_status"]

    if req.exploit_status is not None:
        val = req.exploit_status.lower()
        node.properties["exploit_status"] = val
        if val == "done":
            node.properties["status"] = "pwned"
        elif val in ("pending", "unsuccessful") and node.properties.get("status") == "pwned":
            node.properties["status"] = "alive"
        updated["exploit_status"] = val

    if req.postexploit_status is not None:
        node.properties["postexploit_status"] = req.postexploit_status.lower()
        updated["postexploit_status"] = node.properties["postexploit_status"]

    if req.phase and req.status:
        phase_key = f"{req.phase.lower()}_status"
        status_val = req.status.lower()
        node.properties[phase_key] = status_val
        if req.phase.lower() == "exploit":
            if status_val == "done":
                node.properties["status"] = "pwned"
            elif status_val in ("pending", "unsuccessful") and node.properties.get("status") == "pwned":
                node.properties["status"] = "alive"
        updated[phase_key] = status_val

    g._touch()
    g._save()

    return JSONResponse({
        "status": "ok",
        "message": f"Updated status for {node.id}",
        "node_id": node.id,
        "properties": node.properties,
    })


import asyncio

@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return Response(status_code=204)


# ── WebSocket — live graph updates ────────────────────────────────────────────


@app.websocket("/ws/graph")
async def ws_graph(ws: WebSocket, campaign: str = "drupal-lab"):
    """Stream graph deltas to the browser whenever graph.json changes."""
    try:
        path = _campaign_path(campaign)
    except ValueError:
        await ws.close(code=1008)
        return

    await manager.connect(ws)
    last = _load_graph(path)
    last_mtime = os.path.getmtime(path) if path.exists() else 0.0

    # Send initial full graph
    await manager.send(ws, {"type": "init", "data": last})

    try:
        while True:
            await asyncio.sleep(1.0)
            if not path.exists():
                continue
            current_mtime = os.path.getmtime(path)
            if current_mtime != last_mtime:
                last_mtime = current_mtime
                current = _load_graph(path)
                await manager.send(ws, {"type": "init", "data": current})
                last = current
    except (WebSocketDisconnect, RuntimeError, asyncio.CancelledError):
        pass
    finally:
        manager.disconnect(ws)


# ── Static files (web/) ───────────────────────────────────────────────────────

app.mount("/", StaticFiles(directory="web", html=True), name="static")


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    uvicorn.run(
        "dashboard:app",
        host=DASHBOARD_HOST,
        port=DASHBOARD_PORT,
        reload=False,
    )
