"""
Attack Surface Metrics & Agno Tool Hooks.

Provides a unified counter and telemetry hook for tracking tool calls
that interact with the attack surface (target networks, services, hosts, exploits, shells).
Internal AKG (Attack Knowledge Graph) management tools are strictly excluded from the count.
"""

from __future__ import annotations
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional


class AttackSurfaceMetrics:
    """Thread-safe telemetry tracker for attack-surface tool calls across all agents."""

    def __init__(self):
        self._lock = threading.Lock()
        self._counter: int = 0
        self._history: List[Dict[str, Any]] = []

    def record_call(self, tool_name: str, agent_name: str = "unknown", args: Optional[Dict[str, Any]] = None):
        with self._lock:
            self._counter += 1
            self._history.append({
                "seq": self._counter,
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "tool": tool_name,
                "agent": agent_name,
                "args": args or {},
            })

    @property
    def count(self) -> int:
        with self._lock:
            return self._counter

    def get_history(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._history)

    def reset(self):
        with self._lock:
            self._counter = 0
            self._history.clear()


# Shared singleton instance across all agents in the process
_metrics = AttackSurfaceMetrics()


import inspect

async def attack_surface_tool_hook(name: str, func: Callable, args: Dict[str, Any], agent: Any = None, team: Any = None) -> Any:
    """
    Agno tool hook that intercepts and counts tool calls interacting with the attack surface.
    Internal AKG management tools (prefixed with 'akg_') and delegation tools are explicitly excluded.

    Args:
        name: Name of the executed tool function.
        func: The entrypoint callable to continue execution.
        args: Arguments dictionary passed to the tool.
        agent: Optional agent instance passed by Agno.
        team: Optional team instance passed by Agno.
    """
    # Exclude internal AKG knowledge graph manipulation and team delegation tools
    if not name.startswith("akg_") and not name.startswith("delegate_"):
        agent_name = "unknown"
        if agent and hasattr(agent, "name") and agent.name:
            agent_name = agent.name
        elif team and hasattr(team, "name") and team.name:
            agent_name = team.name

        _metrics.record_call(tool_name=name, agent_name=agent_name, args=args)

    res = func(**args)
    if inspect.isawaitable(res) or inspect.iscoroutine(res):
        res = await res
    return res


# ── Public API helpers ────────────────────────────────────────────────────────

def get_attack_surface_calls() -> int:
    """Return the total number of attack surface tool calls recorded so far."""
    return _metrics.count


def get_attack_surface_history() -> List[Dict[str, Any]]:
    """Return the chronological history of all attack surface tool executions."""
    return _metrics.get_history()


def reset_attack_surface_counter() -> None:
    """Reset the attack surface tool calls counter to 0."""
    _metrics.reset()
