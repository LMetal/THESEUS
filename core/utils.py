# core/utils.py
#
# Shared infrastructure utilities for the THESEUS framework.
# Framework-level helpers that are not specific to any single agent or tool module.

import subprocess


def get_attacker_container() -> str | None:
    """
    Discover the running attacker container (if any) without relying on hardcoded names.

    Strategy (in order):
    1. If the ATTACKER_CONTAINER env variable is set, use it directly.
    2. Look for any running Docker container that was launched by the benchmark harness
       (i.e. connected to ``machines_net-main_network``).
    3. Fall back to heuristic name-prefix matching (``kali``, ``msf``, ``attacker``)
       for non-benchmark deployments.

    Returns:
        The container ID/name to pass to ``docker exec``, or ``None`` if no suitable
        container is found or Docker is unavailable.
    """
    import os

    # 1. Explicit override via environment variable (highest priority)
    env_override = os.environ.get("ATTACKER_CONTAINER", "").strip()
    if env_override:
        return env_override

    try:
        # 2. Network-based discovery: find containers attached to the lab network
        net_check = subprocess.run(
            ["docker", "network", "inspect", "machines_net-main_network",
             "--format", "{{range .Containers}}{{.Name}} {{end}}"],
            capture_output=True, text=True, timeout=3
        )
        if net_check.returncode == 0 and net_check.stdout.strip():
            # Return the first container on the lab network that is running
            for name in net_check.stdout.strip().split():
                ps = subprocess.run(
                    ["docker", "ps", "--filter", f"name=^/{name}$",
                     "--filter", "status=running", "-q"],
                    capture_output=True, text=True, timeout=2
                )
                if ps.returncode == 0 and ps.stdout.strip():
                    return ps.stdout.strip().split()[0]

        # 3. Heuristic name-prefix fallback (bare-metal / custom deployments)
        for prefix in ("kali", "msf", "attacker"):
            ps = subprocess.run(
                ["docker", "ps", "--filter", f"name={prefix}",
                 "--filter", "status=running", "-q"],
                capture_output=True, text=True, timeout=2
            )
            if ps.returncode == 0 and ps.stdout.strip():
                return ps.stdout.strip().split()[0]

    except Exception:
        pass

    return None
