# scout_tools.py
import json
import time
import subprocess
import xml.etree.ElementTree as ET
from typing import Union
from core.rpc_client import msf_client


from config import ATTACKER_LHOST

def msf_execute_scanner(module_path: str, rhosts: str, rport: Union[int, str], extra_options: Union[dict, str] = None) -> str:
    """
    Auxiliary tool for the SCOUT agent. Loads and executes a scanning,
    discovery, or fingerprinting module in Metasploit (e.g. auxiliary/scanner/portscan/tcp,
    auxiliary/scanner/http/dir_scanner, auxiliary/scanner/http/apache_mod_cgi_bash_env).

    NOTE: Only accepts auxiliary/ modules. Exploit/ or post/ modules are NOT allowed.

    Uses the MSF console API to capture real scanner output. The older
    module.execute + module.results approach always returned null for auxiliary
    scanners because results are written to console output only.

    Args:
        module_path: Path of the Metasploit auxiliary module.
        rhosts: Target IP or host/range to scan.
        rport: Port to scan (e.g. 80) or port range/list (e.g. "1-1000", "22,80,443").
        extra_options: Optional dictionary or JSON string of module options (e.g. {"TARGETURI": "/cgi-bin/vulnerable", "PATH": "/cgi-bin/"}).
    """
    import re

    if isinstance(extra_options, str):
        try:
            extra_options = json.loads(extra_options)
        except Exception:
            extra_options = {}

    # Guard: only auxiliary/ modules are permitted for reconnaissance
    if not module_path.startswith("auxiliary/"):
        return json.dumps({
            "status": "error",
            "message": (
                f"Invalid module '{module_path}' for msf_execute_scanner: "
                f"only auxiliary/ modules (e.g., 'auxiliary/scanner/portscan/tcp') are allowed."
            )
        })

    # Guard: verify pivot route presence for internal targets
    try:
        from core.coder_tools import _check_target_pivot_status
        first_rhost = str(rhosts).split()[0].split(",")[0]
        route_ok, route_msg = _check_target_pivot_status(first_rhost)
        if not route_ok:
            return json.dumps({
                "status": "error",
                "message": route_msg,
                "open_ports": [],
                "findings": [],
                "loot": []
            })
    except Exception:
        pass

    # Validate module existence via Metasploit RPC
    clean_mod = module_path.replace("auxiliary/", "", 1)
    try:
        info = msf_client.call("module.info", "auxiliary", clean_mod)
        if isinstance(info, dict) and ("error" in info or "error_message" in info or info.get("error") is True):
            # Module does not exist: find matching auxiliary modules to suggest
            aux_res = msf_client.call("module.auxiliary")
            all_aux = [f"auxiliary/{m}" for m in aux_res.get("modules", [])] if isinstance(aux_res, dict) else []
            query_terms = [t.lower() for t in clean_mod.split("/") if t and t.lower() not in {"scanner", "auxiliary"}]
            matches = []
            for m in all_aux:
                score = sum(1 for t in query_terms if t in m.lower())
                if score > 0:
                    matches.append((score, m))
            matches.sort(key=lambda x: (-x[0], len(x[1])))
            top_suggestions = [m for _, m in matches[:10]]
            return json.dumps({
                "status": "error",
                "message": f"Auxiliary module '{module_path}' does not exist in Metasploit.",
                "suggested_scanners": top_suggestions
            })
    except Exception:
        pass

    try:
        rport_str = str(rport)

        # Snapshot loot directory before running module
        pre_loot_files = set()
        try:
            loot_list_proc = subprocess.run(
                ["docker", "exec", "msf-rpc", "ls", "-1", "/root/.msf4/loot"],
                capture_output=True, text=True, timeout=5
            )
            if loot_list_proc.returncode == 0:
                pre_loot_files = set(f.strip() for f in loot_list_proc.stdout.splitlines() if f.strip())
        except Exception:
            pass

        # Create a dedicated MSF console to capture real scanner output.
        console_res = msf_client.call("console.create")
        if not isinstance(console_res, dict) or "id" not in console_res:
            return json.dumps({"status": "error", "message": "Failed to create Metasploit console."})
        cid = str(console_res["id"])

        try:
            # Build and send the module commands
            lines = [
                f"use {module_path}",
                f"set RHOSTS {rhosts}",
            ]
            if "portscan" in module_path:
                lines.append(f"set PORTS {rport_str}")
                # Optimize performance for pivot port scans:
                # - CONCURRENCY: concurrent ports per host (default is 10, boost to 50)
                # - TIMEOUT: socket connect timeout in ms (default is 1000ms, reduce to 300ms)
                lines.append("set CONCURRENCY 50")
                lines.append("set TIMEOUT 300")
            else:
                lines.append(f"set PORTS {rport_str}")
                lines.append(f"set RPORT {rport_str}")
                lines.append(f"set SRVHOST {ATTACKER_LHOST}")

            lines.append("set THREADS 5")
            if extra_options and isinstance(extra_options, dict):
                for opt_k, opt_v in extra_options.items():
                    lines.append(f"set {opt_k} {opt_v}")
            lines.append("run")
            cmd = "\n".join(lines) + "\n"
            msf_client.call("console.write", cid, cmd)

            # Poll console.read until not busy (module completed) or timeout
            # Large port ranges need more time; single port / small probes finish quickly
            is_large_portscan = "portscan" in module_path and ("-" in rport_str or len(rport_str.split(",")) > 20)
            timeout = 240 if is_large_portscan else 120
            start_time = time.time()
            full_output = ""
            idle_cycles = 0
            timed_out = False
            while True:
                time.sleep(1)
                res = msf_client.call("console.read", cid)
                if not isinstance(res, dict):
                    break
                chunk = res.get("data", "")
                if isinstance(chunk, str) and chunk:
                    full_output += chunk
                    idle_cycles = 0
                else:
                    idle_cycles += 1

                busy = res.get("busy", False)
                # Stop when console is no longer busy and either completion marker seen or output has settled
                if not busy and (
                    "Auxiliary module execution completed" in full_output
                    or "Scanned" in full_output
                    or idle_cycles >= 2
                ):
                    break
                # Hard timeout guard
                if time.time() - start_time > timeout:
                    timed_out = True
                    break

        finally:
            # Always destroy the console to avoid resource leaks
            try:
                msf_client.call("console.destroy", cid)
            except Exception:
                pass

        # Parse open ports from TCP scanner output lines
        open_ports = []
        for match in re.finditer(
            r'\[\+\]\s+(?:[^\s\-]+\s+-\s+)?([\d\.]+):(\d+)\s+-\s+TCP OPEN',
            full_output
        ):
            open_ports.append({"host": match.group(1), "port": int(match.group(2)), "state": "open"})

        # Collect positive findings from output
        positive_findings = re.findall(r'\[\+\] (.+)', full_output)

        # Retrieve and decode any newly saved loot files (e.g. from traversal / file read exploits)
        captured_loot = []
        try:
            loot_post_proc = subprocess.run(
                ["docker", "exec", "msf-rpc", "ls", "-1", "/root/.msf4/loot"],
                capture_output=True, text=True, timeout=5
            )
            if loot_post_proc.returncode == 0:
                post_files = set(f.strip() for f in loot_post_proc.stdout.splitlines() if f.strip())
                new_loot_files = [f for f in post_files if f not in pre_loot_files]
                for l_name in sorted(new_loot_files):
                    cat_proc = subprocess.run(
                        ["docker", "exec", "msf-rpc", "cat", f"/root/.msf4/loot/{l_name}"],
                        capture_output=True, text=True, timeout=5
                    )
                    content = cat_proc.stdout.strip()
                    captured_loot.append({"file": l_name, "content": content})
                    full_output += f"\n[+] Loot saved to /root/.msf4/loot/{l_name}:\n{content}\n"
                    positive_findings.append(f"Loot captured ({l_name}): {content}")
        except Exception:
            pass

        if timed_out:
            info = (
                f"Scan TIMED OUT after {timeout}s before completing full port range/checks. "
                f"Partial results: {[p['port'] for p in open_ports]}. "
                "WARNING: The scan was aborted due to timeout! Unscanned ports may still be open; do NOT conclude that the host has no open ports."
            )
        else:
            info = f"Scan completed via Metasploit using module {module_path}."

        return json.dumps({
            "status": "success",
            "timed_out": timed_out,
            "info": info,
            "console_output": full_output.strip(),
            "open_ports": open_ports,
            "findings": positive_findings,
            "loot": captured_loot,
        })
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})


def nmap_scan(target: str, ports: str = "1-1024", arguments: str = "-sV --open") -> str:
    """
    Native reconnaissance tool for the SCOUT agent.
    Runs an Nmap scan via Docker (instrumentisto/nmap) and returns
    structured JSON results containing host status, open ports, services, versions, and OS guesses.

    Args:
        target: Target IP or hostname (e.g., "192.168.1.10").
        ports: Port range to scan (e.g., "22,80,443" or "1-65535").
        arguments: Additional Nmap flags (default: service version detection).
                   Note: -O (OS detection) requires --privileged in the container.
    """
    try:
        # Pass --unprivileged, -sT, -Pn and --open to ensure reliable TCP connect scans
        # across Docker bridges and under ARM64/x86 container emulation without pcap_create errors
        extra_args = []
        for arg in arguments.split():
            if arg not in extra_args:
                extra_args.append(arg)

        # Ensure --unprivileged and -sT are present for socket-level scanning
        if "--unprivileged" not in extra_args:
            extra_args.append("--unprivileged")
        if "-sT" not in extra_args and "-sS" not in extra_args and "-sU" not in extra_args:
            extra_args.append("-sT")
        if "-Pn" not in extra_args:
            extra_args.append("-Pn")

        cmd = [
            "docker", "run", "--rm", "--network", "host",
            "instrumentisto/nmap",
            "-p", ports, "--open", "-oX", "-"
        ] + extra_args + [target]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=180  # Docker startup + scan window
        )

        if result.returncode != 0:
            return json.dumps({"status": "error", "message": result.stderr.strip()})

        # Parse Nmap XML output
        root = ET.fromstring(result.stdout)
        hosts_data = []

        for host in root.findall("host"):
            addr_el = host.find("address[@addrtype='ipv4']")
            if addr_el is None:
                continue
            ip = addr_el.get("addr")

            open_ports = []
            ports_el = host.find("ports")
            if ports_el is not None:
                for port_el in ports_el.findall("port"):
                    state_el = port_el.find("state")
                    if state_el is None or state_el.get("state") != "open":
                        continue
                    svc_el = port_el.find("service")
                    open_ports.append({
                        "port": int(port_el.get("portid")),
                        "protocol": port_el.get("protocol"),
                        "service": svc_el.get("name") if svc_el is not None else "unknown",
                        "product": svc_el.get("product", "") if svc_el is not None else "",
                        "version": svc_el.get("version", "") if svc_el is not None else "",
                        "extra_info": svc_el.get("extrainfo", "") if svc_el is not None else ""
                    })

            # OS detection guesses
            os_guesses = []
            os_el = host.find("os")
            if os_el is not None:
                for osmatch in os_el.findall("osmatch"):
                    os_guesses.append({
                        "name": osmatch.get("name"),
                        "accuracy": osmatch.get("accuracy")
                    })

            hosts_data.append({
                "ip": ip,
                "open_ports": open_ports,
                "os_guesses": os_guesses
            })

        return json.dumps({"status": "success", "hosts": hosts_data})

    except subprocess.TimeoutExpired:
        return json.dumps({"status": "error", "message": "Nmap timeout: scan halted after 180 seconds."})
    except ET.ParseError as e:
        return json.dumps({"status": "error", "message": f"Nmap XML parse error: {str(e)}"})
    except FileNotFoundError:
        return json.dumps({"status": "error", "message": "docker binary not found in PATH."})
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})


def curl_request(
    url: str,
    method: str = "GET",
    headers: dict = None,
    data: str = "",
    follow_redirects: bool = True,
    timeout: int = 15,
    insecure: bool = False
) -> str:
    """
    Reconnaissance tool for the SCOUT agent.
    Performs an HTTP/HTTPS request via curl to a target URL and returns
    status code, response headers, and body preview (truncated to 4096 characters).

    Args:
        url: Full target URL (e.g., "http://192.168.1.10:8080/").
        method: HTTP method to use (GET, POST, HEAD, PUT, DELETE, OPTIONS).
        headers: Dict of additional headers to send (e.g., {"User-Agent": "Mozilla/5.0"}).
        data: Request body payload (used in POST/PUT). Raw string or JSON.
        follow_redirects: If True, automatically follows HTTP redirect headers (-L flag).
        timeout: Connection and transfer timeout in seconds.
        insecure: If True, disables TLS certificate verification (-k flag).
    """
    try:
        cmd = ["curl", "-s", "-i",  # -s silent, -i include headers
               "-X", method.upper(),
               "--max-time", str(timeout),
               "--connect-timeout", str(min(timeout, 10))]

        if follow_redirects:
            cmd.append("-L")

        if insecure:
            cmd.append("-k")

        if headers:
            for k, v in headers.items():
                cmd += ["-H", f"{k}: {v}"]

        if data:
            cmd += ["--data", data]

        cmd.append(url)

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 5
        )

        if result.returncode != 0 and not result.stdout.strip():
            return json.dumps({
                "status": "error",
                "message": f"curl failed (code {result.returncode}): {result.stderr.strip() or 'Connection failed or refused'}"
            })

        raw_output = result.stdout

        # Separate headers and body from raw response
        if "\r\n\r\n" in raw_output:
            header_section, body = raw_output.split("\r\n\r\n", 1)
        elif "\n\n" in raw_output:
            header_section, body = raw_output.split("\n\n", 1)
        else:
            header_section, body = raw_output, ""

        # Extract status code from the first header line
        header_lines = header_section.strip().splitlines()
        status_line = header_lines[0] if header_lines else ""
        response_headers = {}
        for line in header_lines[1:]:
            if ":" in line:
                k, _, v = line.partition(":")
                response_headers[k.strip()] = v.strip()

        # Truncate response body preview
        MAX_BODY = 4096
        truncated = len(body) > MAX_BODY
        body_preview = body[:MAX_BODY]

        return json.dumps({
            "status": "success",
            "url": url,
            "method": method.upper(),
            "status_line": status_line,
            "response_headers": response_headers,
            "body_preview": body_preview,
            "body_truncated": truncated,
            "stderr": result.stderr.strip() or None
        })

    except subprocess.TimeoutExpired:
        return json.dumps({"status": "error", "message": f"curl timed out after {timeout} seconds on {url}."})
    except FileNotFoundError:
        return json.dumps({"status": "error", "message": "curl binary not found in PATH."})
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})


def msf_search_modules(keyword: str) -> str:
    """
    Searches Metasploit modules (exploits and auxiliaries) matching a keyword, phrase, CVE, or description.
    ALWAYS call this tool prior to running an exploit or auxiliary scanner to verify the exact module path.
    """
    if not keyword or len(keyword.strip()) < 2:
        return json.dumps({"status": "error", "message": "Please provide a keyword of at least 2 characters to search."})

    import re
    cleaned_keyword = keyword.strip()
    
    # 1. Advanced Query Processing: Extract CVEs and filter stop words
    cves = re.findall(r'cve-\d{4}-\d{4,5}', cleaned_keyword.lower())
    clean_kw = re.sub(r'[()\[\]{},.;:/\\_-]', ' ', cleaned_keyword.lower())
    words = clean_kw.split()
    stopwords = {
        "or", "and", "the", "in", "for", "with", "on", "to", "a", "an", "by", "of", "is", "at",
        "vulnerability", "vulnerabilities", "exploit", "exploits", "rce", "remote", "code",
        "execution", "scanner", "check", "bypass", "attack"
    }
    filtered_words = [w for w in words if w not in stopwords and len(w) >= 2]

    # 2. Try Metasploit's native module.search (matches CVEs, descriptions, titles, etc.)
    results = []
    try:
        # If CVEs are extracted, search them first
        if cves:
            for cve in cves:
                search_res = msf_client.call("module.search", cve)
                if isinstance(search_res, list) and len(search_res) > 0:
                    results.extend([r.get("fullname") for r in search_res if r.get("fullname")])
        
        # Search with filtered keywords phrase
        if not results and filtered_words:
            kw_phrase = " ".join(filtered_words)
            search_res = msf_client.call("module.search", kw_phrase)
            if isinstance(search_res, list) and len(search_res) > 0:
                results.extend([r.get("fullname") for r in search_res if r.get("fullname")])

        # Broad fallback: if query was multi-word (e.g. "struts2 showcase") and yielded few results (<3),
        # also search using just the primary technology term (first filtered word)
        if len(filtered_words) > 1 and len(results) < 3:
            primary_term = filtered_words[0]
            broad_res = msf_client.call("module.search", primary_term)
            if isinstance(broad_res, list) and len(broad_res) > 0:
                results.extend([r.get("fullname") for r in broad_res if r.get("fullname")])

        if results:
            # Deduplicate preserving order
            seen = set()
            dedup_results = [r for r in results if not (r in seen or seen.add(r))]
            # Prioritize exploit modules over auxiliary/post modules
            dedup_results.sort(key=lambda m: (0 if m.startswith("exploit/") else 1))
            return json.dumps({
                "status": "success",
                "keyword": keyword,
                "count": len(dedup_results),
                "results": dedup_results[:20]
            })
    except Exception:
        pass  # Fall back to local search if RPC search fails

    # 3. Local fallback (matching keywords against module paths)
    try:
        exploits_res = msf_client.call("module.exploits")
        auxiliary_res = msf_client.call("module.auxiliary")

        if isinstance(exploits_res, dict) and "error" in exploits_res:
            err = exploits_res.get("error_message") or exploits_res.get("error")
            return json.dumps({"status": "error", "message": f"Metasploit RPC error listing exploits: {err}"})
        if isinstance(auxiliary_res, dict) and "error" in auxiliary_res:
            err = auxiliary_res.get("error_message") or auxiliary_res.get("error")
            return json.dumps({"status": "error", "message": f"Metasploit RPC error listing auxiliaries: {err}"})

        exploits = exploits_res.get("modules", []) if isinstance(exploits_res, dict) else []
        auxiliary = auxiliary_res.get("modules", []) if isinstance(auxiliary_res, dict) else []

        all_modules = [f"exploit/{m}" for m in exploits] + [f"auxiliary/{m}" for m in auxiliary]

        if not filtered_words:
            return json.dumps({"status": "error", "message": "Please provide a valid search query."})

        matches = []
        for m in all_modules:
            # Check if all filtered keywords are present in the module path
            if all(w in m.lower() for w in filtered_words):
                matches.append(m)

        primary_kw = filtered_words[0] if filtered_words else ""
        matches.sort(key=lambda m: (0 if m.startswith("exploit/") else 1, primary_kw != m.split("/")[-1].lower(), len(m)))

        return json.dumps({
            "status": "success",
            "keyword": keyword,
            "count": len(matches),
            "results": matches[:20]
        })
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})


def get_network_interfaces() -> str:
    """
    Reconnaissance tool for the SCOUT agent.
    Returns the full map of local network interfaces and their IPv4 addresses.
    Use this to understand the attacker machine's network topology (bridges, VPNs,
    Docker networks, etc.) and select the correct interface for a given engagement.

    NOTE: This tool is intentionally scoped to Scout only. It must NOT be used
    for LHOST selection during exploit configuration — use get_lhost_for_target() instead.
    """
    import socket
    try:
        # Best-effort outbound IP via routing table
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            active_ip = s.getsockname()[0]
        except Exception:
            active_ip = "Unknown (no route to internet)"
        finally:
            s.close()

        interfaces = {}
        try:
            res = subprocess.run(["ip", "-j", "addr"], capture_output=True, text=True, timeout=5)
            if res.returncode == 0:
                addr_data = json.loads(res.stdout)
                for iface in addr_data:
                    ifname = iface.get("ifname", "")
                    ips = []
                    for addr_info in iface.get("addr_info", []):
                        if addr_info.get("family") == "inet":
                            ips.append(addr_info.get("local"))
                    if ips:
                        interfaces[ifname] = ips
            else:
                res_fallback = subprocess.run(["ip", "addr"], capture_output=True, text=True, timeout=5)
                interfaces["raw"] = res_fallback.stdout
        except Exception as e:
            interfaces["error"] = f"Could not list interfaces: {str(e)}"

        return json.dumps({
            "status": "success",
            "active_outbound_ip": active_ip,
            "local_interfaces": interfaces
        })
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})



