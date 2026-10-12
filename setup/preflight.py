#!/usr/bin/env python3
"""
preflight.py — Verifies that all framework components are operational
by executing the EXACT same functions and libraries used in production.

If all tests pass, you can safely run `uv run main.py`.

Usage:
  uv run preflight.py [target] [http_url]
  Examples:
    uv run preflight.py                              # default: 127.0.0.1, http://127.0.0.1:80/
    uv run preflight.py 192.168.1.10 http://192.168.1.10:8080/
"""

import sys
import json
import os

# Ensure the project root is always in sys.path, regardless of how this
# module is invoked (imported by setup.py or run standalone as setup/preflight.py)
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

# ── ANSI Colors ──────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def ok(msg):     print(f"  {GREEN}✔{RESET} {msg}")
def fail(msg):   print(f"  {RED}✘{RESET} {msg}")
def warn(msg):   print(f"  {YELLOW}⚠{RESET} {msg}")
def section(t):  print(f"\n{BOLD}{CYAN}[{t}]{RESET}")

# ── CLI Arguments ────────────────────────────────────────────────────────────
TARGET   = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
HTTP_URL = sys.argv[2] if len(sys.argv) > 2 else f"http://{TARGET}:80/"

results: dict[str, bool] = {}


# ════════════════════════════════════════════════════════════════════════════
# TEST 1 — NMAP  (calls tools.nmap_scan — real project function)
# ════════════════════════════════════════════════════════════════════════════
def test_nmap(target: str) -> bool:
    section("TEST 1 — NMAP  [tools.nmap_scan()]")
    print(f"  Target: {target}  Ports: 22,80,443,8080")

    # ← same function used by Scout in production
    from core.tools import nmap_scan

    raw = nmap_scan(target=target, ports="22,80,443,8080", arguments="-sT -sV")
    data = json.loads(raw)

    if data["status"] == "error":
        fail(f"nmap_scan() returned error: {data['message']}")
        return False

    hosts = data.get("hosts", [])
    ok(f"nmap_scan() completed — found {len(hosts)} host(s)")
    for h in hosts:
        print(f"    Host: {h['ip']}")
        for p in h["open_ports"]:
            line = f"      {p['port']}/{p['protocol']}  {p['service']}"
            if p.get("product") or p.get("version"):
                ver = f"{p.get('product','')} {p.get('version','')}".strip()
                line += f"  ({ver})"
            print(line)
        if h.get("os_guesses"):
            for g in h["os_guesses"][:1]:
                print(f"      OS guess: {g['name']} ({g['accuracy']}%)")
    if not hosts:
        warn("No hosts responded — the tool works but the target is unreachable")
    return True


# ════════════════════════════════════════════════════════════════════════════
# TEST 2 — CURL  (calls tools.curl_request — real project function)
# ════════════════════════════════════════════════════════════════════════════
def test_curl(url: str) -> bool:
    section("TEST 2 — CURL  [tools.curl_request()]")

    # ← same function used by Scout in production
    from core.tools import curl_request

    # Try target URL first, then httpbin as a connectivity fallback
    test_cases = [
        {"url": url,                    "label": f"target ({url})"},
        {"url": "http://httpbin.org/get", "label": "httpbin.org (internet fallback)"},
    ]

    any_ok = False
    for tc in test_cases:
        print(f"  → {tc['label']}")
        raw = curl_request(url=tc["url"], method="GET", timeout=10, insecure=True)
        data = json.loads(raw)

        if data["status"] == "error":
            warn(f"curl_request() error: {data['message']}")
            continue

        status_line = data.get("status_line", "(no response)")
        ok(f"Response: {status_line}")
        hdrs = data.get("response_headers", {})
        for k in ("Server", "Content-Type", "X-Powered-By", "Location"):
            if k in hdrs:
                print(f"      {k}: {hdrs[k]}")
        if data.get("body_preview"):
            preview = data["body_preview"][:120].replace("\n", " ").strip()
            print(f"      Body preview: {preview}{'…' if data.get('body_truncated') else ''}")
        any_ok = True

    if not any_ok:
        fail("curl_request() failed to reach any endpoint — check curl binary in PATH")
    return any_ok


# ════════════════════════════════════════════════════════════════════════════
# TEST 3 — METASPLOIT RPC  (calls rpc_client.msf_client — real client)
# ════════════════════════════════════════════════════════════════════════════
def test_msf() -> bool:
    section("TEST 3 — METASPLOIT RPC  [rpc_client.msf_client]")

    # ← same object imported by tools.py in production
    from core.rpc_client import msf_client

    if not msf_client.is_connected:
        fail("msf_client not authenticated — token not acquired")
        warn("Start msfrpcd: msfrpcd -a 127.0.0.1 -p 55553 -U msf -P <pass>")
        return False

    ok(f"Authenticated — token: {msf_client.token[:10]}...")

    # Test real RPC call (same API used by msf_execute_scanner)
    res = msf_client.call("module.exploits")
    if isinstance(res, dict) and "error" in res:
        fail(f"RPC call failed: {res['error']}")
        return False

    count = len(res.get("modules", [])) if isinstance(res, dict) else 0
    ok(f"module.exploits OK — {count} exploit modules")

    # Test session list (same API used by msf_trigger_exploit)
    sessions_res = msf_client.call("session.list")
    if isinstance(sessions_res, dict) and "error" in sessions_res:
        warn(f"session.list returned error: {sessions_res['error']}")
    else:
        n_sessions = len(sessions_res) if isinstance(sessions_res, dict) else 0
        ok(f"session.list OK — {n_sessions} active sessions")

    return True


# ════════════════════════════════════════════════════════════════════════════
# TEST 4 — LLM  (uses agno.OpenAIChat — same class used in agents.py)
# ════════════════════════════════════════════════════════════════════════════
def test_llm() -> bool:
    section("TEST 4 — LLM  [agno.OpenAIChat → DeepSeek]")

    # ← same class and configuration as agents.py
    from agno.agent import Agent
    from agno.models.openai import OpenAIChat
    from config import LLM_ID, LLM_BASE_URL, LLM_API_KEY, LLM_MAX_TOKENS

    try:
        llm = OpenAIChat(
            id=LLM_ID,
            base_url=LLM_BASE_URL,
            api_key=LLM_API_KEY,
            max_tokens=LLM_MAX_TOKENS,
        )

        agent = Agent(
            model=llm,
            instructions=["You are a test agent. Always reply only with: PONG"],
            markdown=False,
        )

        # run_response returns a RunResponse object; .content holds the text
        response = agent.run("PING")
        content = (response.content or "").strip()

        # agno swallows connection errors and returns them as content strings
        # instead of raising exceptions — detect this case explicitly
        ERROR_PATTERNS = [
            "connection error",
            "connection refused",
            "failed to connect",
            "error communicating",
            "api connection error",
            "could not connect",
            "network error",
        ]
        lower_content = content.lower()
        if any(pat in lower_content for pat in ERROR_PATTERNS):
            fail(f"agno returned a connection error as response content: {content!r}")
            warn(f"Ensure the LLM server is running on {LLM_BASE_URL}")
            return False

        if not content:
            fail("agno returned an empty response — LLM may be unreachable")
            warn(f"Ensure the LLM server is running on {LLM_BASE_URL}")
            return False

        ok(f"agno → {LLM_ID} responds correctly")
        ok(f"Response: {content!r}")

        return True

    except Exception as e:
        fail(f"agno/OpenAIChat error: {e}")
        warn(f"Ensure the LLM server is running on {LLM_BASE_URL}")
        return False


# ════════════════════════════════════════════════════════════════════════════
# TEST 5 — ATTACKER IP  (calls tools.get_attacker_ip — real project function)
# ════════════════════════════════════════════════════════════════════════════
def test_attacker_ip() -> bool:
    section("TEST 5 — NETWORK INTERFACES  [tools.get_network_interfaces()]")
    
    from core.tools import get_network_interfaces
    
    try:
        raw = get_network_interfaces()
        data = json.loads(raw)
        
        if data["status"] == "error":
            fail(f"get_network_interfaces() returned error: {data['message']}")
            return False
            
        active_ip = data.get("active_outbound_ip")
        local_ifaces = data.get("local_interfaces", {})
        
        ok("get_network_interfaces() completed successfully")
        print(f"    Active Outbound  : {active_ip}")
        print("    Local Interfaces :")
        for iface, ips in local_ifaces.items():
            if isinstance(ips, list):
                print(f"      - {iface}: {', '.join(ips)}")
            else:
                print(f"      - {iface}: {ips}")

        from core.tools import get_lhost_for_target
        raw2 = get_lhost_for_target("8.8.8.8")
        data2 = json.loads(raw2)
        if data2["status"] == "success":
            ok(f"get_lhost_for_target() → lhost={data2['lhost']} (source: {data2['source']})")
        else:
            warn(f"get_lhost_for_target() returned error: {data2.get('message')}")
            
        return True
    except Exception as e:
        fail(f"Network interface check error: {e}")
        return False


# ════════════════════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    print(f"\n{BOLD}{'═'*60}")
    print(f"  PREFLIGHT CHECK — v1 Framework")
    print(f"  Target: {TARGET}   HTTP URL: {HTTP_URL}")
    print(f"  (using production modules and configurations)")
    print(f"{'═'*60}{RESET}")

    results["nmap"] = test_nmap(TARGET)
    results["curl"] = test_curl(HTTP_URL)
    results["msf"]  = test_msf()
    results["llm"]  = test_llm()
    results["ip"]   = test_attacker_ip()

    section("SUMMARY")
    all_passed = True
    for name, passed in results.items():
        status = f"{GREEN}PASS{RESET}" if passed else f"{RED}FAIL{RESET}"
        print(f"  {BOLD}{name:<8}{RESET}  {status}")
        if not passed:
            all_passed = False

    print()
    if all_passed:
        print(f"{GREEN}{BOLD}✔ All tests passed — you can safely run: uv run main.py{RESET}\n")
        sys.exit(0)
    else:
        failed = [k for k, v in results.items() if not v]
        print(f"{RED}{BOLD}✘ Tests failed: {', '.join(failed)}{RESET}")
        print(f"{YELLOW}  Fix the issues highlighted above before running main.py{RESET}\n")
        sys.exit(1)
