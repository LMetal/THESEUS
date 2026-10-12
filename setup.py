#!/usr/bin/env python3
"""
setup.py — Interactive first-run configuration wizard for the v1 Framework.

Guides the user through LLM, Metasploit, and network configuration,
validates each component via the real preflight checks, then writes
config.py only if all tests pass.

Usage:
  uv run setup.py
"""

import sys
import json
import subprocess
import re
import requests

# ── ANSI Colors (same palette as preflight.py) ───────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

def ok(msg):      print(f"  {GREEN}✔{RESET} {msg}")
def fail(msg):    print(f"  {RED}✘{RESET} {msg}")
def warn(msg):    print(f"  {YELLOW}⚠{RESET} {msg}")
def info(msg):    print(f"  {CYAN}→{RESET} {msg}")
def section(t):   print(f"\n{BOLD}{CYAN}[{t}]{RESET}")
def banner(t):    print(f"\n{BOLD}{t}{RESET}")

def prompt(label: str, default: str = "", secret: bool = False) -> str:
    """Prompt the user for input, showing default in brackets."""
    if secret:
        display_default = "*" * len(default) if default else "none"
    else:
        display_default = default or "none"

    suffix = f" {DIM}[{display_default}]{RESET}: " if default else ": "
    try:
        val = input(f"  {BOLD}{label}{RESET}{suffix}").strip()
    except (KeyboardInterrupt, EOFError):
        print(f"\n\n{YELLOW}Setup interrupted.{RESET}")
        sys.exit(0)
    return val if val else default

def numbered_choice(items: list[str], label: str = "Choice") -> str:
    """Present a numbered list and return the chosen item."""
    for i, item in enumerate(items, 1):
        print(f"    {DIM}{i}.{RESET} {item}")
    while True:
        raw = prompt(label, default="1")
        if raw.isdigit() and 1 <= int(raw) <= len(items):
            return items[int(raw) - 1]
        print(f"  {RED}Invalid choice. Enter a number between 1 and {len(items)}.{RESET}")


# ════════════════════════════════════════════════════════════════════════════
# STEP 1 — LLM
# ════════════════════════════════════════════════════════════════════════════
def setup_llm() -> dict:
    section("STEP 1 — LLM Configuration")

    base_url = prompt("LLM base URL", default="http://127.0.0.1:8000/v1")
    # Normalise trailing slash
    base_url = base_url.rstrip("/")

    # Try to fetch available models from the OpenAI-compatible endpoint
    model_id = None
    info(f"Querying {base_url}/models …")
    try:
        resp = requests.get(f"{base_url}/models", timeout=5)
        resp.raise_for_status()
        data = resp.json()
        models = [m["id"] for m in data.get("data", []) if "id" in m]

        if models:
            ok(f"Found {len(models)} model(s):")
            model_id = numbered_choice(models, label="Select model number")
            ok(f"Selected: {model_id}")
        else:
            warn("Endpoint responded but returned no models.")
    except requests.exceptions.ConnectionError:
        warn(f"Could not reach {base_url}/models — server may not be running yet.")
    except Exception as e:
        warn(f"Model discovery failed: {e}")

    if not model_id:
        info("Enter the model ID manually.")
        model_id = prompt("Model ID", default="deepseek-v4-flash")

    api_key = prompt("API key", default="dsv4-local")
    max_tokens_raw = prompt("Max tokens per call", default="4096")
    try:
        max_tokens = int(max_tokens_raw)
    except ValueError:
        warn("Invalid value, defaulting to 4096.")
        max_tokens = 4096

    return {
        "LLM_BASE_URL": base_url,
        "LLM_ID": model_id,
        "LLM_API_KEY": api_key,
        "LLM_MAX_TOKENS": max_tokens,
    }


# ════════════════════════════════════════════════════════════════════════════
# STEP 2 — Metasploit RPC
# ════════════════════════════════════════════════════════════════════════════
def setup_msf() -> dict:
    section("STEP 2 — Metasploit RPC Configuration")

    msf_host = prompt("msfrpcd host", default="127.0.0.1")
    msf_port_raw = prompt("msfrpcd port", default="55553")
    try:
        msf_port = int(msf_port_raw)
    except ValueError:
        warn("Invalid port, defaulting to 55553.")
        msf_port = 55553
    msf_user = prompt("RPC username", default="msf")
    msf_pass = prompt("RPC password", secret=True)

    # Live RPC test — instantiate MetasploitRPCClient directly with user values
    # (same class and protocol used in production: HTTPS + requests + msgpack)
    info("Testing Metasploit RPC connection …")
    try:
        import msgpack
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        url = f"https://{msf_host}:{msf_port}/api/"
        payload = msgpack.packb(["auth.login", msf_user, msf_pass])
        headers = {"Content-Type": "binary/message-pack"}

        resp = requests.post(url, data=payload, headers=headers, verify=False, timeout=10)

        if resp.status_code != 200:
            fail(f"msfrpcd returned HTTP {resp.status_code}")
            return None

        result = msgpack.unpackb(resp.content, raw=False, strict_map_key=False)
        # Normalize byte keys (older msfrpcd versions)
        result = {
            (k.decode() if isinstance(k, bytes) else k):
            (v.decode() if isinstance(v, bytes) else v)
            for k, v in result.items()
        }

        if result.get("result") == "success":
            token = result.get("token", "")
            ok(f"Authenticated — token: {token[:10]}…")
        else:
            fail(f"Authentication failed: {result}")
            info("Check username and password.")
            return None

    except requests.exceptions.ConnectionError:
        fail(f"Connection refused on {msf_host}:{msf_port}")
        info("Start msfrpcd:  msfrpcd -a 127.0.0.1 -p 55553 -U msf -P <password>")
        return None
    except Exception as e:
        fail(f"MSF RPC error: {e}")
        return None

    return {
        "MSF_HOST": msf_host,
        "MSF_PORT": msf_port,
        "MSF_USER": msf_user,
        "MSF_PASS": msf_pass,
    }


# ════════════════════════════════════════════════════════════════════════════
# STEP 3 — Network / LHOST
# ════════════════════════════════════════════════════════════════════════════
def setup_network() -> dict:
    section("STEP 3 — Attacker Network Configuration")

    # Show live interfaces using the real tool function
    info("Detecting local network interfaces …")
    try:
        from core.tools import get_network_interfaces
        raw = get_network_interfaces()
        data = json.loads(raw)

        if data["status"] == "success":
            active_ip = data.get("active_outbound_ip", "unknown")
            ifaces = data.get("local_interfaces", {})

            info(f"Active outbound IP: {BOLD}{active_ip}{RESET}")
            print(f"  Available interfaces:")
            iface_ips = []
            for name, ips in ifaces.items():
                if isinstance(ips, list):
                    for ip in ips:
                        print(f"    {DIM}{name}{RESET}  →  {ip}")
                        iface_ips.append(ip)

            # Pre-select the active outbound IP as the sensible default
            default_lhost = active_ip if active_ip != "unknown" else "10.0.0.5"
        else:
            warn(f"Interface detection failed: {data.get('message')}")
            default_lhost = "10.0.0.5"
    except Exception as e:
        warn(f"Could not detect interfaces: {e}")
        default_lhost = "10.0.0.5"

    lhost = prompt("ATTACKER_LHOST (reverse-shell callback IP)", default=default_lhost)
    lport = prompt("ATTACKER_LPORT (reverse-shell listener port)", default="4444")

    return {
        "ATTACKER_LHOST": lhost,
        "ATTACKER_LPORT": lport,
    }


# ════════════════════════════════════════════════════════════════════════════
# STEP 4 — Preflight
# ════════════════════════════════════════════════════════════════════════════
def run_preflight(cfg: dict) -> bool:
    """
    Run all preflight checks in-process, injecting the collected configuration
    directly into sys.modules so the test functions see the user's values —
    no subprocess, no file swapping, no PATH issues.
    """
    section("STEP 4 — Preflight Check")

    import types

    # Build a fake 'config' module with the user-supplied values and
    # inject it before any preflight import resolves it.
    fake_config = types.ModuleType("config")
    fake_config.LLM_ID         = cfg["LLM_ID"]
    fake_config.LLM_BASE_URL   = cfg["LLM_BASE_URL"]
    fake_config.LLM_API_KEY    = cfg["LLM_API_KEY"]
    fake_config.LLM_MAX_TOKENS = cfg["LLM_MAX_TOKENS"]
    fake_config.MSF_HOST       = cfg["MSF_HOST"]
    fake_config.MSF_PORT       = cfg["MSF_PORT"]
    fake_config.MSF_USER       = cfg["MSF_USER"]
    fake_config.MSF_PASS       = cfg["MSF_PASS"]
    fake_config.ATTACKER_LHOST = cfg["ATTACKER_LHOST"]
    fake_config.ATTACKER_LPORT = cfg["ATTACKER_LPORT"]

    # Save and replace any already-loaded modules that depend on config
    _saved = {}
    for mod_name in ["config", "rpc_client", "tools"]:
        _saved[mod_name] = sys.modules.pop(mod_name, None)

    sys.modules["config"] = fake_config

    try:
        # Import test functions from preflight using the patched config
        from setup.preflight import test_nmap, test_curl, test_msf, test_llm, test_attacker_ip

        results = {
            "nmap": test_nmap("127.0.0.1"),
            "curl": test_curl(f"http://127.0.0.1:80/"),
            "msf":  test_msf(),
            "llm":  test_llm(),
            "ip":   test_attacker_ip(),
        }

        section("SUMMARY")
        all_passed = True
        for name, passed in results.items():
            status = f"{GREEN}PASS{RESET}" if passed else f"{RED}FAIL{RESET}"
            print(f"  {BOLD}{name:<8}{RESET}  {status}")
            if not passed:
                all_passed = False

        return all_passed

    finally:
        # Restore original modules so the rest of setup.py is unaffected
        for mod_name, mod in _saved.items():
            if mod is not None:
                sys.modules[mod_name] = mod
            else:
                sys.modules.pop(mod_name, None)


# ════════════════════════════════════════════════════════════════════════════
# CONFIG WRITER
# ════════════════════════════════════════════════════════════════════════════
def _write_config(cfg: dict, path: str = "config.py"):
    """
    Render config.py from config.template.py, substituting placeholder
    values with the collected configuration. The template is never touched.
    """
    template_path = "setup/config.template.py"
    try:
        with open(template_path, "r") as f:
            template = f.read()
    except FileNotFoundError:
        # Fallback: generate from scratch if template is missing
        template = None

    lhost = cfg["ATTACKER_LHOST"]
    lport = cfg["ATTACKER_LPORT"]
    msf_host = cfg["MSF_HOST"]
    msf_port = cfg["MSF_PORT"]
    msf_user = cfg["MSF_USER"]
    msf_pass = cfg["MSF_PASS"]
    llm_id = cfg["LLM_ID"]
    llm_url = cfg["LLM_BASE_URL"]
    llm_key = cfg["LLM_API_KEY"]
    llm_tok = cfg["LLM_MAX_TOKENS"]

    if template:
        # Replace placeholder values using regex so we're not brittle to whitespace
        def sub(pattern, value, text):
            return re.sub(pattern, value, text, count=1)

        out = template
        out = sub(r'LLM_ID\s*=\s*"[^"]*"',         f'LLM_ID = "{llm_id}"',   out)
        out = sub(r'LLM_BASE_URL\s*=\s*"[^"]*"',   f'LLM_BASE_URL = "{llm_url}"', out)
        out = sub(r'LLM_API_KEY\s*=\s*"[^"]*"',    f'LLM_API_KEY = "{llm_key}"',  out)
        out = sub(r'LLM_MAX_TOKENS\s*=\s*\d+',     f'LLM_MAX_TOKENS = {llm_tok}', out)
        out = sub(r'MSF_HOST\s*=\s*"[^"]*"',       f'MSF_HOST = "{msf_host}"',    out)
        out = sub(r'MSF_PORT\s*=\s*\d+',           f'MSF_PORT = {msf_port}',      out)
        out = sub(r'MSF_USER\s*=\s*"[^"]*"',       f'MSF_USER = "{msf_user}"',    out)
        out = sub(r'MSF_PASS\s*=\s*"[^"]*"',       f'MSF_PASS = "{msf_pass}"',    out)
        out = sub(r'ATTACKER_LHOST\s*=\s*"[^"]*"', f'ATTACKER_LHOST = "{lhost}"', out)
        out = sub(r'ATTACKER_LPORT\s*=\s*"[^"]*"', f'ATTACKER_LPORT = "{lport}"', out)

        # Replace the header comment to clarify this is the generated file
        out = out.replace(
            "# config.template.py",
            "# config.py  —  generated by setup.py  —  do not edit manually"
        ).replace(
            "# ╔══════════════════════════════════════════════════════════════════════╗\n"
            "# ║  DO NOT MODIFY THIS FILE                                            ║\n"
            "# ║                                                                     ║\n"
            "# ║  This is the configuration template used by setup.py to generate   ║\n"
            "# ║  config.py with your actual values.                                 ║\n"
            "# ║                                                                     ║\n"
            "# ║  To configure the framework, run:  uv run setup.py                 ║\n"
            "# ╚══════════════════════════════════════════════════════════════════════╝\n",
            "# To reconfigure, run:  uv run setup.py\n"
        )
    else:
        # Fallback template (if config.template.py is missing)
        out = f"""\
# config.py  —  generated by setup.py  —  do not edit manually
# To reconfigure, run:  uv run setup.py

LLM_ID = "{llm_id}"
LLM_BASE_URL = "{llm_url}"
LLM_API_KEY = "{llm_key}"
LLM_MAX_TOKENS = {llm_tok}

MSF_HOST = "{msf_host}"
MSF_PORT = {msf_port}
MSF_USER = "{msf_user}"
MSF_PASS = "{msf_pass}"

ATTACKER_LHOST = "{lhost}"
ATTACKER_LPORT = "{lport}"
"""

    with open(path, "w") as f:
        f.write(out)


# ════════════════════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    print(f"\n{BOLD}{'═' * 62}")
    print(f"  v1 Framework — First-Run Setup Wizard")
    print(f"  Configures LLM, Metasploit RPC, and network settings.")
    print(f"  config.py is written ONLY if all preflight checks pass.")
    print(f"{'═' * 62}{RESET}")

    cfg = {}

    # ── Step 1: LLM ──────────────────────────────────────────────────────
    llm_cfg = setup_llm()
    cfg.update(llm_cfg)

    # ── Step 2: Metasploit ───────────────────────────────────────────────
    while True:
        msf_cfg = setup_msf()
        if msf_cfg is not None:
            cfg.update(msf_cfg)
            break
        print()
        retry = prompt("MSF connection failed. Retry with different values? (y/n)", default="y")
        if retry.lower() != "y":
            print(f"\n{RED}{BOLD}Setup aborted — Metasploit RPC is required.{RESET}")
            sys.exit(1)

    # ── Step 3: Network ──────────────────────────────────────────────────
    net_cfg = setup_network()
    cfg.update(net_cfg)

    # ── Step 4: Preflight ────────────────────────────────────────────────
    all_passed = run_preflight(cfg)

    # ── Step 5: Outcome ──────────────────────────────────────────────────
    print()
    if all_passed:
        _write_config(cfg)
        print(f"\n{GREEN}{BOLD}{'═' * 62}")
        print(f"  ✔  All checks passed — config.py written successfully.")
        print(f"{'═' * 62}{RESET}")
        print(f"\n  You can now start the framework:")
        print(f"    {CYAN}uv run main.py{RESET}          ← CLI mode")
        print(f"    {CYAN}uv run serve.py{RESET}         ← AgentOS dashboard mode\n")
    else:
        print(f"\n{RED}{BOLD}{'═' * 62}")
        print(f"  ✘  Preflight failed — config.py was NOT modified.")
        print(f"{'═' * 62}{RESET}")
        print(f"\n  Fix the issues shown above and re-run:")
        print(f"    {CYAN}uv run setup.py{RESET}\n")
        sys.exit(1)
