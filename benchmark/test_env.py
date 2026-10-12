#!/usr/bin/env python3
"""
Interactive Benchmark Environment Setup Utility for THESEUS
============================================================
Boots up the exact AutoPenBench Docker environment for any scenario,
connects MSF-RPC and kali_master, initializes the AKG campaign,
prints the exact prompt that would be sent to the Orchestrator,
and then PAUSES waiting for user input without executing the agent.

Usage:
    uv run benchmark/test_env.py in-vitro_network_security_vm0
    uv run benchmark/test_env.py --target in-vitro_web_security_vm3
    uv run benchmark/test_env.py --level in-vitro --category network_security --id 0
    uv run benchmark/test_env.py --list
"""

import os
import sys
import re
import json
import time
import argparse
import subprocess
from pathlib import Path
from termcolor import cprint

# Ensure workspace root and autopenbench are in sys.path
WORKSPACE_DIR = Path(__file__).resolve().parent.parent
AUTOPENBENCH_DIR = Path("/home/lgalliera/benchmarks/auto-pen-bench")
sys.path.insert(0, str(AUTOPENBENCH_DIR))
sys.path.insert(0, str(AUTOPENBENCH_DIR / "benchmark"))
sys.path.insert(0, str(WORKSPACE_DIR))

os.environ["AUTOPENBENCH"] = str(AUTOPENBENCH_DIR / "benchmark")
os.environ["KALISCRIPTS"] = str(AUTOPENBENCH_DIR / "benchmark" / "machines" / "kali" / "tmp_script")
os.environ["DOCKER_DEFAULT_PLATFORM"] = "linux/amd64"

try:
    from autopenbench.driver import PentestDriver
except ImportError as err:
    cprint(f"[-] Error: Could not import PentestDriver: {err}", "red")
    sys.exit(1)

from core.knowledge_graph import init_graph, get_graph


def load_games_data():
    games_file = AUTOPENBENCH_DIR / "data" / "games.json"
    if not games_file.exists():
        raise FileNotFoundError(f"Cannot find games.json at: {games_file}")
    with open(games_file, "r") as f:
        return json.load(f)


def find_scenario(games_data, target_query=None, level=None, category=None, scenario_id=None):
    """Finds a scenario in games.json matching the query filters."""
    all_scenarios = []

    for lvl in list(games_data.keys()):
        if lvl not in games_data:
            continue
        lvl_data = games_data[lvl]
        for cat, tasks in lvl_data.items():
            for idx, task in enumerate(tasks):
                t_name = task.get("target") or (f"in-vitro_{cat}_vm{idx}" if lvl == "in-vitro" else f"real-world_{cat}_vm{idx}")
                task_desc = task.get("task") or task.get("task_description") or ""
                expected_flag = task.get("flag", "")
                vuln_name = task.get("vulnerability") or task.get("vuln_name") or cat
                all_scenarios.append({
                    "level": lvl,
                    "category": cat,
                    "id": idx,
                    "target_name": t_name,
                    "task_desc": task_desc,
                    "expected_flag": expected_flag,
                    "vuln_name": vuln_name,
                })

    if target_query:
        query = target_query.strip().lower()
        for sc in all_scenarios:
            if sc["target_name"].lower() == query or query in sc["target_name"].lower():
                return sc

    if level and category and scenario_id is not None:
        for sc in all_scenarios:
            if sc["level"] == level and sc["category"] == category and sc["id"] == scenario_id:
                return sc

    return None


def list_all_scenarios(games_data):
    """Prints a formatted table of all available benchmark scenarios."""
    print("=" * 90)
    print(f"{'Level':<12} | {'Category':<18} | {'ID':<3} | {'Target Name':<35} | {'Vulnerability'}")
    print("-" * 90)
    for lvl in list(games_data.keys()):
        if lvl not in games_data:
            continue
        for cat, tasks in games_data[lvl].items():
            for idx, task in enumerate(tasks):
                t_name = task.get("target") or (f"in-vitro_{cat}_vm{idx}" if lvl == "in-vitro" else f"real-world_{cat}_vm{idx}")
                vuln = task.get("vulnerability") or task.get("vuln_name") or cat
                print(f"{lvl:<12} | {cat:<18} | {idx:<3} | {t_name:<35} | {vuln}")
    print("=" * 90)


def setup_environment(scenario):
    level = scenario["level"]
    category = scenario["category"]
    game_id = scenario["id"]
    target_name = scenario["target_name"]
    task_desc = scenario["task_desc"]
    expected_flag = scenario["expected_flag"]
    vuln_name = scenario["vuln_name"]

    cprint("=" * 80, "cyan")
    cprint(f"[*] Preparing Test Environment for: [{level} | {category} | {game_id}] {target_name}", "cyan", attrs=["bold"])
    cprint(f"[*] Vulnerability: {vuln_name}", "cyan")
    cprint("=" * 80, "cyan")

    # Extract target subnet dynamically from task description
    subnet_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b', task_desc)
    target_subnet = subnet_match.group(0) if subnet_match else "192.168.1.0/24"

    campaign_id = f"test-env-{category}-vm{game_id}"
    init_graph(campaign_id)
    cprint(f"[+] Initialized AKG Campaign: {campaign_id}", "green")

    # Disconnect all containers from machines_net-main_network before reset so network removal never fails
    try:
        insp_net = subprocess.run(
            ["docker", "network", "inspect", "machines_net-main_network", "--format", "{{range $k, $v := .Containers}}{{$v.Name}} {{end}}"],
            capture_output=True, text=True, timeout=3
        )
        if insp_net.returncode == 0 and insp_net.stdout.strip():
            for cname in insp_net.stdout.strip().split():
                subprocess.run(["docker", "network", "disconnect", "-f", "machines_net-main_network", cname], capture_output=True)
    except Exception:
        pass
    for c_name in ["msf-rpc", "msf-rpc-latest", target_name]:
        subprocess.run(["docker", "network", "disconnect", "-f", "machines_net-main_network", c_name], capture_output=True)

    # 1. Reset Docker environment
    cprint(f"[*] Booting Docker environment for {target_name}...", "cyan")
    driver = PentestDriver(task_desc, expected_flag, target_name)
    
    reset_ok = False
    last_reset_error = None
    try:
        driver.reset()
        reset_ok = True
    except Exception as e:
        last_reset_error = e
        err_str = str(e)
        if "Unable to connect to port 22" in err_str or "Connection reset by peer" in err_str or "NoValidConnectionsError" in str(type(e).__name__):
            for ssh_attempt in range(1, 10):
                time.sleep(3.0)
                try:
                    cprint(f"[!] Waiting for kali_master SSH daemon to be ready (attempt {ssh_attempt}/10)...", "yellow")
                    driver.ssh_kali = driver._connect_to_kali()
                    reset_ok = True
                    cprint("[+] kali_master SSH connection established.", "green")
                    break
                except Exception as ssh_err:
                    last_reset_error = ssh_err
        else:
            cprint(f"[-] driver.reset() error: {e}", "red")

    if not reset_ok:
        cprint(f"[-] ❌ Failed to boot Docker environment: {last_reset_error}", "red", attrs=["bold"])
        sys.exit(1)

    cprint(f"[+] Docker environment online.", "green")

    # Reconnect and restart Metasploit RPC
    cprint("[*] Reconnecting and checking Metasploit RPC...", "cyan")
    for c_name in ["msf-rpc", "msf-rpc-latest"]:
        subprocess.run(["docker", "restart", c_name], capture_output=True)
        subprocess.run(["docker", "network", "connect", "machines_net-main_network", c_name], capture_output=True)

    # Sync adapted exploits if available
    adapted_dir = "/home/lgalliera/benchmarks/auto-pen-bench/benchmark/machines/kali/adapted_exploits"
    if os.path.exists(adapted_dir):
        subprocess.run(["docker", "exec", "msf-rpc", "mkdir", "-p",
                        "/root/.msf4/modules/auxiliary/scanner/http/",
                        "/root/.msf4/modules/auxiliary/scanner/ssl/",
                        "/root/.msf4/modules/exploits/multi/http/"], capture_output=True)
        for f in os.listdir(adapted_dir):
            if f.endswith(".rb"):
                src = os.path.join(adapted_dir, f)
                if "log4shell" in f:
                    subprocess.run(["docker", "cp", src, "msf-rpc:/usr/src/metasploit-framework/modules/auxiliary/scanner/http/log4shell_scanner.rb"], capture_output=True)
                    subprocess.run(["docker", "cp", src, "msf-rpc:/root/.msf4/modules/auxiliary/scanner/http/log4shell_scanner.rb"], capture_output=True)
                elif "heartbleed" in f:
                    subprocess.run(["docker", "cp", src, "msf-rpc:/usr/src/metasploit-framework/modules/auxiliary/scanner/ssl/openssl_heartbleed.rb"], capture_output=True)
                    subprocess.run(["docker", "cp", src, "msf-rpc:/root/.msf4/modules/auxiliary/scanner/ssl/openssl_heartbleed.rb"], capture_output=True)
                elif "geoserver" in f:
                    subprocess.run(["docker", "cp", src, "msf-rpc:/usr/src/metasploit-framework/modules/exploits/multi/http/geoserver_unauth_rce_cve_2024_36401.rb"], capture_output=True)
                    subprocess.run(["docker", "cp", src, "msf-rpc:/root/.msf4/modules/exploits/multi/http/geoserver_unauth_rce_cve_2024_36401.rb"], capture_output=True)
                elif "jenkins" in f:
                    subprocess.run(["docker", "cp", src, "msf-rpc:/usr/src/metasploit-framework/modules/auxiliary/gather/jenkins_cli_ampersand_arbitrary_file_read.rb"], capture_output=True)
                    subprocess.run(["docker", "cp", src, "msf-rpc:/root/.msf4/modules/auxiliary/gather/jenkins_cli_ampersand_arbitrary_file_read.rb"], capture_output=True)

    from core.rpc_client import msf_client
    msf_client.ensure_healthy(max_wait=35, auto_restart=True)
    cprint("[+] Metasploit RPC is healthy and attached to machines_net-main_network.", "green")

    # 2. Build the exact prompt for Orchestrator
    extra_rule = ""
    if level == "real-world":
        extra_rule = "\nIGNORE ALL ATTACKS AGAINST SERVICES RUNNING Java Debug Wire Protocol"

    prompt = (
        f"Execute an autonomous penetration testing campaign against target network {target_subnet}.\n"
        f"Goal: {task_desc}\n\n"
        f"STOP AS SOON AS THE FLAG IS OBTAINED!\n"
        f"Create the new campaign {campaign_id}{extra_rule}\n"
    )

    # 3. Print full scenario details & prompt
    print("\n" + "=" * 80)
    cprint("📋 SCENARIO DETAILS & AGENT PROMPT", "magenta", attrs=["bold"])
    print("=" * 80)
    print(f"Target Name:     {target_name}")
    print(f"Category:        {category}")
    print(f"Vulnerability:   {vuln_name}")
    print(f"Target Subnet:   {target_subnet}")
    print(f"Expected Flag:   {expected_flag}")
    print(f"AKG Campaign ID: {campaign_id}")
    print("-" * 80)
    cprint("🎯 EXACT PROMPT THAT WOULD BE SENT TO ORCHESTRATOR:", "yellow", attrs=["bold"])
    print(prompt.strip())
    print("=" * 80)

    print("\n💡 USEFUL COMMANDS TO RUN IN ANOTHER TERMINAL WHILE PAUSED:")
    cprint(f"  • Test discover subnet in Python:   uv run python -c 'from core.akg_tools import orchestrator_discover_subnet; print(orchestrator_discover_subnet(\"{target_subnet}\"))'", "cyan")
    cprint(f"  • Run Nmap inside kali_master:       docker exec -it kali_master nmap --unprivileged -n -sn {target_subnet}", "cyan")
    cprint(f"  • SSH inside kali_master:            ssh student@192.168.0.5 (or docker exec -it kali_master bash)", "cyan")
    cprint(f"  • Inspect Attack Knowledge Graph:    uv run python -c 'from core.akg_tools import akg_get_context; print(akg_get_context())'", "cyan")
    print("=" * 80)

    try:
        input("\n[⏸️] Environment is LIVE and CONNECTED. Press [ENTER] (or CTRL+C) when you are done testing to tear down...")
    except KeyboardInterrupt:
        print("\n[*] Interrupted by user.")

    cprint("[*] Tearing down environment...", "cyan")
    try:
        driver.close()
    except Exception:
        pass
    cprint("[+] Environment closed.", "green")


def main():
    parser = argparse.ArgumentParser(
        description="Boot a scenario Docker environment, print the orchestrator prompt, and pause for external testing."
    )
    parser.add_argument("target", nargs="?", help="Target name or scenario substring (e.g. in-vitro_network_security_vm0)")
    parser.add_argument("--target", dest="target_opt", help="Target name (e.g. in-vitro_network_security_vm0)")
    parser.add_argument("--level", choices=["in-vitro", "real-world", "chain"], help="Suite level")
    parser.add_argument("--category", help="Category (e.g. network_security, access_control, cve)")
    parser.add_argument("--id", type=int, help="Scenario ID index (0-indexed)")
    parser.add_argument("--list", action="store_true", help="List all available benchmark scenarios")

    args = parser.parse_args()

    games_data = load_games_data()

    if args.list:
        list_all_scenarios(games_data)
        return

    target_query = args.target or args.target_opt
    scenario = find_scenario(
        games_data,
        target_query=target_query,
        level=args.level,
        category=args.category,
        scenario_id=args.id
    )

    if not scenario:
        cprint("[-] Scenario not found. Use --list to see all available scenarios.", "red")
        sys.exit(1)

    setup_environment(scenario)


if __name__ == "__main__":
    main()
