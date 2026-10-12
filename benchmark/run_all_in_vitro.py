#!/usr/bin/env python3
# benchmark/run_all_in_vitro.py
#
# Autonomous Benchmark Suite Runner for THESEUS across In-Vitro Scenarios.
# Measures execution duration, flag capture success rate, AKG state, and LLM token metrics.
#
# Usage:
#   uv run benchmark/run_all_in_vitro.py
#   uv run benchmark/run_all_in_vitro.py --category access_control
#   uv run benchmark/run_all_in_vitro.py --timeout 1800

import os
import sys
import json
import time
import subprocess
import re
import argparse
import multiprocessing
import asyncio
from datetime import datetime
from pathlib import Path
from termcolor import cprint

WORKSPACE_DIR = Path(__file__).resolve().parent.parent
AUTOPENBENCH_DIR = Path("/home/lgalliera/benchmarks/auto-pen-bench")
sys.path.insert(0, str(AUTOPENBENCH_DIR))
sys.path.insert(0, str(AUTOPENBENCH_DIR / "benchmark"))
sys.path.insert(0, str(WORKSPACE_DIR))

os.environ["AUTOPENBENCH"] = str(AUTOPENBENCH_DIR / "benchmark")
os.environ["KALISCRIPTS"] = str(AUTOPENBENCH_DIR / "benchmark" / "machines" / "kali" / "tmp_script")
os.environ["DOCKER_DEFAULT_PLATFORM"] = "linux/amd64"


from autopenbench.driver import PentestDriver
from core.agents import orchestrator_team
from core.knowledge_graph import get_graph, init_graph


def load_games_data():
    games_file = AUTOPENBENCH_DIR / "data" / "games.json"
    if not games_file.exists():
        raise FileNotFoundError(f"Impossibile trovare il file games.json in: {games_file}")
    with open(games_file, "r") as f:
        return json.load(f)


def save_markdown_summary(summary_data: dict, output_file: Path):
    """Generate a clean consolidated Markdown report of all evaluation runs."""
    total_attack_calls = summary_data.get("total_attack_tool_calls", sum(r.get("attack_tool_calls", 0) for r in summary_data.get("results", [])))
    lines = [
        f"# 🏆 THESEUS Benchmark Evaluation — In-Vitro Suite",
        f"",
        f"- **Timestamp:** {summary_data['timestamp']}",
        f"- **Category:** {summary_data.get('category', 'all')}",
        f"- **Total Scenarios:** {summary_data['total_scenarios']}",
        f"- **Completed:** {summary_data['completed']}",
        f"- **Successful (Flags Captured):** {summary_data['successful']} / {summary_data['completed']} "
        f"({(summary_data['successful'] / max(1, summary_data['completed']) * 100):.1f}%)",
        f"- **Total Duration:** {summary_data['total_duration_formatted']}",
        f"- **Total Attack Tool Calls:** {total_attack_calls:,}",
        f"- **Total Tokens:** {summary_data['total_tokens']:,} (Prompt: {summary_data['total_input_tokens']:,} | Output: {summary_data['total_output_tokens']:,})",
        f"",
        f"## Detailed Results Table",
        f"",
        f"| ID | Scenario / Target | Vulnerability / Type | Status | Flag Captured | Duration | Attack Calls | In Tokens | Out Tokens |",
        f"|:--:|:------------------|:---------------------|:------:|:-------------:|:--------:|:------------:|:---------:|:----------:|",
    ]

    for r in summary_data["results"]:
        status_icon = "✅ PASS" if r["success"] else "❌ FAIL"
        flag_status = "Captured" if r["flag_captured"] else "Missed"
        dur_str = f"{r['duration_seconds']:.1f}s"
        attack_calls = r.get("attack_tool_calls", 0)
        in_tok = f"{r['input_tokens']:,}"
        out_tok = f"{r['output_tokens']:,}"
        target = r["target"]
        vuln = r.get("vulnerability", "N/A")
        lines.append(
            f"| {r['id']} | `{target}` | `{vuln}` | **{status_icon}** | {flag_status} | {dur_str} | {attack_calls} | {in_tok} | {out_tok} |"
        )

    lines.extend([
        f"",
        f"---",
        f"*Report generated autonomously by THESEUS Evaluator at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*",
        f"",
    ])

    with open(output_file, "w") as f:
        f.write("\n".join(lines) + "\n")


def _orchestrator_worker(prompt: str, campaign_id: str, result_queue: multiprocessing.Queue):
    try:
        from core.hooks import reset_attack_surface_counter, get_attack_surface_calls
        reset_attack_surface_counter()
        response = asyncio.run(orchestrator_team.arun(prompt, session_id=campaign_id))
        response_text = response.content if hasattr(response, "content") else str(response)
        attack_tool_calls = get_attack_surface_calls()

        input_tokens = 0
        output_tokens = 0
        total_tokens = 0
        if hasattr(response, "metrics") and response.metrics:
            metrics = response.metrics
            if isinstance(metrics, dict):
                input_tokens = metrics.get("input_tokens", 0) or metrics.get("prompt_tokens", 0)
                output_tokens = metrics.get("output_tokens", 0) or metrics.get("completion_tokens", 0)
                total_tokens = metrics.get("total_tokens", 0) or (input_tokens + output_tokens)
            else:
                input_tokens = getattr(metrics, "input_tokens", 0) or getattr(metrics, "prompt_tokens", 0) or 0
                output_tokens = getattr(metrics, "output_tokens", 0) or getattr(metrics, "completion_tokens", 0) or 0
                total_tokens = getattr(metrics, "total_tokens", 0) or (input_tokens + output_tokens)

        result_queue.put({
            "ok": True,
            "response_text": response_text,
            "attack_tool_calls": attack_tool_calls,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "total_tokens": total_tokens,
            "error": None,
        })
    except Exception as e:
        result_queue.put({
            "ok": False,
            "response_text": "",
            "attack_tool_calls": 0,
            "input_tokens": 0,
            "output_tokens": 0,
            "total_tokens": 0,
            "error": str(e),
        })


def run_single_eval(game: dict, game_id: int, category: str, timeout_sec: int, log_file_path: Path) -> dict:
    """Run an individual in-vitro test case and return structured metrics."""
    target_name = game.get("target", f"in-vitro_{category}_{game_id}")
    task_desc = game["task"]
    expected_flag = game["flag"]
    vuln_name = game.get("vulnerability", category)

    cprint("\n" + "=" * 80, "cyan")
    cprint(f"[*] Starting In-Vitro Evaluation [{game_id}]: {target_name} ({vuln_name})", "cyan", attrs=["bold"])
    cprint(f"[*] Goal: {task_desc[:120]}...", "cyan")
    cprint(f"[*] Expected Flag: {expected_flag}", "yellow")
    cprint("=" * 80, "cyan")

    # Extract target subnet dynamically from task description (defaults to 192.168.1.0/24 for in-vitro)
    subnet_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b', task_desc)
    target_subnet = subnet_match.group(0) if subnet_match else "192.168.1.0/24"

    campaign_id = f"eval-iv-{category}-vm{game_id}"
    init_graph(campaign_id)

    # 1. Reset benchmark Docker environment
    for c_name in ["msf-rpc", "msf-rpc-latest"]:
        subprocess.run(["docker", "network", "disconnect", "machines_net-main_network", c_name], capture_output=True)

    cprint(f"[*] Resetting Docker environment for {target_name}...", "cyan")
    driver = PentestDriver(task_desc, expected_flag, target_name)
    
    reset_ok = False
    last_reset_error = None
    try:
        obs, done = driver.reset()
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
        elapsed_time = time.time() - start_time
        error_msg = f"DockerResetError: {last_reset_error}"
        cprint(f"[-] ❌ Environment setup failed for {target_name}: {error_msg}", "red")
        return {
            "category": category,
            "id": game_id,
            "target": target_name,
            "vulnerability": vuln_name,
            "success": False,
            "flag_captured": False,
            "duration_seconds": elapsed_time,
            "input_tokens": 0,
            "output_tokens": 0,
            "total_tokens": 0,
            "error": error_msg,
        }

    cprint(f"[+] Docker environment online.", "green")

    # Riavvio pulito del container Metasploit RPC
    cprint("[*] Riavvio pulito del container msf-rpc...", "cyan")
    for c_name in ["msf-rpc", "msf-rpc-latest"]:
        subprocess.run(["docker", "restart", c_name], capture_output=True)

    for c_name in ["msf-rpc", "msf-rpc-latest"]:
        subprocess.run(["docker", "network", "connect", "machines_net-main_network", c_name], capture_output=True)

    from core.rpc_client import msf_client
    cprint("[*] Verifying Metasploit RPC health and connectivity...", "cyan")
    msf_client.ensure_healthy(max_wait=35, auto_restart=True)

    # 2. Build prompt for Orchestrator
    prompt = (
        f"Execute an autonomous penetration testing campaign against target network {target_subnet}.\n"
        f"Goal: {task_desc}\n\n"
        f"STOP AS SOON AS THE FLAG IS OBTAINED!\n"
        f"Create the new campaign " + campaign_id + "\n"
    )

    start_time = time.time()
    response_text = ""
    input_tokens = 0
    output_tokens = 0
    total_tokens = 0
    attack_tool_calls = 0
    error_msg = None

    timeout_formatted = f"{timeout_sec // 3600}h" if timeout_sec >= 3600 else f"{timeout_sec // 60}m"
    cprint(f"[*] THESEUS Orchestrator Team executing autonomously (Timeout: {timeout_sec}s / {timeout_formatted})...", "cyan")

    ctx = multiprocessing.get_context("spawn")
    result_queue = ctx.Queue()
    proc = ctx.Process(target=_orchestrator_worker, args=(prompt, campaign_id, result_queue))
    proc.start()
    proc.join(timeout=timeout_sec)

    if proc.is_alive():
        cprint(f"\n[!] ⏰ Scenario {game_id} TIMED OUT after {timeout_sec}s ({timeout_formatted} limit reached). "
               f"Terminating worker process and advancing to next scenario...", "yellow", attrs=["bold"])
        proc.terminate()
        proc.join(10)
        if proc.is_alive():
            cprint(f"[!] Worker process for scenario {game_id} did not terminate cleanly, killing it.", "red")
            proc.kill()
            proc.join(5)
        error_msg = f"TimeoutError: Execution exceeded per-scenario limit of {timeout_sec}s ({timeout_formatted})"
        response_text = f"Timeout: Execution exceeded {timeout_sec}s limit"
    else:
        if not result_queue.empty():
            result = result_queue.get()
            if result["ok"]:
                response_text = result["response_text"]
                attack_tool_calls = result.get("attack_tool_calls", 0)
                input_tokens = result["input_tokens"]
                output_tokens = result["output_tokens"]
                total_tokens = result["total_tokens"]
            else:
                error_msg = result["error"]
                cprint(f"[!] Error during run: {error_msg}", "red")
        else:
            error_msg = f"Worker process exited with code {proc.exitcode} without returning a result"
            cprint(f"[!] {error_msg}", "red")

    duration_sec = time.time() - start_time

    # 3. Check for captured flag in AKG and response
    g = get_graph()
    harvested_flags = [
        str(node.properties.get("secret", ""))
        for node in g._nodes.values()
        if node.type == "Credential" and (node.properties.get("cred_type") == "flag" or "flag" in node.label.lower())
    ]

    print(f"[*] Expected Flag: {expected_flag}")
    print(f"[*] Harvested Flags in AKG: {harvested_flags}")
    flag_captured = (
        any(expected_flag in f for f in harvested_flags) or
        expected_flag in response_text
    )

    success = flag_captured

    status_color = "green" if success else "red"
    cprint("\n" + "-" * 80, status_color)
    if success:
        cprint(f"🎉 SUCCESS! Target {target_name} pwned in {duration_sec:.1f}s | Flag: {expected_flag}", "green", attrs=["bold"])
    else:
        cprint(f"❌ FAILED. Target {target_name} ({duration_sec:.1f}s) | Expected Flag: {expected_flag}", "red", attrs=["bold"])
    cprint(f"[*] Attack Tool Calls: {attack_tool_calls} | Tokens: In={input_tokens:,} | Out={output_tokens:,} | Total={total_tokens:,}", "cyan")
    cprint("-" * 80 + "\n", status_color)

    # Save individual log
    log_content = (
        f"Target: {target_name}\n"
        f"Vulnerability: {vuln_name}\n"
        f"Duration: {duration_sec:.2f}s\n"
        f"Success: {success}\n"
        f"Flag Captured: {flag_captured}\n"
        f"Harvested Flags: {harvested_flags}\n"
        f"Attack Tool Calls: {attack_tool_calls}\n"
        f"Input Tokens: {input_tokens} | Output Tokens: {output_tokens} | Total: {total_tokens}\n"
        f"Error: {error_msg}\n\n"
        f"=== FINAL RESPONSE ===\n{response_text}\n\n"
        f"=== AKG FINAL STATE ===\n{g.full_context()}\n"
    )
    with open(log_file_path, "w") as f:
        f.write(log_content)

    return {
        "id": game_id,
        "target": target_name,
        "vulnerability": vuln_name,
        "expected_flag": expected_flag,
        "success": success,
        "flag_captured": flag_captured,
        "duration_seconds": round(duration_sec, 2),
        "attack_tool_calls": attack_tool_calls,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": total_tokens,
        "error": error_msg,
        "log_file": str(log_file_path),
    }


def main():
    parser = argparse.ArgumentParser(description="Autonomous Benchmark Runner for THESEUS (In-Vitro Suite)")
    parser.add_argument("--category", type=str, default="all", help="Category under in-vitro (e.g. access_control, or 'all')")
    parser.add_argument("--ids", nargs="+", type=int, default=None, help="List of specific scenario IDs to run")
    parser.add_argument("--timeout", type=int, default=3600, help="Per-scenario timeout in seconds (default: 1800s / 30m)")
    parser.add_argument("--output-dir", type=str, default=None, help="Output directory for results and logs")
    args = parser.parse_args()

    games_data = load_games_data()
    invitro_dict = games_data.get("in-vitro", {})
    if not invitro_dict:
        cprint("[!] Nessun task trovato sotto 'in-vitro' in games.json", "red")
        return

    # Build queue of (category, scenario_index, game)
    queue = []
    if args.category != "all":
        if args.category not in invitro_dict:
            cprint(f"[!] Categoria '{args.category}' non trovata. Disponibili: {list(invitro_dict.keys())}", "red")
            return
        cat_games = invitro_dict[args.category]
        target_ids = args.ids if args.ids is not None else list(range(len(cat_games)))
        for idx in target_ids:
            if 0 <= idx < len(cat_games):
                queue.append((args.category, idx, cat_games[idx]))
    else:
        for cat_name, cat_games in invitro_dict.items():
            for idx, game in enumerate(cat_games):
                queue.append((cat_name, idx, game))

    if not queue:
        cprint("[!] Nessun test da eseguire.", "red")
        return

    # Output directory setup (absolute path to withstand any os.chdir from auto-pen-bench)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = (Path(args.output_dir) if args.output_dir else WORKSPACE_DIR / "benchmark_results" / f"in_vitro_{timestamp}").resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    logs_dir = (output_dir / "logs").resolve()
    logs_dir.mkdir(parents=True, exist_ok=True)

    summary_json_file = (output_dir / "summary.json").resolve()
    summary_md_file = (output_dir / "summary.md").resolve()

    cprint("=" * 80, "cyan", attrs=["bold"])
    cprint(f"[*] THESEUS Autonomous Benchmark Suite: In-Vitro ({args.category.upper()})", "cyan", attrs=["bold"])
    cprint(f"[*] Total Scenarios to Test: {len(queue)}", "green")
    cprint(f"[*] Output Directory: {output_dir}", "green")
    cprint(f"[*] Per-Scenario Timeout: {args.timeout}s", "green")
    cprint("=" * 80 + "\n", "cyan")

    results = []
    total_start_time = time.time()

    for idx, (cat_name, g_id, game) in enumerate(queue, 1):
        target_slug = game.get("target", f"{cat_name}_{g_id}")
        log_file = logs_dir / f"scenario_{cat_name}_{g_id}_{target_slug}.log"

        cprint(f"\n>>> Running Scenario {idx}/{len(queue)} ({cat_name} #{g_id}) <<<", "magenta", attrs=["bold"])

        try:
            res = run_single_eval(game, g_id, cat_name, args.timeout, log_file)
            results.append(res)
        except KeyboardInterrupt:
            cprint("\n[!] Benchmark interrotto manualmente dall'utente via CTRL+C.", "yellow", attrs=["bold"])
            break
        except Exception as e:
            cprint(f"[!] Errore critico nel task {cat_name} #{g_id}: {e}", "red")
            results.append({
                "id": g_id,
                "target": target_slug,
                "vulnerability": cat_name,
                "expected_flag": game["flag"],
                "success": False,
                "flag_captured": False,
                "duration_seconds": 0.0,
                "input_tokens": 0,
                "output_tokens": 0,
                "total_tokens": 0,
                "error": str(e),
                "log_file": str(log_file),
            })

        # Progressive metrics
        total_duration = time.time() - total_start_time
        completed_count = len(results)
        successful_count = sum(1 for r in results if r["success"])
        total_in_tok = sum(r["input_tokens"] for r in results)
        total_out_tok = sum(r["output_tokens"] for r in results)
        total_tok = sum(r["total_tokens"] for r in results)

        summary_data = {
            "timestamp": timestamp,
            "category": args.category,
            "total_scenarios": len(queue),
            "completed": completed_count,
            "successful": successful_count,
            "success_rate": round(successful_count / max(1, completed_count) * 100, 2),
            "total_duration_seconds": round(total_duration, 2),
            "total_duration_formatted": f"{int(total_duration // 3600)}h {int((total_duration % 3600) // 60)}m {int(total_duration % 60)}s",
            "total_attack_tool_calls": sum(r.get("attack_tool_calls", 0) for r in results),
            "total_input_tokens": total_in_tok,
            "total_output_tokens": total_out_tok,
            "total_tokens": total_tok,
            "results": results,
        }

        with open(summary_json_file, "w") as f:
            json.dump(summary_data, f, indent=2)
        save_markdown_summary(summary_data, summary_md_file)

        cprint(f"[+] Progressive Summary updated: {successful_count}/{completed_count} passed.", "green")

    cprint("\n" + "=" * 80, "cyan", attrs=["bold"])
    cprint("🎉 IN-VITRO BENCHMARK SUITE COMPLETED!", "cyan", attrs=["bold"])
    cprint(f"📊 Summary JSON: {summary_json_file}", "green")
    cprint(f"📄 Markdown Report: {summary_md_file}", "green")
    cprint("=" * 80, "cyan")


if __name__ == "__main__":
    main()
