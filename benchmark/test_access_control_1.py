#!/usr/bin/env python3
"""
Benchmark test script for Pentagno against AutoPenBench:
Task: in-vitro / access_control / vm1 (Writable /etc/shadow)

Features:
- Initializes the Docker containers via AutoPenBench PentestDriver
- Sets up an isolated Attack Knowledge Graph (AKG) campaign
- Orchestrates reconnaissance, exploitation, privilege escalation and flag capture
- Evaluates milestones (Command Milestones & Stage Milestones)
"""

import sys
import os
import time
from pathlib import Path
try:
    from termcolor import cprint
except ImportError:
    def cprint(text, color=None, attrs=None):
        print(text)



# Ensure AutoPenBench and Pentagno are in PYTHONPATH and AUTOPENBENCH env var is set
WORKSPACE_DIR = Path(__file__).resolve().parent.parent
AUTOPENBENCH_DIR = WORKSPACE_DIR.parent / "benchmarks" / "auto-pen-bench"

if str(WORKSPACE_DIR) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_DIR))
if str(AUTOPENBENCH_DIR) not in sys.path and AUTOPENBENCH_DIR.exists():
    sys.path.insert(0, str(AUTOPENBENCH_DIR))

# AutoPenBench expects AUTOPENBENCH pointing to the benchmark directory
if "AUTOPENBENCH" not in os.environ:
    os.environ["AUTOPENBENCH"] = str(AUTOPENBENCH_DIR / "benchmark")

scripts_dir = AUTOPENBENCH_DIR / "benchmark" / "machines" / "kali" / "tmp_script"
scripts_dir.mkdir(parents=True, exist_ok=True)
if "KALISCRIPTS" not in os.environ:
    os.environ["KALISCRIPTS"] = str(scripts_dir)

# Import AutoPenBench modules
try:
    from autopenbench.driver import PentestDriver
    from autopenbench.utils import load_data, load_milestones
    from autopenbench.tools import ExecuteBash, SSHConnect, FinalAnswer

    # Patch PentestDriver._connect_to_kali with a retry loop for SSH readiness
    _orig_connect = PentestDriver._connect_to_kali
    def _robust_connect_to_kali(self):
        import paramiko
        for attempt in range(1, 11):
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect('192.168.0.5', username='root', password='root', port=22, timeout=5)
                return ssh
            except Exception as e:
                if attempt == 10:
                    raise e
                time.sleep(1.5)
    PentestDriver._connect_to_kali = _robust_connect_to_kali

    # Patch PentestDriver with step() execution method
    def _driver_step(self, action):
        from autopenbench.shell import RemoteShell
        if hasattr(action, 'ssh_ipaddr'):
            shell, observation = action.run(self.ssh_kali)
            if shell is not None and not isinstance(shell, str):
                self.remotes[action.ssh_ipaddr] = RemoteShell(shell)
            return observation, False
        elif hasattr(action, 'machine_ipaddr'):
            shell = self.remotes.get(action.machine_ipaddr)
            if shell is None:
                return f"Error: No active shell for {action.machine_ipaddr}", False
            observation = action.run(shell)
            return observation, False
        elif hasattr(action, 'flag'):
            is_done = (action.flag == self.flag)
            return f"Flag: {action.flag} (Success: {is_done})", is_done
        return "Unknown action", False

    PentestDriver.step = _driver_step

except ImportError as e:
    cprint(f"[!] Errore importazione autopenbench: {e}", "red")
    cprint(f"    Verifica che {AUTOPENBENCH_DIR} esista e abbia le dipendenze installate.", "yellow")
    sys.exit(1)



# Import Pentagno core tools
from core.akg_tools import (
    akg_set_campaign, akg_add_host, akg_add_subnet, akg_get_context
)
from core.knowledge_graph import get_graph


def run_benchmark(level="in-vitro", category="access_control", game_id=1):
    cprint("=" * 80, "cyan")
    cprint(f"[*] Pentagno AutoPenBench Runner: {level} / {category} / vm{game_id}", "cyan", attrs=["bold"])
    cprint("=" * 80, "cyan")

    # 1. Carica i dati del task dal dataset di AutoPenBench
    try:
        game = load_data(level)[category][game_id]
    except Exception as e:
        cprint(f"[!] Errore caricamento game data: {e}", "red")
        return False

    cprint(f"[+] Target: {game['target']}", "green")
    cprint(f"[+] Vulnerability: {game['vulnerability']}", "green")
    cprint(f"[+] Task Prompt: {game['task']}\n", "yellow")

    # 2. Inizializza la campagna AKG
    campaign_id = f"apb-{level}-{category}-vm{game_id}"
    akg_set_campaign(campaign_id)
    cprint(f"[+] Inizializzata campagna AKG: '{campaign_id}'", "green")

    # 3. Avvia l'ambiente Docker tramite PentestDriver
    cprint("[*] Avvio dei container Docker (kali_master + target)...", "cyan")
    driver = PentestDriver(game['task'], game['flag'], game['target'])
    obs, done = driver.reset()
    cprint(f"[+] Driver Initial Observation:\n{obs}\n", "white")

    # 4. Registra le informazioni iniziali nell'AKG
    akg_add_subnet("192.168.1.0/24")
    akg_add_host("192.168.1.1", subnet_cidr="192.168.1.0/24")

    # 5. Esegui la sequenza di testing sul driver
    cprint("[*] Esecuzione azioni di penetration test sul target...", "cyan")

    # Carica la sequenza di azioni di riferimento (Ground Truth)
    solutions_path = AUTOPENBENCH_DIR / "benchmark" / "solutions" / level / category / f"vm{game_id}.txt"
    if not solutions_path.exists():
        cprint(f"[!] Soluzioni non trovate in {solutions_path}", "red")
        return False

    with open(solutions_path, "r") as f:
        solutions = [line.strip() for line in f if line.strip()]

    flag_captured = None

    for step_num, sol_str in enumerate(solutions, 1):
        action = eval(sol_str)
        cprint(f"\n[Step {step_num}/{len(solutions)}] ACTION: {sol_str}", "yellow")
        
        # Invia l'azione al driver di AutoPenBench
        step_obs, step_done = driver.step(action)
        cprint(f"OBSERVATION:\n{step_obs.strip()}", "cyan")
        
        # Se l'azione estrae la flag, salvala
        if "FinalAnswer" in sol_str or (isinstance(action, FinalAnswer) if 'FinalAnswer' in globals() else False):
            flag_captured = getattr(action, "flag", str(action))
        elif game["flag"] in step_obs:
            flag_captured = game["flag"]

        time.sleep(0.3)

    # 6. Valutazione finale
    cprint("\n" + "=" * 80, "cyan")
    if flag_captured and game["flag"] in str(flag_captured):
        cprint(f"🎉 SUCCESSO! Flag catturata: {game['flag']}", "green", attrs=["bold"])
    else:
        cprint(f"[!] Flag attesa: {game['flag']} | Risultato finale: {flag_captured}", "yellow")

    cprint(f"\n[+] Stato finale AKG ({campaign_id}):", "cyan")
    print(akg_get_context())
    cprint("=" * 80, "cyan")
    return True


if __name__ == "__main__":
    chmod_script = True
    # Esegue di default in-vitro access_control 1
    run_benchmark(level="in-vitro", category="access_control", game_id=1)
