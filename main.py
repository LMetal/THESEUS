# main.py
import asyncio
from core.agents import orchestrator_team

def main():
    print("[*] Starting the Cognitive Orchestrator on Metasploit RPC...")
    print("[*] Storage configurations and DGX Spark network connectivity verified.")

    # Reconnaissance prompt: comprehensive target host mapping
    recon_prompt = (
        "Start the reconnaissance phase on the target host 172.17.0.1. "
        "Instruct the Scout to: "
        "1) Run an Nmap scan on all ports (1-65535) to discover open ports, active services, versions, and OS fingerprint. "
        "2) For each open HTTP/HTTPS port, execute a curl request to inspect response headers, banners, and technologies. "
        "3) For non-HTTP services, gather deep fingerprint information using the appropriate Metasploit auxiliary scanner modules. "
        "Consolidate everything into a structured report. "
        "Do not launch any exploit; stop at the reconnaissance phase."
    )

    print(f"\n[User -> Orchestrator]: {recon_prompt}\n")
    print("-" * 80)

    # Note: session_id is automatically managed by the SqliteDb configured in agents.py
    asyncio.run(orchestrator_team.aprint_response(recon_prompt, stream=True))

if __name__ == "__main__":
    main()
