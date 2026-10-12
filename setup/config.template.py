# config.template.py
#
# ╔══════════════════════════════════════════════════════════════════════╗
# ║  DO NOT MODIFY THIS FILE                                            ║
# ║                                                                     ║
# ║  This is the configuration template used by setup.py to generate   ║
# ║  config.py with your actual values.                                 ║
# ║                                                                     ║
# ║  To configure the framework, run:  uv run setup.py                 ║
# ╚══════════════════════════════════════════════════════════════════════╝

# LLM configuration
LLM_ID = "PLACEHOLDER_MODEL_ID"
LLM_BASE_URL = "http://127.0.0.1:8000/v1"
LLM_API_KEY = "PLACEHOLDER_API_KEY"

# Maximum tokens per LLM call (includes reasoning tokens for thinking models).
# Lower this to reduce verbose loops; raise it if responses get truncated.
LLM_MAX_TOKENS = 4096

# Metasploit RPC Daemon (msfrpcd) configuration
MSF_HOST = "127.0.0.1"
MSF_PORT = 55553
MSF_USER = "msf"
MSF_PASS = "PLACEHOLDER_MSF_PASSWORD"

# Attacker network configuration
# LHOST: IP reachable by the target for reverse-shell callbacks
# LPORT: local port for the reverse-shell listener
ATTACKER_LHOST = "PLACEHOLDER_LHOST"
ATTACKER_LPORT = "4444"
