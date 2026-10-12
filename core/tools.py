# tools.py
# Facade for backward compatibility. Imports and re-exports all tools from the split files.

import core.scout_tools
import core.coder_tools
import core.postexploit_tools

from core.rpc_client import msf_client

from core.scout_tools import (
    msf_execute_scanner,
    nmap_scan,
    curl_request,
    msf_search_modules,
    get_network_interfaces
)

from core.coder_tools import (
    msf_trigger_exploit,
    get_lhost_for_target,
    get_network_environment,
    _verify_session_alive
)

from core.postexploit_tools import (
    msf_session_command,
    msf_add_route,
    msf_discover_hosts,
    msf_upgrade_shell_to_meterpreter,
    msf_trigger_local_exploit,
)

def __setattr__(name, value):
    if name == "msf_client":
        core.scout_tools.msf_client = value
        core.coder_tools.msf_client = value
        core.postexploit_tools.msf_client = value
    globals()[name] = value