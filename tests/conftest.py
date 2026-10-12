# tests/conftest.py
"""
Shared pytest fixtures for the THESEUS test suite.

All fixtures that mock external dependencies (msf_client, subprocess, socket)
live here so that individual test modules stay focused on behaviour.
"""
import json
import pytest
from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# Sample data
# ---------------------------------------------------------------------------

NMAP_XML_ONE_HOST = """\
<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9" extrainfo="Ubuntu"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache httpd" version="2.4.52" extrainfo=""/>
      </port>
      <port protocol="tcp" portid="21">
        <state state="closed"/>
        <service name="ftp"/>
      </port>
    </ports>
    <os>
      <osmatch name="Linux 5.x" accuracy="95"/>
    </os>
  </host>
</nmaprun>
"""

NMAP_XML_EMPTY = """\
<?xml version="1.0"?>
<nmaprun>
</nmaprun>
"""


# ---------------------------------------------------------------------------
# MSF client mock factory
# ---------------------------------------------------------------------------

def make_msf_mock(
    module_execute_result=None,
    session_list_result=None,
    module_search_result=None,
    module_exploits_result=None,
    module_auxiliary_result=None,
    session_meterpreter_run_result=None,
    session_meterpreter_read_result=None,
    session_meterpreter_write_result=None,
    session_shell_write_result=None,
    session_shell_read_result=None,
    routing_add_result=None,
    session_interactive_write_result=None,
    session_interactive_read_result=None,
    module_info_result=None,
):
    """
    Build a MagicMock that mimics MetasploitRPCClient.call() responses.
    Only the provided kwargs are configured; all others default to empty dicts.
    """
    mock = MagicMock()
    mock.is_connected = True

    defaults = {
        "module.execute":               module_execute_result or {"job_id": 1},
        "session.list":                 session_list_result or {},
        "module.search":                module_search_result if module_search_result is not None else [],
        "module.exploits":              module_exploits_result or {"modules": []},
        "module.auxiliary":             module_auxiliary_result or {"modules": []},
        "module.info":                  module_info_result if module_info_result is not None else {"name": "Mock Module"},
        "session.meterpreter_run_single": session_meterpreter_run_result or {"result": "success"},
        "session.meterpreter_read":     session_meterpreter_read_result or {"data": "active"},
        "session.meterpreter_write":    session_meterpreter_write_result or {"result": "success"},
        "session.shell_write":          session_shell_write_result or {"result": "success"},
        "session.shell_read":           session_shell_read_result or {"data": "active"},
        "session.routing.add":          routing_add_result or {"result": "success"},
        "session.interactive_write":    session_interactive_write_result or {"result": "success"},
        "session.interactive_read":     session_interactive_read_result or {"data": "active"},
    }

    def _call(method, *args, **kwargs):
        return defaults.get(method, {})

    mock.call.side_effect = _call
    return mock


@pytest.fixture
def msf_mock():
    """Default MSF mock with reasonable happy-path defaults."""
    return make_msf_mock()


# ---------------------------------------------------------------------------
# AKG Isolation fixture (runs automatically for EVERY test)
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def isolate_akg_for_tests(tmp_path, monkeypatch):
    """
    Guarantees that ALL unit tests run against an isolated ephemeral AttackGraph
    in a temporary directory, and NEVER touch or mutate real campaigns on disk.
    """
    from core.knowledge_graph import AttackGraph
    import core.knowledge_graph as kg_module
    import core.akg_tools as akg_module

    ephemeral_graph = AttackGraph(campaign_id="test-ephemeral", campaign_dir=str(tmp_path))
    
    monkeypatch.setattr(kg_module, "_active_graph", ephemeral_graph)
    monkeypatch.setattr(kg_module, "ACTIVE_CAMPAIGN_FILE", tmp_path / ".active_campaign")
    monkeypatch.setattr(akg_module, "_g", lambda: ephemeral_graph)
    
    yield ephemeral_graph
