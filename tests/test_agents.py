# tests/test_agents.py
"""
Static configuration tests for core/agents.py.

These tests verify that each agent is wired correctly — right tools, right model,
right team membership — WITHOUT invoking the LLM or Metasploit.

Key principle: agent behaviour is largely determined by configuration. If the
wrong tool is absent, the agent cannot complete its job regardless of how good
the LLM is. These tests catch misconfigurations instantly.
"""
import pytest
from unittest.mock import patch, MagicMock


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _tool_names(agent):
    """Return the set of function names registered on an agent."""
    # agno Agent exposes tools as a list of callables or FunctionTool wrappers
    tools = getattr(agent, "tools", None) or []
    names = set()
    for t in tools:
        # FunctionTool wrapper or plain callable
        if hasattr(t, "name"):
            names.add(t.name)
        elif hasattr(t, "__name__"):
            names.add(t.__name__)
        elif hasattr(t, "function") and hasattr(t.function, "__name__"):
            names.add(t.function.__name__)
    return names


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def agents():
    """
    Import agents with the MSF client mocked so agents.py can be loaded
    without a live msfrpcd connection.
    """
    mock_client = MagicMock()
    mock_client.is_connected = False

    with patch("core.rpc_client._msf_client_instance", mock_client):
        from core.agents import scout_agent, coder_agent, post_exploit_agent, orchestrator_team
        return {
            "scout": scout_agent,
            "coder": coder_agent,
            "post_exploit": post_exploit_agent,
            "orchestrator": orchestrator_team,
        }


# ---------------------------------------------------------------------------
# Scout Agent
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Scout Agent
# ---------------------------------------------------------------------------

class TestScoutAgent:

    EXPECTED_TOOLS = {
        "nmap_scan",
        "curl_request",
        "msf_search_modules",
        "msf_get_module_info",
        "msf_execute_scanner",
        "get_network_interfaces",
        "akg_add_service",
        "akg_add_subnet",
        "akg_add_host",
        "akg_add_credential",
    }

    def test_has_all_expected_tools(self, agents):
        """Scout must have all reconnaissance tools registered."""
        scout = agents["scout"]
        names = _tool_names(scout)
        missing = self.EXPECTED_TOOLS - names
        assert not missing, f"Scout is missing tools: {missing}"

    def test_does_not_have_exploit_tools(self, agents):
        """Scout must NOT have exploit triggering tools."""
        scout = agents["scout"]
        names = _tool_names(scout)
        forbidden = {"msf_trigger_exploit", "msf_trigger_exploit_auto", "msf_trigger_local_exploit"}
        present = forbidden & names
        assert not present, f"Scout has forbidden exploit tools: {present}"

    def test_name_is_scout(self, agents):
        """Agent name must be 'Scout' (used by Orchestrator for delegation)."""
        assert agents["scout"].name == "Scout"

    def test_has_model(self, agents):
        """Scout must have a model configured."""
        assert agents["scout"].model is not None

    def test_markdown_disabled(self, agents):
        """Scout should have markdown=False (raw output for LLM parsing)."""
        assert agents["scout"].markdown is False

    def test_validation_and_fallback_instructions(self, agents):
        """Scout instructions must contain recon and graph recording directives."""
        scout = agents["scout"]
        instructions_str = " ".join(scout.instructions)
        assert "akg_add_service" in instructions_str
        assert "akg_add_credential" in instructions_str


# ---------------------------------------------------------------------------
# Coder Agent
# ---------------------------------------------------------------------------

class TestCoderAgent:

    EXPECTED_TOOLS = {
        "msf_trigger_exploit_auto",
        "msf_search_modules",
        "msf_get_module_info",
        "msf_get_best_payload",
        "msf_trigger_exploit",
        "msf_trigger_local_exploit",
        "msf_execute_scanner",
        "msf_login",
        "execute_python_code",
        "get_network_environment",
        "get_lhost_for_target",
        "akg_record_exploit",
        "akg_restore_sessions",
        "akg_add_credential",
    }

    def test_has_all_expected_tools(self, agents):
        """Coder must have the expected exploit automation tools."""
        coder = agents["coder"]
        names = _tool_names(coder)
        missing = self.EXPECTED_TOOLS - names
        assert not missing, f"Coder is missing tools: {missing}"

    def test_does_not_have_recon_tools(self, agents):
        """Coder must NOT have Scout-only reconnaissance tools."""
        coder = agents["coder"]
        names = _tool_names(coder)
        forbidden = {"nmap_scan", "curl_request", "get_network_interfaces"}
        present = forbidden & names
        assert not present, f"Coder has forbidden recon tools: {present}"

    def test_does_not_have_post_exploit_command_tools(self, agents):
        """Coder must NOT have post-exploitation command execution tools."""
        coder = agents["coder"]
        names = _tool_names(coder)
        forbidden = {"msf_session_command", "msf_add_route", "msf_discover_hosts"}
        present = forbidden & names
        assert not present, f"Coder has forbidden post-exploit tools: {present}"

    def test_name_is_coder(self, agents):
        """Agent name must be 'Coder'."""
        assert agents["coder"].name == "Coder"

    def test_markdown_disabled(self, agents):
        """Coder should have markdown=False."""
        assert agents["coder"].markdown is False

    def test_anti_hallucination_instructions(self, agents):
        """Coder instructions must explicitly forbid guessing modules/options and require search/module info."""
        coder = agents["coder"]
        instructions_str = " ".join(coder.instructions)
        assert "guess" in instructions_str.lower()
        assert "msf_search_modules" in instructions_str
        assert "msf_trigger_exploit_auto" in instructions_str


# ---------------------------------------------------------------------------
# PostExploiter Agent
# ---------------------------------------------------------------------------

class TestPostExploiterAgent:

    EXPECTED_TOOLS = {
        "msf_session_command",
        "msf_add_route",
        "msf_discover_hosts",
        "msf_upgrade_shell_to_meterpreter",
        "msf_trigger_local_exploit",
        "msf_search_modules",
        "msf_get_module_info",
        "akg_add_interface",
        "akg_add_credential",
        "akg_add_pivot",
        "akg_add_host",
        "akg_add_subnet",
        "akg_restore_sessions",
        "akg_get_context",
    }

    def test_has_all_expected_tools(self, agents):
        """PostExploiter must have all post-exploitation tools."""
        pe = agents["post_exploit"]
        names = _tool_names(pe)
        missing = self.EXPECTED_TOOLS - names
        assert not missing, f"PostExploiter is missing tools: {missing}"

    def test_does_not_have_remote_exploit_tools(self, agents):
        """PostExploiter must NOT have remote exploit triggering tools."""
        pe = agents["post_exploit"]
        names = _tool_names(pe)
        forbidden = {"msf_trigger_exploit", "msf_trigger_exploit_auto", "nmap_scan", "curl_request"}
        present = forbidden & names
        assert not present, f"PostExploiter has forbidden tools: {present}"

    def test_name_is_postexploiter(self, agents):
        """Agent name must be 'PostExploiter'."""
        assert agents["post_exploit"].name == "PostExploiter"

    def test_markdown_disabled(self, agents):
        """PostExploiter should have markdown=False."""
        assert agents["post_exploit"].markdown is False

    def test_validation_and_fallback_instructions(self, agents):
        """PostExploiter instructions must contain session validation directives."""
        pe = agents["post_exploit"]
        instructions_str = " ".join(pe.instructions)
        assert "session_id" in instructions_str.lower()
        assert "akg_add_credential" in instructions_str


# ---------------------------------------------------------------------------
# Orchestrator Team
# ---------------------------------------------------------------------------

class TestOrchestratorTeam:

    EXPECTED_TOOLS = {
        "akg_set_campaign",
        "akg_list_campaigns",
        "akg_get_current_campaign",
        "akg_restore_sessions",
        "akg_log_decision",
        "akg_get_context",
        "akg_get_next_targets",
        "akg_add_host",
        "akg_add_subnet",
        "akg_set_phase_status",
        "orchestrator_discover_subnet",
    }

    def test_has_all_expected_tools(self, agents):
        """Orchestrator must have all strategic AKG and campaign tools."""
        orch = agents["orchestrator"]
        names = _tool_names(orch)
        missing = self.EXPECTED_TOOLS - names
        assert not missing, f"Orchestrator is missing tools: {missing}"

    def test_has_three_member_agents(self, agents):
        """Orchestrator team must have exactly 3 members."""
        team = agents["orchestrator"]
        members = getattr(team, "members", []) or []
        assert len(members) == 3, f"Expected 3 members, got {len(members)}"

    def test_member_names_correct(self, agents):
        """Orchestrator members must be Scout, Coder, and PostExploiter."""
        team = agents["orchestrator"]
        members = getattr(team, "members", []) or []
        member_names = {getattr(m, "name", None) for m in members}
        expected = {"Scout", "Coder", "PostExploiter"}
        assert expected == member_names, (
            f"Unexpected member names: {member_names}. Expected: {expected}"
        )

    def test_has_model(self, agents):
        """Orchestrator team must have a model configured."""
        team = agents["orchestrator"]
        assert team.model is not None

    def test_has_session_storage(self, agents):
        """Orchestrator must have persistent storage configured (SqliteDb)."""
        team = agents["orchestrator"]
        db = getattr(team, "db", None) or getattr(team, "storage", None)
        assert db is not None, "Orchestrator has no persistent session storage configured"

    def test_history_enabled(self, agents):
        """Orchestrator must have history-in-context enabled."""
        team = agents["orchestrator"]
        assert getattr(team, "add_history_to_context", False) is True

    def test_team_history_not_bloating_stateless_members(self, agents):
        """Team history should not be shared to stateless member workers."""
        team = agents["orchestrator"]
        assert getattr(team, "add_team_history_to_members", False) is False

    def test_num_history_runs_positive(self, agents):
        """num_history_runs must be a positive integer."""
        team = agents["orchestrator"]
        runs = getattr(team, "num_history_runs", 0)
        assert isinstance(runs, int) and runs > 0

    def test_markdown_enabled(self, agents):
        """Orchestrator team output should have markdown=True for final reports."""
        team = agents["orchestrator"]
        assert team.markdown is True

    def test_cve_search_and_anti_hallucination_instructions(self, agents):
        """Orchestrator instructions must mandate passing verified evidence and forbid guessing."""
        team = agents["orchestrator"]
        instructions_str = " ".join(team.instructions)
        assert "guess" in instructions_str.lower()
        assert "akg_set_phase_status" in instructions_str
