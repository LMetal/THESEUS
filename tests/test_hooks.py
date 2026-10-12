import pytest
from core.hooks import (
    attack_surface_tool_hook,
    get_attack_surface_calls,
    get_attack_surface_history,
    reset_attack_surface_counter,
)
from core.agents import scout_agent, coder_agent, post_exploit_agent, orchestrator_team


@pytest.fixture(autouse=True)
def clean_counter():
    reset_attack_surface_counter()
    yield
    reset_attack_surface_counter()


class TestAttackSurfaceHook:

    def test_initial_counter_is_zero(self):
        assert get_attack_surface_calls() == 0
        assert get_attack_surface_history() == []

    @pytest.mark.anyio
    async def test_hook_increments_for_attack_surface_tools(self):
        def dummy_nmap(target):
            return "nmap output"

        res = await attack_surface_tool_hook("nmap_scan", dummy_nmap, {"target": "192.168.1.10"})
        assert res == "nmap output"
        assert get_attack_surface_calls() == 1

        history = get_attack_surface_history()
        assert len(history) == 1
        assert history[0]["tool"] == "nmap_scan"
        assert history[0]["args"] == {"target": "192.168.1.10"}

    @pytest.mark.anyio
    async def test_hook_ignores_akg_tools(self):
        def dummy_akg(ip, hostname):
            return "host recorded"

        res = await attack_surface_tool_hook("akg_add_host", dummy_akg, {"ip": "192.168.1.10", "hostname": "target"})
        assert res == "host recorded"
        # Counter must NOT increment for akg_ tools
        assert get_attack_surface_calls() == 0
        assert len(get_attack_surface_history()) == 0

    def test_hook_attached_to_all_agents_and_team(self):
        assert scout_agent.tool_hooks == [attack_surface_tool_hook]
        assert coder_agent.tool_hooks == [attack_surface_tool_hook]
        assert post_exploit_agent.tool_hooks == [attack_surface_tool_hook]
        assert orchestrator_team.tool_hooks == [attack_surface_tool_hook]

    @pytest.mark.anyio
    async def test_multiple_tools_tracking(self):
        def dummy_tool(**kwargs):
            return "ok"

        await attack_surface_tool_hook("nmap_scan", dummy_tool, {"target": "10.0.0.1"})
        await attack_surface_tool_hook("akg_add_service", dummy_tool, {"service": "http"})
        await attack_surface_tool_hook("curl_request", dummy_tool, {"url": "http://10.0.0.1"})
        await attack_surface_tool_hook("akg_record_exploit", dummy_tool, {"session_id": 1})
        await attack_surface_tool_hook("msf_trigger_exploit_auto", dummy_tool, {"module_path": "exploit/test"})
        await attack_surface_tool_hook("execute_python_code", dummy_tool, {"code": "print(1)"})

        # Out of 6 calls: 4 are attack tools, 2 are AKG tools
        assert get_attack_surface_calls() == 4
        history = get_attack_surface_history()
        assert [h["tool"] for h in history] == [
            "nmap_scan",
            "curl_request",
            "msf_trigger_exploit_auto",
            "execute_python_code",
        ]
