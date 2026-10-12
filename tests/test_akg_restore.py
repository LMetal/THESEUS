import json
from unittest.mock import MagicMock, patch
import core.coder_tools
import core.postexploit_tools
from core.knowledge_graph import AttackGraph, GraphNode, GraphEdge


def test_akg_restore_sessions_success_order_and_routes(tmp_path):
    g = AttackGraph(campaign_id="test-restore", campaign_dir=str(tmp_path))

    # Add two ExploitStep nodes in chronological order
    node1 = GraphNode(
        id="exploit-1",
        type="ExploitStep",
        label="Session 1",
        source="tool",
        discovered_at="2026-09-01T10:00:00Z",
        properties={
            "session_id": 1,
            "port": 8080,
            "exploit_module": "exploit/multi/http/exp1",
            "payload": "linux/meterpreter/reverse_tcp",
            "lhost": "192.168.0.2",
            "extra_options": {"TARGETURI": "/app"},
        }
    )
    g.add_node(node1)
    g.add_edge(GraphEdge(
        id="e1-comp", type="COMPROMISES", from_node="exploit-1", to_node="host-192.168.10.2", source="tool", properties={}
    ))
    g.add_node(GraphNode(
        id="subnet-10.10.1.0_24",
        type="Subnet",
        label="10.10.1.0/24",
        source="tool",
        properties={"cidr": "10.10.1.0/24"}
    ))
    g.add_edge(GraphEdge(
        id="e1-pivot", type="PIVOTS_INTO", from_node="exploit-1", to_node="subnet-10.10.1.0_24", source="tool", properties={"via_session_id": 1}
    ))

    node2 = GraphNode(
        id="exploit-2",
        type="ExploitStep",
        label="Session 2",
        source="tool",
        discovered_at="2026-09-01T10:15:00Z",
        properties={
            "session_id": 2,
            "port": 445,
            "exploit_module": "exploit/linux/samba/exp2",
            "payload": "cmd/unix/interact",
            "lhost": "192.168.0.2",
            "extra_options": {"SMB_SHARE_NAME": "myshare"},
        }
    )
    g.add_node(node2)
    g.add_edge(GraphEdge(
        id="e2-comp", type="COMPROMISES", from_node="exploit-2", to_node="host-10.10.1.3", source="tool", properties={}
    ))

    call_order = []

    def mock_trigger(module_path, rhosts, rport, payload, lhost, extra_options):
        call_order.append((module_path, rhosts, rport, payload, lhost, extra_options))
        sid = 10 if "exp1" in module_path else 11
        return json.dumps({"status": "success", "session_id": sid, "session_details": {"type": "meterpreter"}})

    mock_add_route = MagicMock()

    with patch("core.akg_tools._g", return_value=g), \
         patch("core.coder_tools.msf_trigger_exploit", side_effect=mock_trigger), \
         patch("core.postexploit_tools.msf_add_route", mock_add_route), \
         patch("time.sleep"):

        from core.akg_tools import akg_restore_sessions
        out = akg_restore_sessions()

    # Verify chronological order
    assert len(call_order) == 2
    assert call_order[0][0] == "exploit/multi/http/exp1"
    assert call_order[0][1] == "192.168.10.2"
    assert call_order[0][2] == 8080
    assert call_order[0][5] == {"TARGETURI": "/app"}

    assert call_order[1][0] == "exploit/linux/samba/exp2"
    assert call_order[1][1] == "10.10.1.3"
    assert call_order[1][2] == 445
    assert call_order[1][5] == {"SMB_SHARE_NAME": "myshare"}

    # Verify route was added for the first exploit pivot
    mock_add_route.assert_called_once_with(session_id=10, subnet="10.10.1.0", netmask="255.255.255.0")
    assert "All exploit steps restored successfully" in out


def test_akg_restore_sessions_aborts_on_failure(tmp_path):
    g = AttackGraph(campaign_id="test-restore-fail", campaign_dir=str(tmp_path))

    node1 = GraphNode(
        id="exploit-1",
        type="ExploitStep",
        label="Session 1",
        source="tool",
        discovered_at="2026-09-01T10:00:00Z",
        properties={
            "session_id": 1,
            "port": 8080,
            "exploit_module": "exploit/multi/http/exp1",
            "target_ip": "192.168.10.2",
        }
    )
    node2 = GraphNode(
        id="exploit-2",
        type="ExploitStep",
        label="Session 2",
        source="tool",
        discovered_at="2026-09-01T10:15:00Z",
        properties={
            "session_id": 2,
            "port": 445,
            "exploit_module": "exploit/linux/samba/exp2",
            "target_ip": "10.10.1.3",
        }
    )
    g.add_node(node1)
    g.add_node(node2)

    call_count = 0

    def mock_trigger(module_path, rhosts, rport, payload, lhost, extra_options):
        nonlocal call_count
        call_count += 1
        return json.dumps({"status": "failed", "message": "Connection refused"})

    with patch("core.akg_tools._g", return_value=g), \
         patch("core.coder_tools.msf_trigger_exploit", side_effect=mock_trigger), \
         patch("time.sleep"):

        from core.akg_tools import akg_restore_sessions
        out = akg_restore_sessions()

    # Exploit 1 failed, so it must halt immediately and NOT execute exploit 2
    assert call_count == 1
    assert "Aborting restore sequence" in out
    assert "FAILED attempt at step 1" in out
