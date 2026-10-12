# tests/test_akg_service_recon.py
import json
import pytest
from unittest.mock import patch, MagicMock
from core.knowledge_graph import AttackGraph, init_graph, get_graph
from core.akg_tools import akg_add_service
from core.coder_tools import _resolve_exploit_parameters, msf_trigger_exploit


@pytest.fixture
def clean_graph(tmp_path):
    """Initializes a fresh in-memory AttackGraph backed by a temporary directory."""
    g = AttackGraph(campaign_id="test-recon", campaign_dir=str(tmp_path))
    with patch("core.knowledge_graph._active_graph", g), \
         patch("core.akg_tools._g", return_value=g), \
         patch("core.coder_tools._get_akg_service_properties", side_effect=lambda ip, port: (
             g._nodes.get(f"svc-{ip}-{port}").properties if g._nodes.get(f"svc-{ip}-{port}") else {}
         )):
        yield g


class TestAKGServiceSchemaExtension:

    def test_add_service_stores_discovered_paths_and_attributes(self, clean_graph):
        node = clean_graph.add_service(
            host_ip="172.32.4.20",
            port=80,
            service_name="http",
            banner="Apache/2.4.7 (Ubuntu)",
            cves=["CVE-2014-6271"],
            discovered_paths=["/cgi-bin/vulnerable", "/cgi-bin/test.cgi", "/index.html"],
            attributes={"server_headers": {"Server": "Apache"}, "detected_methods": ["GET", "POST"]},
            ssl=False,
            target_os="linux",
            target_arch="x64",
        )
        assert node.properties["discovered_paths"] == ["/cgi-bin/vulnerable", "/cgi-bin/test.cgi", "/index.html"]
        assert node.properties["attributes"]["server_headers"]["Server"] == "Apache"
        assert node.properties["web_path"] == "/cgi-bin/vulnerable"
        assert node.properties["target_os"] == "linux"
        assert node.properties["target_arch"] == "x64"

    def test_add_service_merges_incrementally(self, clean_graph):
        # First call by initial recon
        clean_graph.add_service(
            host_ip="172.32.4.20",
            port=80,
            service_name="http",
            banner="Apache/2.4.7",
            web_path="/",
        )
        svc_nid = "svc-172.32.4.20-80"
        assert clean_graph._nodes[svc_nid].properties["web_path"] == "/"

        # Second call after CGI discovery
        clean_graph.add_service(
            host_ip="172.32.4.20",
            port=80,
            discovered_paths=["/cgi-bin/vulnerable"],
            cves=["CVE-2014-6271"],
            attributes={"cgi_found": True},
        )
        node = clean_graph._nodes[svc_nid]
        assert "/cgi-bin/vulnerable" in node.properties["discovered_paths"]
        assert node.properties["cves"] == ["CVE-2014-6271"]
        assert node.properties["attributes"]["cgi_found"] is True

    def test_akg_add_service_tool_wrapper(self, clean_graph):
        res = akg_add_service(
            host_ip="172.31.0.5",
            port=8080,
            service_name="http",
            banner="Apache-Coyote/1.1",
            cves="CVE-2017-5638",
            discovered_paths="/showcase.action, /login.action",
            attributes={"framework": "struts2"},
            target_os="linux",
            target_arch="x64",
        )
        assert "[AKG] Service registered: svc-172.31.0.5-8080" in res
        node = clean_graph._nodes["svc-172.31.0.5-8080"]
        assert "/showcase.action" in node.properties["discovered_paths"]
        assert node.properties["attributes"]["framework"] == "struts2"


class TestCoderParameterResolution:

    @patch("core.coder_tools.msf_client")
    def test_resolve_cgi_shellshock_targeturi(self, mock_msf, clean_graph):
        # Register CGI vulnerable paths in AKG
        clean_graph.add_service(
            host_ip="172.32.4.20",
            port=80,
            service_name="http",
            banner="Apache/2.4.7",
            discovered_paths=["/index.html", "/cgi-bin/vulnerable", "/cgi-bin/test.cgi"],
            target_os="linux",
            target_arch="x64",
        )

        mock_msf.call.side_effect = lambda method, *args: {
            "module.options": {
                "TARGETURI": {"required": True, "default": "/cgi-bin/hi"},
                "CMD": {"required": False, "default": ""},
            },
            "module.info": {
                "targets": {0: "Automatic", 1: "Linux x86", 2: "Linux x86_64"},
            }
        }.get(method, {})

        resolved = _resolve_exploit_parameters(
            module_path="exploit/multi/http/apache_mod_cgi_bash_env_exec",
            rhosts="172.32.4.20",
            rport=80,
        )

        assert resolved.get("TARGETURI") == "/cgi-bin/vulnerable"
        assert resolved.get("TARGET") == "2"  # matches Linux x86_64 for linux/x64

    @patch("core.coder_tools.msf_client")
    def test_resolve_struts_targeturi_and_ssl(self, mock_msf, clean_graph):
        clean_graph.add_service(
            host_ip="172.31.0.5",
            port=8443,
            service_name="https",
            banner="Apache Struts",
            discovered_paths=["/index.jsp", "/showcase.action"],
            ssl=True,
        )

        mock_msf.call.side_effect = lambda method, *args: {
            "module.options": {
                "TARGETURI": {"required": True, "default": "/"},
                "SSL": {"required": False, "default": False},
            },
            "module.info": {"targets": {0: "Universal"}}
        }.get(method, {})

        resolved = _resolve_exploit_parameters(
            module_path="exploit/multi/http/struts2_content_type_ognl",
            rhosts="172.31.0.5",
            rport=8443,
        )

        assert resolved.get("TARGETURI") == "/showcase.action"
        assert resolved.get("SSL") == "true"

    @patch("core.coder_tools.msf_client")
    def test_explicit_extra_options_override_resolved_params(self, mock_msf, clean_graph):
        clean_graph.add_service(
            host_ip="172.32.4.20",
            port=80,
            discovered_paths=["/cgi-bin/vulnerable"],
        )

        mock_msf.call.side_effect = lambda method, *args: {
            "module.options": {"TARGETURI": {"required": True, "default": "/"}},
            "module.info": {}
        }.get(method, {})

        resolved = _resolve_exploit_parameters(
            module_path="exploit/multi/http/apache_mod_cgi_bash_env_exec",
            rhosts="172.32.4.20",
            rport=80,
            extra_options={"TARGETURI": "/custom/path.cgi"},
        )

        # TARGETURI should not be in resolved if already present in extra_options
        assert "TARGETURI" not in resolved

    @patch("core.coder_tools.msf_client")
    def test_resolve_phpmailer_web_root(self, mock_msf, clean_graph):
        clean_graph.add_service(
            host_ip="172.32.3.15",
            port=80,
            service_name="http",
            banner="Apache/2.4.10 (Debian)",
            discovered_paths=["/"],
        )

        mock_msf.call.side_effect = lambda method, *args: {
            "module.options": {
                "TARGETURI": {"required": True, "default": "/"},
                "WEB_ROOT": {"required": True, "default": "/var/www"},
            },
            "module.info": {"targets": {0: "PHPMailer <5.2.18"}}
        }.get(method, {})

        resolved = _resolve_exploit_parameters(
            module_path="exploit/multi/http/phpmailer_arg_injection",
            rhosts="172.32.3.15",
            rport=80,
        )

        assert resolved.get("WEB_ROOT") == "/www"

    def test_cgi_payload_selection_prefers_stable_shell(self):
        from core.coder_tools import _smart_select_payload
        compat = [
            "linux/x86/meterpreter/bind_tcp",
            "linux/x86/meterpreter/reverse_tcp",
            "linux/x86/shell_bind_tcp",
            "cmd/unix/bind_netcat_gaping",
        ]
        res = _smart_select_payload(
            compat_payloads=compat,
            module_path="exploit/multi/http/apache_mod_cgi_bash_env_exec",
            target_os="linux",
            target_arch="x86",
        )
        # For CGI exploits, stable bind/stageless shell payloads should be top candidates
        assert res["suggested_payload"] in ["cmd/unix/bind_netcat_gaping", "linux/x86/shell_bind_tcp"]
        assert res["scoring_hints"]["is_cgi_exploit"] is True


class TestAKGNodeAndEventDeletion:

    def test_delete_service_node_removes_edges(self, clean_graph):
        clean_graph.add_host("172.32.4.20")
        clean_graph.add_service(host_ip="172.32.4.20", port=80, service_name="http")

        assert "svc-172.32.4.20-80" in clean_graph._nodes
        assert "e-172.32.4.20-runs-80" in clean_graph._edges

        success = clean_graph.delete_node("svc-172.32.4.20-80")
        assert success is True
        assert "svc-172.32.4.20-80" not in clean_graph._nodes
        assert "e-172.32.4.20-runs-80" not in clean_graph._edges

    def test_delete_exploit_node_resets_host_status(self, clean_graph):
        clean_graph.add_host("172.32.4.20")
        clean_graph.add_service(host_ip="172.32.4.20", port=80, service_name="http")
        exp_node = clean_graph.add_exploit_step(
            session_id=1,
            host_ip="172.32.4.20",
            port=80,
            exploit_module="exploit/multi/http/apache_mod_cgi_bash_env_exec",
            payload="linux/x64/meterpreter/reverse_tcp",
            user="www-data",
        )
        host_node = clean_graph._nodes["host-172.32.4.20"]
        host_node.properties["exploit_status"] = "done"
        assert host_node.properties.get("status") == "pwned"

        success = clean_graph.delete_node(exp_node.id)
        assert success is True
        assert exp_node.id not in clean_graph._nodes
        # Host exploit status and node status must be reset to allow re-attack
        assert host_node.properties.get("status") == "alive"
        assert host_node.properties.get("exploit_status") == "pending"

    def test_delete_event_log_entry(self, clean_graph):
        clean_graph.log(
            event_type="decision",
            actor="orchestrator",
            source="model",
            action="exploit_selection",
            target="172.32.4.20:80",
            reasoning="Targeting Apache CGI Shellshock based on scout report",
            result="exploit/multi/http/apache_mod_cgi_bash_env_exec",
        )
        assert len(clean_graph._event_log) == 1
        seq = clean_graph._event_log[0].seq

        success = clean_graph.delete_event(seq)
        assert success is True
        assert len(clean_graph._event_log) == 0


class TestDashboardDeleteEndpoints:

    def test_dashboard_delete_node_api(self, tmp_path):
        from fastapi.testclient import TestClient
        from dashboard import app, CAMPAIGNS_DIR
        import dashboard

        # Set up a test campaign folder
        camp_dir = tmp_path / "test-api-camp"
        camp_dir.mkdir(parents=True, exist_ok=True)
        g = AttackGraph(campaign_id="test-api-camp", campaign_dir=str(tmp_path))
        g.add_host("172.30.0.5")
        g.add_service(host_ip="172.30.0.5", port=80, service_name="http")

        with patch.object(dashboard, "CAMPAIGNS_DIR", tmp_path), \
             patch("dashboard._campaign_path", return_value=camp_dir / "graph.json"):
            client = TestClient(app)

            # Test POST /api/graph/node/delete
            res = client.post("/api/graph/node/delete", json={
                "campaign": "test-api-camp",
                "node_id": "svc-172.30.0.5-80"
            })
            assert res.status_code == 200
            assert res.json()["status"] == "ok"

            # Reload graph from disk to verify persistence
            reloaded = AttackGraph.load_or_create("test-api-camp", campaign_dir=str(tmp_path))
            assert "svc-172.30.0.5-80" not in reloaded._nodes

    def test_dashboard_delete_event_api(self, tmp_path):
        from fastapi.testclient import TestClient
        from dashboard import app
        import dashboard

        camp_dir = tmp_path / "test-event-camp"
        camp_dir.mkdir(parents=True, exist_ok=True)
        g = AttackGraph(campaign_id="test-event-camp", campaign_dir=str(tmp_path))
        g.log(
            event_type="decision",
            actor="orchestrator",
            source="model",
            action="exploit_selection",
            target="172.30.0.5",
            reasoning="Testing deletion of decision",
            result="module_x",
        )
        seq = g._event_log[0].seq

        with patch.object(dashboard, "CAMPAIGNS_DIR", tmp_path), \
             patch("dashboard._campaign_path", return_value=camp_dir / "graph.json"):
            client = TestClient(app)

            res = client.post("/api/graph/event/delete", json={
                "campaign": "test-event-camp",
                "seq": seq
            })
            assert res.status_code == 200
            assert res.json()["status"] == "ok"

            reloaded = AttackGraph.load_or_create("test-event-camp", campaign_dir=str(tmp_path))
            assert len(reloaded._event_log) == 0

    def test_dashboard_update_host_status_api(self, tmp_path):
        from fastapi.testclient import TestClient
        from dashboard import app
        import dashboard

        camp_dir = tmp_path / "test-status-camp"
        camp_dir.mkdir(parents=True, exist_ok=True)
        g = AttackGraph(campaign_id="test-status-camp", campaign_dir=str(tmp_path))
        g.add_host("172.30.0.5")

        with patch.object(dashboard, "CAMPAIGNS_DIR", tmp_path), \
             patch("dashboard._campaign_path", return_value=camp_dir / "graph.json"):
            client = TestClient(app)

            # Update scout_status, exploit_status, postexploit_status
            res = client.post("/api/graph/host/status", json={
                "campaign": "test-status-camp",
                "node_id": "host-172.30.0.5",
                "scout_status": "done",
                "exploit_status": "done",
                "postexploit_status": "done"
            })
            assert res.status_code == 200
            data = res.json()
            assert data["status"] == "ok"
            assert data["properties"]["scout_status"] == "done"
            assert data["properties"]["exploit_status"] == "done"
            assert data["properties"]["postexploit_status"] == "done"
            assert data["properties"]["status"] == "pwned"

            # Reload from disk
            reloaded = AttackGraph.load_or_create("test-status-camp", campaign_dir=str(tmp_path))
            host = reloaded._nodes["host-172.30.0.5"]
            assert host.properties["scout_status"] == "done"
            assert host.properties["exploit_status"] == "done"
            assert host.properties["postexploit_status"] == "done"
            assert host.properties["status"] == "pwned"

            # Update back to pending
            res2 = client.post("/api/graph/host/status", json={
                "campaign": "test-status-camp",
                "ip": "172.30.0.5",
                "exploit_status": "pending"
            })
            assert res2.status_code == 200
            assert res2.json()["properties"]["exploit_status"] == "pending"
            assert res2.json()["properties"]["status"] == "alive"
