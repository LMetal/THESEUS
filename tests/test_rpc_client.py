# tests/test_rpc_client.py
"""
Unit tests for core/rpc_client.py (MetasploitRPCClient).

These tests verify the RPC communication logic using mocked HTTP responses
from msfrpcd — no real Metasploit daemon required.
"""
import json
import pytest
import msgpack
from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _pack_response(data: dict) -> bytes:
    """Encode a dict as msgpack bytes (mimics msfrpcd wire format)."""
    return msgpack.packb(data, use_bin_type=True)


def _make_http_response(data: dict, status_code: int = 200):
    """Build a mock requests.Response from a dict payload."""
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.content = _pack_response(data)
    return mock_resp


# ---------------------------------------------------------------------------
# MetasploitRPCClient
# ---------------------------------------------------------------------------

class TestMetasploitRPCClient:

    def _make_client(self, login_response=None):
        """Instantiate a MetasploitRPCClient with a mocked login response."""
        login_data = login_response or {"result": "success", "token": "abc123testtoken"}

        with patch("requests.post", return_value=_make_http_response(login_data)):
            from core.rpc_client import MetasploitRPCClient
            return MetasploitRPCClient()

    def test_successful_login_stores_token(self):
        """A successful auth.login response stores the token."""
        client = self._make_client({"result": "success", "token": "mytoken123"})
        assert client.token == "mytoken123"
        assert client.is_connected is True

    def test_failed_login_stores_no_token(self):
        """A failed auth.login response results in no token stored."""
        client = self._make_client({"result": "failed", "error": "Invalid credentials"})
        assert client.token is None
        assert client.is_connected is False

    def test_http_error_on_login_stores_no_token(self):
        """Non-200 HTTP response during login results in no token."""
        mock_resp = MagicMock()
        mock_resp.status_code = 503
        mock_resp.content = b""

        with patch("requests.post", return_value=mock_resp):
            from core.rpc_client import MetasploitRPCClient
            client = MetasploitRPCClient()

        assert client.token is None
        assert client.is_connected is False

    def test_network_error_on_login_handled(self):
        """Network-level exceptions during login are caught gracefully."""
        with patch("requests.post", side_effect=Exception("Connection refused")):
            from core.rpc_client import MetasploitRPCClient
            client = MetasploitRPCClient()

        assert client.token is None

    def test_call_returns_error_when_not_authenticated(self):
        """Calling any RPC method when not authenticated returns an error dict."""
        with patch("requests.post", return_value=_make_http_response({"result": "failed"})):
            client = self._make_client({"result": "failed"})
            result = client.call("module.search", "vsftpd")
            assert "error" in result

    def test_call_sends_token_as_second_argument(self):
        """Token is always injected as the second element of the RPC args."""
        client = self._make_client({"result": "success", "token": "tok123"})

        response_data = {"modules": ["exploit/unix/ftp/vsftpd_234_backdoor"]}
        mock_resp = _make_http_response(response_data)

        with patch("requests.post", return_value=mock_resp) as mock_post:
            client.call("module.exploits")

        # The payload sent should be msgpack of ["module.exploits", "tok123"]
        sent_payload = mock_post.call_args[1]["data"]
        decoded = msgpack.unpackb(sent_payload, raw=False)
        assert decoded[0] == "module.exploits"
        assert decoded[1] == "tok123"

    def test_call_deserializes_msgpack_response(self):
        """call() correctly deserializes msgpack-encoded responses."""
        client = self._make_client({"result": "success", "token": "tok123"})

        payload = {"job_id": 42, "status": "ok"}
        with patch("requests.post", return_value=_make_http_response(payload)):
            result = client.call("module.execute", "auxiliary", "auxiliary/scanner/portscan/tcp", {})

        assert result["job_id"] == 42
        assert result["status"] == "ok"

    def test_call_returns_error_on_http_failure(self):
        """Non-200 HTTP status from RPC endpoint returns an error dict."""
        client = self._make_client({"result": "success", "token": "tok123"})

        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.content = b""

        with patch("requests.post", return_value=mock_resp):
            result = client.call("module.exploits")

        assert "error" in result
        assert "500" in result["error"]

    def test_call_returns_error_on_network_exception(self):
        """Network exceptions during RPC calls are caught and returned as error."""
        client = self._make_client({"result": "success", "token": "tok123"})

        with patch("requests.post", side_effect=Exception("Timeout")):
            result = client.call("session.list")

        assert "error" in result

    def test_call_reauthenticates_on_expired_token(self):
        """If the RPC server returns a token expiration error (401), the client re-authenticates and retries."""
        client = self._make_client({"result": "success", "token": "old_token"})

        # Mock responses:
        # First call return: 401 error
        # Re-login return: new token "new_token"
        # Second call return: success data
        error_resp = _make_http_response({"error": True, "error_code": 401, "error_message": "Invalid Authentication Token"})
        login_resp = _make_http_response({"result": "success", "token": "new_token"})
        success_resp = _make_http_response({"modules": ["exploit/unix/ftp/vsftpd_234_backdoor"]})

        mock_responses = [error_resp, login_resp, success_resp]

        with patch("requests.post", side_effect=mock_responses) as mock_post:
            result = client.call("module.exploits")

        # Result should be the success data from the retry
        assert "modules" in result
        assert result["modules"] == ["exploit/unix/ftp/vsftpd_234_backdoor"]
        assert client.token == "new_token"

        # Check call count: 3 requests (failed call, login request, successful retry call)
        assert mock_post.call_count == 3

    def test_decode_bytes_recursively(self):
        """_decode_bytes handles nested dicts, lists, and byte strings."""
        from core.rpc_client import MetasploitRPCClient
        client = self._make_client({"result": "success", "token": "tok"})

        nested = {
            b"key1": b"value1",
            b"key2": [b"item1", b"item2"],
            b"key3": {b"nested_key": b"nested_value"},
        }
        decoded = client._decode_bytes(nested)

        assert decoded["key1"] == "value1"
        assert decoded["key2"] == ["item1", "item2"]
        assert decoded["key3"]["nested_key"] == "nested_value"


# ---------------------------------------------------------------------------
# Lazy Singleton
# ---------------------------------------------------------------------------

class TestLazyClientSingleton:

    def test_lazy_client_instantiates_on_first_use(self):
        """_LazyClient should not instantiate MetasploitRPCClient until first call."""
        import core.rpc_client as rpc_mod

        # Reset singleton
        original = rpc_mod._msf_client_instance
        rpc_mod._msf_client_instance = None

        login_data = {"result": "success", "token": "lazytoken"}
        with patch("requests.post", return_value=_make_http_response(login_data)):
            # Access msf_client.is_connected to trigger instantiation
            _ = rpc_mod.msf_client.is_connected

        assert rpc_mod._msf_client_instance is not None
        rpc_mod._msf_client_instance = original  # restore

    def test_lazy_client_reuses_same_instance(self):
        """get_msf_client() returns the same instance on repeated calls."""
        import core.rpc_client as rpc_mod

        original = rpc_mod._msf_client_instance
        rpc_mod._msf_client_instance = None

        login_data = {"result": "success", "token": "singletontest"}
        with patch("requests.post", return_value=_make_http_response(login_data)):
            inst1 = rpc_mod.get_msf_client()
            inst2 = rpc_mod.get_msf_client()

        assert inst1 is inst2
        rpc_mod._msf_client_instance = original  # restore
