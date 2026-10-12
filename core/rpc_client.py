# rpc_client.py
import time
import subprocess
import requests
import msgpack
import urllib3
from urllib3.util import Retry
from requests.adapters import HTTPAdapter

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from config import MSF_HOST, MSF_PORT, MSF_USER, MSF_PASS


class MetasploitRPCClient:
    def __init__(self):
        self.url = f"https://{MSF_HOST}:{MSF_PORT}/api/"
        self.token = None
        self._session = self._init_session()
        self._consecutive_failures = 0
        self._login()

    def _init_session(self) -> requests.Session:
        session = requests.Session()
        retries = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=[500, 502, 503, 504],
            raise_on_status=False
        )
        adapter = HTTPAdapter(max_retries=retries, pool_connections=10, pool_maxsize=20)
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        return session

    def _login(self, timeout: int = 15) -> bool:
        payload = msgpack.packb(["auth.login", MSF_USER, MSF_PASS])
        headers = {"Content-Type": "binary/message-pack"}
        try:
            res = self._session.post(self.url, data=payload, headers=headers, verify=False, timeout=timeout)
            if res.status_code == 200:
                result = msgpack.unpackb(res.content, raw=False, strict_map_key=False)
                result = {(k.decode() if isinstance(k, bytes) else k):
                          (v.decode() if isinstance(v, bytes) else v)
                          for k, v in result.items()}
                if result.get("result") == "success":
                    self.token = result.get("token")
                    self._consecutive_failures = 0
                    print(f"[+] Handshake completed! Token acquired: {self.token[:10]}...")
                    return True
                else:
                    print(f"[-] MSF Authentication error. Server response: {result}")
            else:
                print(f"[-] MSF RPC server responded with HTTP status code: {res.status_code}")
        except Exception as e:
            print(f"[-] Connection error to msfrpcd: {e}")

        self.token = None
        return False

    def ensure_healthy(self, max_wait: int = 30, auto_restart: bool = True) -> bool:
        """
        Actively checks if msfrpcd is responsive and healthy.
        If unresponsive and auto_restart is True, triggers a docker restart and polls until online.
        """
        start_time = time.time()
        while time.time() - start_time < max_wait:
            if self._login(timeout=5):
                return True
            time.sleep(1.5)

        if auto_restart:
            print("[!] msfrpcd is unresponsive. Triggering self-healing docker restart on msf-rpc...")
            try:
                subprocess.run(["docker", "restart", "msf-rpc"], capture_output=True, timeout=15)
                # Re-initialize session after docker container restart to clear stale SSL sockets
                self._session = self._init_session()
            except Exception as e:
                print(f"[-] Failed to restart msf-rpc container: {e}")

            # Poll for readiness after restart
            restart_wait = time.time()
            while time.time() - restart_wait < 35:
                time.sleep(2.0)
                if self._login(timeout=5):
                    print("[+] msfrpcd self-healing successful! Ready for execution.")
                    return True

        return False

    @property
    def is_connected(self) -> bool:
        return self.token is not None

    def call(self, method, *args, timeout: int = 60):
        # Ensure authenticated token
        if not self.token:
            if not self._login(timeout=10):
                if not self.ensure_healthy(max_wait=15, auto_restart=True):
                    return {"error": "Not authenticated to Metasploit RPC (msfrpcd is unreachable)"}

        headers = {"Content-Type": "binary/message-pack"}
        max_attempts = 2

        for attempt in range(max_attempts):
            rpc_args = [method, self.token] + list(args)
            payload = msgpack.packb(rpc_args)

            try:
                res = self._session.post(self.url, data=payload, headers=headers, verify=False, timeout=timeout)
                if res.status_code == 200:
                    raw_data = msgpack.unpackb(res.content, raw=False, strict_map_key=False)
                    decoded = self._decode_bytes(raw_data)
                    self._consecutive_failures = 0

                    # Handle token expiration
                    if isinstance(decoded, dict) and (
                        decoded.get("error_code") == 401 
                        or "token" in str(decoded.get("error_message", "")).lower()
                    ):
                        print("[*] MSF RPC token expired or invalid. Re-authenticating...")
                        self.token = None
                        if self._login(timeout=10):
                            continue
                        else:
                            return {"error": "Authentication token refresh failed"}

                    return decoded
                elif res.status_code == 401:
                    print("[*] MSF RPC returned 401. Re-authenticating...")
                    self.token = None
                    self._login(timeout=10)
                    continue
                else:
                    return {"error": f"HTTP Error {res.status_code}"}

            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
                self._consecutive_failures += 1
                print(f"[-] msfrpcd call '{method}' failed (attempt {attempt+1}/{max_attempts}): {e}")
                self.token = None
                time.sleep(1.0)
                # If repeated failures occur, attempt container recovery
                if self._consecutive_failures >= 3:
                    print("[!] Multiple consecutive RPC timeouts detected. Initiating auto-recovery...")
                    self.ensure_healthy(max_wait=25, auto_restart=True)
                else:
                    self._login(timeout=8)

            except Exception as e:
                return {"error": str(e)}

        return {"error": f"RPC call '{method}' timed out or failed after {max_attempts} attempts"}

    def _decode_bytes(self, val):
        """Recursively decodes bytes to strings (UTF-8), preserving binary data when appropriate."""
        if isinstance(val, dict):
            return {self._decode_bytes(k): self._decode_bytes(v) for k, v in val.items()}
        elif isinstance(val, list):
            return [self._decode_bytes(x) for x in val]
        elif isinstance(val, bytes):
            try:
                return val.decode("utf-8")
            except UnicodeDecodeError:
                return val
        return val


# ── Lazy Singleton ────────────────────────────────────────────────────────────
_msf_client_instance: MetasploitRPCClient | None = None

def get_msf_client() -> MetasploitRPCClient:
    global _msf_client_instance
    if _msf_client_instance is None:
        _msf_client_instance = MetasploitRPCClient()
    return _msf_client_instance


class _LazyClient:
    """Transparent proxy that instantiates MetasploitRPCClient only on first use."""
    def __getattr__(self, name):
        return getattr(get_msf_client(), name)

    def call(self, *args, **kwargs):
        return get_msf_client().call(*args, **kwargs)

    @property
    def is_connected(self):
        return get_msf_client().is_connected

msf_client = _LazyClient()
