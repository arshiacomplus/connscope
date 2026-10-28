from __future__ import annotations

import http.server
import json
import socket
import subprocess
import threading
import time
from typing import Any

from connscope.adapters import resolve_safe_executable, safe_temporary_workspace
from connscope.core import Target

DEFAULT_DIAGNOSTIC_UUID = "23ad3b37-8de4-4e7b-a3e8-e538b30b4f70"

class _DiagnosticHttpHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()

    def do_HEAD(self) -> None:
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()

    def log_message(self, format: str, *args: Any) -> None:
        pass

def _find_safe_ephemeral_port() -> int:
    while True:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            port = int(s.getsockname()[1])
            if port != 10808:
                return port

class LocalDiagnosticHarness:
    def __init__(
        self,
        engine_id: str = "xray",
        client_uuid: str = DEFAULT_DIAGNOSTIC_UUID,
        startup_timeout_s: float = 3.0,
    ) -> None:
        self.engine_id = "xray" if engine_id.lower() == "xray" else "sing_box"
        self.client_uuid = client_uuid
        self.startup_timeout_s = startup_timeout_s
        self.server_port: int = 0
        self.http_port: int = 0
        self._httpd: http.server.HTTPServer | None = None
        self._http_thread: threading.Thread | None = None
        self._server_proc: subprocess.Popen[bytes] | None = None
        self._workspace: Any = None
        self._ws_path: Any = None

    @property
    def target(self) -> Target:
        return Target(host="127.0.0.1", port=self.server_port)

    @property
    def test_url(self) -> str:
        return f"http://127.0.0.1:{self.http_port}/generate_204"

    def _start_http_server(self) -> None:
        port = _find_safe_ephemeral_port()
        self._httpd = http.server.HTTPServer(("127.0.0.1", port), _DiagnosticHttpHandler)
        self.http_port = self._httpd.server_port
        self._http_thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._http_thread.start()

    def _start_engine_server(self) -> None:
        self.server_port = _find_safe_ephemeral_port()
        while self.server_port == self.http_port:
            self.server_port = _find_safe_ephemeral_port()

        exe_name = "xray" if self.engine_id == "xray" else "sing-box"
        exe_path = resolve_safe_executable(exe_name)
        if not exe_path:
            raise RuntimeError(f"Engine binary '{exe_name}' not available for diagnostic harness")

        self._workspace = safe_temporary_workspace(prefix=f"connscope_diag_{self.engine_id}_")
        self._ws_path = self._workspace.__enter__()

        cfg_file = self._ws_path / "server_config.json"

        if self.engine_id == "xray":
            server_cfg = {
                "inbounds": [
                    {
                        "port": self.server_port,
                        "listen": "127.0.0.1",
                        "protocol": "vless",
                        "settings": {
                            "clients": [
                                {
                                    "id": self.client_uuid,
                                    "level": 0,
                                }
                            ],
                            "decryption": "none",
                        },
                    }
                ],
                "outbounds": [
                    {
                        "protocol": "freedom",
                        "settings": {},
                    }
                ],
            }
            cmd = [exe_path, "run", "-c", str(cfg_file)]
        else:
            server_cfg = {
                "inbounds": [
                    {
                        "type": "vless",
                        "tag": "vless-in",
                        "listen": "127.0.0.1",
                        "listen_port": self.server_port,
                        "users": [
                            {
                                "uuid": self.client_uuid,
                            }
                        ],
                    }
                ],
                "outbounds": [
                    {
                        "type": "direct",
                        "tag": "direct",
                    }
                ],
            }
            cmd = [exe_path, "run", "-c", str(cfg_file)]

        with open(cfg_file, "w", encoding="utf-8") as f:
            json.dump(server_cfg, f, indent=2)

        self._server_proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        deadline = time.monotonic() + self.startup_timeout_s
        ready = False
        while time.monotonic() < deadline:
            if self._server_proc.poll() is not None:
                raise RuntimeError(f"Diagnostic server process exited prematurely with code {self._server_proc.returncode}")
            try:
                with socket.create_connection(("127.0.0.1", self.server_port), timeout=0.2):
                    ready = True
                    break
            except (OSError, ConnectionRefusedError):
                time.sleep(0.05)

        if not ready:
            self.close()
            raise TimeoutError(f"Diagnostic server on port {self.server_port} failed to become ready within {self.startup_timeout_s}s")

    def __enter__(self) -> LocalDiagnosticHarness:
        try:
            self._start_http_server()
            self._start_engine_server()
            return self
        except Exception:
            self.close()
            raise

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def close(self) -> None:
        if self._server_proc is not None:
            try:
                self._server_proc.terminate()
                self._server_proc.wait(timeout=2.0)
            except Exception:
                try:
                    self._server_proc.kill()
                except Exception:
                    pass
            self._server_proc = None

        if self._httpd is not None:
            try:
                self._httpd.shutdown()
                self._httpd.server_close()
            except Exception:
                pass
            self._httpd = None

        if self._workspace is not None:
            try:
                self._workspace.__exit__(None, None, None)
            except Exception:
                pass
            self._workspace = None
