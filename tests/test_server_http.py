from http import HTTPStatus
import http.client
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from proxmox_mcp.config import load_config
from proxmox_mcp.server import create_server


class ServerHttpTests(unittest.TestCase):
    def _make_config(self, root: Path):
        config_path = root / "config.toml"
        config_path.write_text(
            """
[server]
host = "127.0.0.1"
port = 0

[tls]
enabled = false
cert_file = "./tls/server.crt"
key_file = "./tls/server.key"
client_ca_file = "./tls/ca.crt"
require_client_cert = false

[remote]
mode = "open"
approval_store = "./state/approvals.json"

[audit]
file = "./state/audit.jsonl"

[proxmox]
base_url = "https://127.0.0.1:8006/api2/json"
token_id = "mcp@pam!default"
token_secret = "secret"
verify_tls = true

[profiles.readonly]
capabilities = ["inventory.read"]

[clients.ops_laptop]
token = "abc"
profile = "readonly"
""".strip()
            + "\n",
            encoding="utf-8",
        )
        return load_config(config_path)

    def test_initialized_notification_keeps_connection_open(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            config = self._make_config(root)
            httpd = create_server(config)
            httpd.daemon_threads = True
            server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
            server_thread.start()
            conn: http.client.HTTPConnection | None = None
            try:
                host, port = httpd.server_address
                conn = http.client.HTTPConnection(host, port, timeout=5)
                headers = {
                    "Authorization": "Bearer abc",
                    "X-Client-Id": "ops_laptop",
                    "Content-Type": "application/json",
                    "Connection": "keep-alive",
                }

                conn.request(
                    "POST",
                    "/mcp",
                    body=json.dumps(
                        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
                    ),
                    headers=headers,
                )
                init_resp = conn.getresponse()
                self.assertEqual(init_resp.status, HTTPStatus.OK)
                init_resp.read()
                first_sock = conn.sock

                conn.request(
                    "POST",
                    "/mcp",
                    body=json.dumps(
                        {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}
                    ),
                    headers=headers,
                )
                notif_resp = conn.getresponse()
                self.assertEqual(notif_resp.status, HTTPStatus.NO_CONTENT)
                self.assertEqual(notif_resp.read(), b"")

                conn.request(
                    "POST",
                    "/mcp",
                    body=json.dumps({"jsonrpc": "2.0", "id": 2, "method": "ping", "params": {}}),
                    headers=headers,
                )
                ping_resp = conn.getresponse()
                self.assertEqual(ping_resp.status, HTTPStatus.OK)
                ping_payload = json.loads(ping_resp.read())
                self.assertEqual(ping_payload["result"], {})

                self.assertIs(conn.sock, first_sock)
            finally:
                if conn is not None:
                    conn.close()
                httpd.shutdown()
                server_thread.join()
                httpd.server_close()
