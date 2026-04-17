from pathlib import Path
import ssl
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from proxmox_mcp.config import load_config
import proxmox_mcp.server as server_module


class ServerTlsTests(unittest.TestCase):
    def test_optional_client_cert_uses_cert_optional(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            config_path = root / "config.toml"
            tls_dir = root / "tls"
            state_dir = root / "state"
            tls_dir.mkdir()
            state_dir.mkdir()
            for name in ("server.crt", "server.key", "ca.crt"):
                (tls_dir / name).write_text("placeholder", encoding="utf-8")
            config_path.write_text(
                """
[server]
host = "127.0.0.1"
port = 8080

[tls]
enabled = true
cert_file = "./tls/server.crt"
key_file = "./tls/server.key"
client_ca_file = "./tls/ca.crt"
require_client_cert = false

[remote]
mode = "allow-listed"
approval_store = "./state/approvals.json"

[audit]
file = "./state/audit.jsonl"

[proxmox]
base_url = "https://127.0.0.1:8006/api2/json"
token_id = "mcp@pam!default"
token_secret = "secret"
verify_tls = true

[profiles.readonly]
capabilities = ["inventory.read", "vm.read"]

[clients.ops_laptop]
token = "abc"
profile = "readonly"
""".strip()
                + "\n",
                encoding="utf-8",
            )
            config = load_config(config_path)

            original_create = ssl.create_default_context
            original_http_server = server_module.ThreadingHTTPServer
            calls: dict[str, object] = {}

            class FakeContext:
                def __init__(self) -> None:
                    self.verify_mode = None

                def load_cert_chain(self, certfile: str, keyfile: str) -> None:
                    calls["certfile"] = certfile
                    calls["keyfile"] = keyfile

                def load_verify_locations(self, cafile: str) -> None:
                    calls["cafile"] = cafile

                def wrap_socket(self, sock, *, server_side: bool):
                    calls["server_side"] = server_side
                    calls["verify_mode"] = self.verify_mode
                    return sock

            class FakeHttpServer:
                def __init__(self, server_address, handler_cls) -> None:
                    calls["server_address"] = server_address
                    calls["handler_cls"] = handler_cls
                    self.socket = object()

                def server_close(self) -> None:
                    calls["server_closed"] = True

            def fake_create_default_context(purpose):
                calls["purpose"] = purpose
                return FakeContext()

            ssl.create_default_context = fake_create_default_context
            server_module.ThreadingHTTPServer = FakeHttpServer
            try:
                server = server_module.create_server(config)
                server.server_close()
            finally:
                ssl.create_default_context = original_create
                server_module.ThreadingHTTPServer = original_http_server

            self.assertEqual(calls["verify_mode"], ssl.CERT_OPTIONAL)
