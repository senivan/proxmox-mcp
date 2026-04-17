from datetime import timedelta
from http import HTTPStatus
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from proxmox_mcp.approval_store import ApprovalStore
from proxmox_mcp.audit import AuditLogger
from proxmox_mcp.config import load_config
from proxmox_mcp.server import handle_mcp_post


class FakeApi:
    pass


class ServerRequestTests(unittest.TestCase):
    def _make_config(self, root: Path):
        config_path = root / "config.toml"
        config_path.write_text(
            """
[server]
host = "127.0.0.1"
port = 8080

[tls]
enabled = false
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
capabilities = ["inventory.read", "node.read", "vm.read", "task.read", "storage.read"]

[clients.ops_laptop]
token = "abc"
profile = "readonly"
""".strip()
            + "\n",
            encoding="utf-8",
        )
        return load_config(config_path)

    def test_request_is_denied_without_approval(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            config = self._make_config(root)
            approval_store = ApprovalStore(config.remote.approval_store)
            audit_logger = AuditLogger(config.audit.file)
            status, payload = handle_mcp_post(
                config=config,
                approval_store=approval_store,
                audit_logger=audit_logger,
                proxmox_api=FakeApi(),
                authorization_header="Bearer abc",
                client_id_header="ops_laptop",
                tls_peer_identity=None,
                raw_body=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"}).encode("utf-8"),
            )
            self.assertEqual(status, HTTPStatus.OK)
            self.assertEqual(payload["error"]["code"], -32001)
            self.assertIn("not approved", payload["error"]["message"])

    def test_request_is_denied_with_invalid_token(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            config = self._make_config(root)
            approval_store = ApprovalStore(config.remote.approval_store)
            approval_store.approve("ops_laptop", timedelta(minutes=5))
            audit_logger = AuditLogger(config.audit.file)
            status, payload = handle_mcp_post(
                config=config,
                approval_store=approval_store,
                audit_logger=audit_logger,
                proxmox_api=FakeApi(),
                authorization_header="Bearer wrong",
                client_id_header="ops_laptop",
                tls_peer_identity=None,
                raw_body=json.dumps({"jsonrpc": "2.0", "id": 2, "method": "ping"}).encode("utf-8"),
            )
            self.assertEqual(status, HTTPStatus.OK)
            self.assertEqual(payload["error"]["code"], -32001)
            self.assertIn("invalid bearer token", payload["error"]["message"])

    def test_unknown_method_returns_json_rpc_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            config = self._make_config(root)
            approval_store = ApprovalStore(config.remote.approval_store)
            approval_store.approve("ops_laptop", timedelta(minutes=5))
            audit_logger = AuditLogger(config.audit.file)
            status, payload = handle_mcp_post(
                config=config,
                approval_store=approval_store,
                audit_logger=audit_logger,
                proxmox_api=FakeApi(),
                authorization_header="Bearer abc",
                client_id_header="ops_laptop",
                tls_peer_identity=None,
                raw_body=json.dumps({"jsonrpc": "2.0", "id": 3, "method": "nope"}).encode("utf-8"),
            )
            self.assertEqual(status, HTTPStatus.OK)
            self.assertEqual(payload["error"]["code"], -32601)
            self.assertIn("method not found", payload["error"]["message"])
