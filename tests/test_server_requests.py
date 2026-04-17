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
from proxmox_mcp.proxmox_api import ProxmoxApiError
from proxmox_mcp.server import handle_mcp_post


class FakeApi:
    def __init__(self) -> None:
        self.calls = []
        self.fail_nodes = False

    def list_nodes(self):
        if self.fail_nodes:
            raise ProxmoxApiError("backend unavailable")
        return [{"node": "pve1"}]

    def vm_action(self, *, node: str, vmid: int, vm_type: str, action: str):
        call = {"node": node, "vmid": vmid, "type": vm_type, "action": action}
        self.calls.append(call)
        return {
            "action": action,
            "target": {
                "node": node,
                "vmid": vmid,
                "type": vm_type,
            },
            "task": {
                "upid": "UPID:pve1:00000001:00000001:reboot:101:root@pam:",
            },
        }


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

[profiles.operator]
capabilities = ["inventory.read", "node.read", "vm.read", "task.read", "storage.read", "vm.power"]

[clients.ops_laptop]
token = "abc"
profile = "readonly"

[clients.ops_console]
token = "xyz"
profile = "operator"
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

    def test_tool_validation_error_returns_invalid_params(self) -> None:
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
                raw_body=json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 4,
                        "method": "tools/call",
                        "params": {
                            "name": "proxmox.vm.get",
                            "arguments": {"node": "pve1", "vmid": True, "type": "qemu"},
                        },
                    }
                ).encode("utf-8"),
            )
            self.assertEqual(status, HTTPStatus.OK)
            self.assertEqual(payload["error"]["code"], -32602)
            self.assertIn("vmid must be an integer", payload["error"]["message"])

    def test_backend_error_returns_server_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            config = self._make_config(root)
            approval_store = ApprovalStore(config.remote.approval_store)
            approval_store.approve("ops_laptop", timedelta(minutes=5))
            audit_logger = AuditLogger(config.audit.file)
            api = FakeApi()
            api.fail_nodes = True
            status, payload = handle_mcp_post(
                config=config,
                approval_store=approval_store,
                audit_logger=audit_logger,
                proxmox_api=api,
                authorization_header="Bearer abc",
                client_id_header="ops_laptop",
                tls_peer_identity=None,
                raw_body=json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 5,
                        "method": "tools/call",
                        "params": {"name": "proxmox.nodes.list", "arguments": {}},
                    }
                ).encode("utf-8"),
            )
            self.assertEqual(status, HTTPStatus.OK)
            self.assertEqual(payload["error"]["code"], -32002)
            self.assertIn("backend unavailable", payload["error"]["message"])

    def test_mutating_tool_request_path_succeeds(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            config = self._make_config(root)
            approval_store = ApprovalStore(config.remote.approval_store)
            approval_store.approve("ops_console", timedelta(minutes=5))
            audit_logger = AuditLogger(config.audit.file)
            api = FakeApi()
            status, payload = handle_mcp_post(
                config=config,
                approval_store=approval_store,
                audit_logger=audit_logger,
                proxmox_api=api,
                authorization_header="Bearer xyz",
                client_id_header="ops_console",
                tls_peer_identity=None,
                raw_body=json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 6,
                        "method": "tools/call",
                        "params": {
                            "name": "proxmox.vm.reboot",
                            "arguments": {"node": "pve1", "vmid": 101, "type": "qemu"},
                        },
                    }
                ).encode("utf-8"),
            )
            self.assertEqual(status, HTTPStatus.OK)
            self.assertIn('"action": "reboot"', payload["result"]["content"][0]["text"])
            self.assertIn('"task"', payload["result"]["content"][0]["text"])
            self.assertIn('"target"', payload["result"]["content"][0]["text"])
            self.assertEqual(api.calls[0]["action"], "reboot")
