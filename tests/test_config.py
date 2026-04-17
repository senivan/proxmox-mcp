from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from proxmox_mcp.config import load_config


class ConfigTests(unittest.TestCase):
    def test_load_config_with_tls_and_audit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            config_path = root / "config.toml"
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
require_client_cert = true

[remote]
mode = "allow-listed"
approval_store = "./state/approvals.json"

[audit]
file = "./state/audit.jsonl"

[guest_exec]
default_timeout_seconds = 45
max_output_bytes = 4096
poll_interval_seconds = 2
local_node_name = "pve1"

[guest_exec.ssh_targets.app1]
node = "pve1"
vmid = 101
type = "qemu"
host = "10.0.0.50"
user = "root"
port = 22

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
            self.assertTrue(config.tls.enabled)
            self.assertTrue(config.tls.require_client_cert)
            self.assertEqual(config.audit.file, (root / "state" / "audit.jsonl").resolve())
            self.assertEqual(config.guest_exec.default_timeout_seconds, 45)
            self.assertEqual(config.guest_exec.local_node_name, "pve1")
            self.assertIn(("pve1", "qemu", 101), config.guest_exec.ssh_targets)
