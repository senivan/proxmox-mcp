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
