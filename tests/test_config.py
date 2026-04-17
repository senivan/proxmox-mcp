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

    def test_example_config_parses(self) -> None:
        config = load_config(Path(__file__).resolve().parents[1] / "examples" / "config.toml")
        self.assertEqual(config.server.port, 8443)
        self.assertTrue(config.tls.enabled)
        self.assertEqual(
            config.remote.approval_store,
            Path("/var/lib/proxmox-mcp/approvals.json").resolve(),
        )

    def test_verify_tls_false_requires_explicit_opt_in(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            config_path = root / "config.toml"
            config_path.write_text(
                """
[server]
host = "127.0.0.1"
port = 8080

[tls]
enabled = false

[remote]
mode = "allow-listed"
approval_store = "./state/approvals.json"

[audit]
file = "./state/audit.jsonl"

[proxmox]
base_url = "https://127.0.0.1:8006/api2/json"
token_id = "mcp@pam!default"
token_secret = "secret"
verify_tls = false

[profiles.readonly]
capabilities = ["inventory.read"]

[clients.ops_laptop]
token = "abc"
profile = "readonly"
""".strip()
                + "\n",
                encoding="utf-8",
            )
            with self.assertRaises(ValueError) as ctx:
                load_config(config_path)
            self.assertIn("allow_insecure_tls = true", str(ctx.exception))

    def test_duplicate_guest_exec_targets_fail(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            config_path = root / "config.toml"
            config_path.write_text(
                """
[server]
host = "127.0.0.1"
port = 8080

[tls]
enabled = false

[remote]
mode = "allow-listed"
approval_store = "./state/approvals.json"

[audit]
file = "./state/audit.jsonl"

[guest_exec]
default_timeout_seconds = 30
max_output_bytes = 1024
poll_interval_seconds = 1

[guest_exec.ssh_targets.app1]
node = "pve1"
vmid = 101
type = "qemu"
host = "10.0.0.50"
user = "root"

[guest_exec.ssh_targets.app1_duplicate]
node = "pve1"
vmid = 101
type = "qemu"
host = "10.0.0.51"
user = "root"

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
            with self.assertRaises(ValueError) as ctx:
                load_config(config_path)
            self.assertIn("duplicate guest_exec ssh target", str(ctx.exception))
            self.assertIn("app1", str(ctx.exception))
            self.assertIn("app1_duplicate", str(ctx.exception))

    def test_require_client_cert_needs_tls_enabled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            config_path = root / "config.toml"
            config_path.write_text(
                """
[server]
host = "127.0.0.1"
port = 8080

[tls]
enabled = false
require_client_cert = true
cert_file = "./tls/server.crt"
key_file = "./tls/server.key"
client_ca_file = "./tls/ca.crt"

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
capabilities = ["inventory.read"]

[clients.ops_laptop]
token = "abc"
profile = "readonly"
""".strip()
                + "\n",
                encoding="utf-8",
            )
            with self.assertRaises(ValueError) as ctx:
                load_config(config_path)
            self.assertIn("tls.require_client_cert requires tls.enabled", str(ctx.exception))

    def test_guest_exec_requires_positive_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            config_path = root / "config.toml"
            config_path.write_text(
                """
[server]
host = "127.0.0.1"
port = 8080

[tls]
enabled = false

[remote]
mode = "allow-listed"
approval_store = "./state/approvals.json"

[audit]
file = "./state/audit.jsonl"

[guest_exec]
default_timeout_seconds = 0
max_output_bytes = 1024
poll_interval_seconds = 1

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
            with self.assertRaises(ValueError) as ctx:
                load_config(config_path)
            self.assertIn("guest_exec.default_timeout_seconds must be >= 1", str(ctx.exception))

    def test_guest_exec_rejects_unknown_ssh_type(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            config_path = root / "config.toml"
            config_path.write_text(
                """
[server]
host = "127.0.0.1"
port = 8080

[tls]
enabled = false

[remote]
mode = "allow-listed"
approval_store = "./state/approvals.json"

[audit]
file = "./state/audit.jsonl"

[guest_exec.ssh_targets.app1]
node = "pve1"
vmid = 101
type = "container"
host = "10.0.0.50"
user = "root"

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
            with self.assertRaises(ValueError) as ctx:
                load_config(config_path)
            self.assertIn("invalid type for guest_exec ssh target app1", str(ctx.exception))

    def test_client_must_reference_known_profile(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            config_path = root / "config.toml"
            config_path.write_text(
                """
[server]
host = "127.0.0.1"
port = 8080

[tls]
enabled = false

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
capabilities = ["inventory.read"]

[clients.ops_laptop]
token = "abc"
profile = "nonexistent"
""".strip()
                + "\n",
                encoding="utf-8",
            )
            with self.assertRaises(ValueError) as ctx:
                load_config(config_path)
            self.assertIn("references unknown profile", str(ctx.exception))
