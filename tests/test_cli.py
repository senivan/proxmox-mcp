from contextlib import redirect_stdout
from datetime import timedelta
import io
from pathlib import Path
import sys
import tempfile
import tomllib
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from proxmox_mcp.cli import _set_mode, parse_ttl, run_admin


class CliTests(unittest.TestCase):
    def test_parse_ttl_accepts_positive_values(self) -> None:
        self.assertEqual(parse_ttl("30m"), timedelta(minutes=30))

    def test_parse_ttl_rejects_negative_values(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            parse_ttl("-5m")
        self.assertIn("ttl must be greater than zero", str(ctx.exception))

    def test_parse_ttl_rejects_zero(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            parse_ttl("0h")
        self.assertIn("ttl must be greater than zero", str(ctx.exception))

    def test_set_mode_updates_remote_section(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            config_path = Path(tmp_dir) / "config.toml"
            config_path.write_text(
                """
[remote]
mode = "deny"
approval_store = "./state/approvals.json"
""".strip()
                + "\n",
                encoding="utf-8",
            )
            _set_mode(str(config_path), "open")
            with config_path.open("rb") as fh:
                data = tomllib.load(fh)
            self.assertEqual(data["remote"]["mode"], "open")

    def test_set_mode_requires_existing_mode_setting(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            config_path = Path(tmp_dir) / "config.toml"
            config_path.write_text(
                """
[remote]
approval_store = "./state/approvals.json"
""".strip()
                + "\n",
                encoding="utf-8",
            )
            with self.assertRaises(ValueError) as ctx:
                _set_mode(str(config_path), "open")
            self.assertIn("mode setting", str(ctx.exception))

    def test_validate_config_check_paths_accepts_existing_deployment_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            (root / "state").mkdir()
            (root / "tls").mkdir()
            (root / "tls" / "server.crt").write_text("cert", encoding="utf-8")
            (root / "tls" / "server.key").write_text("key", encoding="utf-8")
            config_path = root / "config.toml"
            config_path.write_text(
                """
[server]
host = "127.0.0.1"
port = 8443

[tls]
enabled = true
cert_file = "./tls/server.crt"
key_file = "./tls/server.key"

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
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = run_admin(
                    ["--config", str(config_path), "validate-config", "--check-paths"]
                )
            self.assertEqual(exit_code, 0)
            self.assertIn("config ok", stdout.getvalue())

    def test_validate_config_check_paths_rejects_missing_tls_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            (root / "state").mkdir()
            config_path = root / "config.toml"
            config_path.write_text(
                """
[server]
host = "127.0.0.1"
port = 8443

[tls]
enabled = true
cert_file = "./tls/server.crt"
key_file = "./tls/server.key"

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
                run_admin(["--config", str(config_path), "validate-config", "--check-paths"])
            self.assertIn("tls cert file does not exist", str(ctx.exception))
