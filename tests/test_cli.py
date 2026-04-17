from datetime import timedelta
from pathlib import Path
import sys
import tempfile
import tomllib
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from proxmox_mcp.cli import _set_mode, parse_ttl


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
