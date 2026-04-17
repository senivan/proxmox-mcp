from datetime import timedelta
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from proxmox_mcp.cli import parse_ttl


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
