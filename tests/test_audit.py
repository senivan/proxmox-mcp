from pathlib import Path
import json
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from proxmox_mcp.audit import AuditLogger


class AuditLoggerTests(unittest.TestCase):
    def test_write_appends_json_line(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "audit.jsonl"
            logger = AuditLogger(path)
            logger.write(
                event="mcp_request",
                client_id="ops-console",
                profile="operator",
                method="tools/call",
                tool_name="proxmox.vm.start",
                kind="mutating",
                outcome="allowed",
                target={"node": "pve1", "vmid": 100, "type": "qemu"},
            )

            lines = path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 1)
            record = json.loads(lines[0])
            self.assertEqual(record["client_id"], "ops-console")
            self.assertEqual(record["tool_name"], "proxmox.vm.start")
            self.assertEqual(record["kind"], "mutating")
            self.assertEqual(record["outcome"], "allowed")
            self.assertEqual(record["target"]["vmid"], 100)
