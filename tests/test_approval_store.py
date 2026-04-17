from datetime import UTC, datetime, timedelta
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from proxmox_mcp.approval_store import ApprovalStore


class ApprovalStoreTests(unittest.TestCase):
    def test_approval_ttl_expires(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            store = ApprovalStore(Path(tmp_dir) / "approvals.json")
            store.approve("ops-laptop", timedelta(minutes=5))
            self.assertTrue(store.is_approved("ops-laptop"))
            future = datetime.now(UTC) + timedelta(days=1)
            self.assertFalse(store.is_approved("ops-laptop", now=future))

    def test_revoke_removes_approval(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            store = ApprovalStore(Path(tmp_dir) / "approvals.json")
            store.approve("ops-laptop", None)
            self.assertTrue(store.revoke("ops-laptop"))
            self.assertFalse(store.is_approved("ops-laptop"))

    def test_write_keeps_valid_json_on_disk(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "approvals.json"
            store = ApprovalStore(path)
            store.approve("ops-laptop", timedelta(minutes=5))
            self.assertTrue(path.exists())
            parsed = json.loads(path.read_text(encoding="utf-8"))
            self.assertIn("approvals", parsed)
            self.assertIn("ops-laptop", parsed["approvals"])

    def test_corrupted_store_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "approvals.json"
            path.write_text("{", encoding="utf-8")
            store = ApprovalStore(path)
            self.assertFalse(store.is_approved("ops-laptop"))

    def test_invalid_expires_at_is_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "approvals.json"
            path.write_text(
                '{"approvals": {"ops-laptop": {"expires_at": "not-a-date"}}}',
                encoding="utf-8",
            )
            store = ApprovalStore(path)
            self.assertFalse(store.is_approved("ops-laptop"))
