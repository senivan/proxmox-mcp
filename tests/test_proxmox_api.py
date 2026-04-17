from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from proxmox_mcp.config import ProxmoxConfig
from proxmox_mcp.proxmox_api import ProxmoxApi


class _RecordingApi(ProxmoxApi):
    def __init__(self) -> None:
        super().__init__(
            ProxmoxConfig(
                base_url="https://127.0.0.1:8006/api2/json",
                token_id="token",
                token_secret="secret",
                verify_tls=True,
            )
        )
        self.calls: list[tuple[str, str]] = []

    def get(self, path: str) -> dict:
        self.calls.append(("GET", path))
        if path.startswith("/cluster/tasks"):
            return []
        return {}

    def post(self, path: str) -> dict:
        self.calls.append(("POST", path))
        return "UPID:node:task"

    def _request(self, path: str, *, method: str = "GET", data: bytes | None = None) -> dict:
        self.calls.append((method, path))
        return "UPID:node:task"


class ProxmoxApiTests(unittest.TestCase):
    def test_get_task_escapes_upid_path_segment(self) -> None:
        api = _RecordingApi()
        api.get_task("UPID:pve1:abc/def")
        self.assertEqual(
            api.calls[0],
            ("GET", "/nodes/pve1/tasks/UPID%3Apve1%3Aabc%2Fdef/status"),
        )

    def test_snapshot_create_escapes_snapshot_segment(self) -> None:
        api = _RecordingApi()
        api.create_vm_snapshot(
            node="pve1",
            vmid=101,
            vm_type="qemu",
            snapshot="../nightly test",
        )
        self.assertEqual(
            api.calls[0],
            ("POST", "/nodes/pve1/qemu/101/snapshot/..%2Fnightly%20test"),
        )

    def test_tasks_list_uses_encoded_query(self) -> None:
        api = _RecordingApi()
        api.list_tasks(limit=25)
        self.assertEqual(api.calls[0], ("GET", "/cluster/tasks?limit=25"))
