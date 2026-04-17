from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from proxmox_mcp.config import ProxmoxConfig
from proxmox_mcp.proxmox_api import ProxmoxApi, ProxmoxApiError


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
        if path.startswith("/cluster/tasks") or path == "/cluster/status" or path.endswith("/network"):
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

    def test_cluster_summary_uses_cluster_status_endpoint(self) -> None:
        api = _RecordingApi()
        api.get_cluster_summary()
        self.assertEqual(api.calls[0], ("GET", "/cluster/status"))

    def test_node_networks_list_uses_node_network_endpoint(self) -> None:
        api = _RecordingApi()
        api.list_node_networks(node="pve1")
        self.assertEqual(api.calls[0], ("GET", "/nodes/pve1/network"))

    def test_get_vm_rejects_unsupported_type(self) -> None:
        api = _RecordingApi()
        with self.assertRaisesRegex(ProxmoxApiError, "unsupported vm type"):
            api.get_vm(node="pve1", vmid=101, vm_type="container")

    def test_vm_action_rejects_unknown_action(self) -> None:
        api = _RecordingApi()
        with self.assertRaisesRegex(ProxmoxApiError, "unsupported vm action"):
            api.vm_action(node="pve1", vmid=101, vm_type="qemu", action="destroy")
        self.assertEqual(api.calls, [])

    def test_list_nodes_requires_list_payload(self) -> None:
        class _InvalidPayloadApi(_RecordingApi):
            def get(self, path: str) -> dict:
                self.calls.append(("GET", path))
                return {}

        api = _InvalidPayloadApi()
        with self.assertRaisesRegex(ProxmoxApiError, "expected list for /nodes"):
            api.list_nodes()

    def test_node_from_upid_validates_format(self) -> None:
        api = _RecordingApi()
        with self.assertRaisesRegex(ProxmoxApiError, "invalid UPID format"):
            api._node_from_upid("not-a-upid")
        with self.assertRaisesRegex(ProxmoxApiError, "invalid UPID format"):
            api._node_from_upid("UPID::abc")
