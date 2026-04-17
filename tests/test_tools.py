from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from proxmox_mcp.policy import Principal
from proxmox_mcp.tools import call_tool


class FakeApi:
    def __init__(self) -> None:
        self.calls = []

    def vm_action(self, *, node: str, vmid: int, vm_type: str, action: str) -> dict:
        self.calls.append(
            {
                "node": node,
                "vmid": vmid,
                "type": vm_type,
                "action": action,
            }
        )
        return {
            "action": action,
            "target": {
                "node": node,
                "vmid": vmid,
                "type": vm_type,
            },
            "task": {
                "upid": "UPID:pve1:00000001:00000001:reboot:101:root@pam:",
            },
        }

    def list_vm_snapshots(self, *, node: str, vmid: int, vm_type: str) -> list[dict]:
        return [{"name": "snap-1", "vmstate": 0}]

    def create_vm_snapshot(self, *, node: str, vmid: int, vm_type: str, snapshot: str) -> dict:
        return {
            "action": "snapshot.create",
            "target": {
                "node": node,
                "vmid": vmid,
                "type": vm_type,
                "snapshot": snapshot,
            },
            "task": {
                "upid": "UPID:pve1:00000002:00000002:snapshot:101:root@pam:",
            },
        }

    def delete_vm_snapshot(self, *, node: str, vmid: int, vm_type: str, snapshot: str) -> dict:
        return {
            "action": "snapshot.delete",
            "target": {
                "node": node,
                "vmid": vmid,
                "type": vm_type,
                "snapshot": snapshot,
            },
            "task": {
                "upid": "UPID:pve1:00000003:00000003:delsnapshot:101:root@pam:",
            },
        }


class ToolTests(unittest.TestCase):
    def test_vm_reboot_calls_power_action(self) -> None:
        api = FakeApi()
        principal = Principal(
            client_id="ops-console",
            profile="operator",
            capabilities={"vm.power"},
        )
        result = call_tool(
            "proxmox.vm.reboot",
            {"node": "pve1", "vmid": 101, "type": "qemu"},
            principal,
            api,
        )
        self.assertEqual(result["action"], "reboot")
        self.assertEqual(result["target"]["vmid"], 101)
        self.assertEqual(result["task"]["upid"], "UPID:pve1:00000001:00000001:reboot:101:root@pam:")
        self.assertEqual(api.calls[0]["vmid"], 101)

    def test_snapshot_list_returns_target_and_snapshots(self) -> None:
        api = FakeApi()
        principal = Principal(
            client_id="ops-laptop",
            profile="readonly",
            capabilities={"vm.snapshot.read"},
        )
        result = call_tool(
            "proxmox.vm.snapshot.list",
            {"node": "pve1", "vmid": 101, "type": "qemu"},
            principal,
            api,
        )
        self.assertEqual(result["target"]["vmid"], 101)
        self.assertEqual(result["snapshots"][0]["name"], "snap-1")

    def test_snapshot_create_returns_task_shape(self) -> None:
        api = FakeApi()
        principal = Principal(
            client_id="ops-console",
            profile="operator",
            capabilities={"vm.snapshot.write"},
        )
        result = call_tool(
            "proxmox.vm.snapshot.create",
            {"node": "pve1", "vmid": 101, "type": "qemu", "snapshot": "before-upgrade"},
            principal,
            api,
        )
        self.assertEqual(result["action"], "snapshot.create")
        self.assertEqual(result["target"]["snapshot"], "before-upgrade")
        self.assertEqual(result["task"]["upid"], "UPID:pve1:00000002:00000002:snapshot:101:root@pam:")
