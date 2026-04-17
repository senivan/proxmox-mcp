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
