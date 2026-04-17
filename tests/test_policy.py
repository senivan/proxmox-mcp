from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from proxmox_mcp.policy import Principal, require_tool_access
from proxmox_mcp.tools import list_tools


class PolicyTests(unittest.TestCase):
    def test_readonly_profile_can_list_vms(self) -> None:
        principal = Principal(
            client_id="ops-laptop",
            profile="readonly",
            capabilities={"inventory.read", "vm.read"},
        )
        require_tool_access(principal, "proxmox.vms.list")

    def test_readonly_profile_cannot_list_tasks_without_capability(self) -> None:
        principal = Principal(
            client_id="ops-laptop",
            profile="readonly",
            capabilities={"inventory.read", "vm.read"},
        )
        with self.assertRaises(PermissionError) as ctx:
            require_tool_access(principal, "proxmox.tasks.list")
        self.assertIn("task.read", str(ctx.exception))

    def test_tools_list_is_filtered_by_capabilities(self) -> None:
        principal = Principal(
            client_id="ops-laptop",
            profile="readonly",
            capabilities={"inventory.read", "vm.read"},
        )
        tool_names = {tool["name"] for tool in list_tools(principal)}
        self.assertEqual(tool_names, {"proxmox.vms.list", "proxmox.vm.get"})

    def test_operator_profile_can_use_power_actions(self) -> None:
        principal = Principal(
            client_id="ops-console",
            profile="operator",
            capabilities={"vm.power"},
        )
        require_tool_access(principal, "proxmox.vm.start")
        require_tool_access(principal, "proxmox.vm.shutdown")
        require_tool_access(principal, "proxmox.vm.stop")

    def test_operator_tools_are_hidden_from_readonly_clients(self) -> None:
        principal = Principal(
            client_id="ops-laptop",
            profile="readonly",
            capabilities={"inventory.read", "node.read", "vm.read", "task.read", "storage.read"},
        )
        tool_names = {tool["name"] for tool in list_tools(principal)}
        self.assertNotIn("proxmox.vm.start", tool_names)
        self.assertNotIn("proxmox.vm.shutdown", tool_names)
        self.assertNotIn("proxmox.vm.stop", tool_names)

    def test_storage_tools_require_storage_capability(self) -> None:
        principal = Principal(
            client_id="ops-laptop",
            profile="readonly",
            capabilities={"inventory.read", "node.read", "vm.read", "task.read"},
        )
        with self.assertRaises(PermissionError) as ctx:
            require_tool_access(principal, "proxmox.storage.list")
        self.assertIn("storage.read", str(ctx.exception))
