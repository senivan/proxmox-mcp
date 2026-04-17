from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from proxmox_mcp.validation import validate_tool_arguments


class ValidationTests(unittest.TestCase):
    def test_vm_get_requires_integer_vmid(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            validate_tool_arguments(
                "proxmox.vm.get",
                {"node": "pve1", "vmid": "100", "type": "qemu"},
            )
        self.assertIn("vmid must be an integer", str(ctx.exception))

    def test_vm_get_rejects_boolean_vmid(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            validate_tool_arguments(
                "proxmox.vm.get",
                {"node": "pve1", "vmid": True, "type": "qemu"},
            )
        self.assertIn("vmid must be an integer", str(ctx.exception))

    def test_tasks_list_limit_is_bounded(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            validate_tool_arguments("proxmox.tasks.list", {"limit": 101})
        self.assertIn("limit must be <= 100", str(ctx.exception))

    def test_storage_get_accepts_expected_shape(self) -> None:
        validated = validate_tool_arguments(
            "proxmox.storage.get",
            {"node": "pve1", "storage": "local-zfs"},
        )
        self.assertEqual(validated["node"], "pve1")
        self.assertEqual(validated["storage"], "local-zfs")

    def test_task_get_validates_upid_format(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            validate_tool_arguments("proxmox.task.get", {"upid": "not-a-upid"})
        self.assertIn("upid must start with 'UPID:'", str(ctx.exception))

    def test_vm_get_rejects_slash_in_node(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            validate_tool_arguments(
                "proxmox.vm.get",
                {"node": "../pve1", "vmid": 100, "type": "qemu"},
            )
        self.assertIn("node must not contain '/'", str(ctx.exception))

    def test_snapshot_create_rejects_slash_in_snapshot_name(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            validate_tool_arguments(
                "proxmox.vm.snapshot.create",
                {"node": "pve1", "vmid": 100, "type": "qemu", "snapshot": "../nightly"},
            )
        self.assertIn("snapshot must not contain '/'", str(ctx.exception))
