from __future__ import annotations

from dataclasses import dataclass


TOOL_CAPABILITIES = {
    "proxmox.nodes.list": {"inventory.read", "node.read"},
    "proxmox.node.get": {"node.read"},
    "proxmox.vms.list": {"inventory.read", "vm.read"},
    "proxmox.vm.get": {"vm.read"},
    "proxmox.tasks.list": {"task.read"},
    "proxmox.task.get": {"task.read"},
    "proxmox.storage.list": {"inventory.read", "storage.read"},
    "proxmox.storage.get": {"storage.read"},
    "proxmox.vm.start": {"vm.power"},
    "proxmox.vm.reboot": {"vm.power"},
    "proxmox.vm.shutdown": {"vm.power"},
    "proxmox.vm.stop": {"vm.power"},
}


@dataclass(frozen=True)
class Principal:
    client_id: str
    profile: str
    capabilities: set[str]


def require_tool_access(principal: Principal, tool_name: str) -> None:
    required = TOOL_CAPABILITIES.get(tool_name)
    if required is None:
        raise PermissionError(f"unknown or disabled tool: {tool_name}")
    missing = required - principal.capabilities
    if missing:
        missing_text = ", ".join(sorted(missing))
        raise PermissionError(
            f"client {principal.client_id} lacks capability: {missing_text}"
        )
