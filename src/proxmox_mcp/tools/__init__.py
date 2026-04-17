from __future__ import annotations

from proxmox_mcp.policy import TOOL_CAPABILITIES
from proxmox_mcp.policy import require_tool_access
from proxmox_mcp.proxmox_api import ProxmoxApi
from proxmox_mcp.validation import validate_tool_arguments


def list_tools(principal=None) -> list[dict]:
    tools = [
        {
            "name": "proxmox.nodes.list",
            "description": "List Proxmox cluster nodes",
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        },
        {
            "name": "proxmox.node.get",
            "description": "Get status for a Proxmox node",
            "inputSchema": {
                "type": "object",
                "properties": {"node": {"type": "string", "minLength": 1}},
                "required": ["node"],
                "additionalProperties": False,
            },
        },
        {
            "name": "proxmox.vms.list",
            "description": "List cluster VMs and containers exposed as VM resources",
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        },
        {
            "name": "proxmox.vm.get",
            "description": "Get current status for a Proxmox VM or container",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "node": {"type": "string", "minLength": 1},
                    "vmid": {"type": "integer", "minimum": 1},
                    "type": {"type": "string", "enum": ["qemu", "lxc"]},
                },
                "required": ["node", "vmid", "type"],
                "additionalProperties": False,
            },
        },
        {
            "name": "proxmox.tasks.list",
            "description": "List recent cluster tasks",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "minimum": 1, "maximum": 100, "default": 25}
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "proxmox.task.get",
            "description": "Get task status by Proxmox UPID",
            "inputSchema": {
                "type": "object",
                "properties": {"upid": {"type": "string", "minLength": 1}},
                "required": ["upid"],
                "additionalProperties": False,
            },
        },
        {
            "name": "proxmox.storage.list",
            "description": "List configured cluster storage backends",
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        },
        {
            "name": "proxmox.storage.get",
            "description": "Get storage status on a specific node",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "node": {"type": "string", "minLength": 1},
                    "storage": {"type": "string", "minLength": 1},
                },
                "required": ["node", "storage"],
                "additionalProperties": False,
            },
        },
        {
            "name": "proxmox.vm.start",
            "description": "Start a Proxmox VM or container",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "node": {"type": "string", "minLength": 1},
                    "vmid": {"type": "integer", "minimum": 1},
                    "type": {"type": "string", "enum": ["qemu", "lxc"]},
                },
                "required": ["node", "vmid", "type"],
                "additionalProperties": False,
            },
        },
        {
            "name": "proxmox.vm.snapshot.list",
            "description": "List snapshots for a Proxmox VM or container",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "node": {"type": "string", "minLength": 1},
                    "vmid": {"type": "integer", "minimum": 1},
                    "type": {"type": "string", "enum": ["qemu", "lxc"]},
                },
                "required": ["node", "vmid", "type"],
                "additionalProperties": False,
            },
        },
        {
            "name": "proxmox.vm.snapshot.create",
            "description": "Create a snapshot for a Proxmox VM or container",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "node": {"type": "string", "minLength": 1},
                    "vmid": {"type": "integer", "minimum": 1},
                    "type": {"type": "string", "enum": ["qemu", "lxc"]},
                    "snapshot": {"type": "string", "minLength": 1},
                },
                "required": ["node", "vmid", "type", "snapshot"],
                "additionalProperties": False,
            },
        },
        {
            "name": "proxmox.vm.snapshot.delete",
            "description": "Delete a snapshot for a Proxmox VM or container",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "node": {"type": "string", "minLength": 1},
                    "vmid": {"type": "integer", "minimum": 1},
                    "type": {"type": "string", "enum": ["qemu", "lxc"]},
                    "snapshot": {"type": "string", "minLength": 1},
                },
                "required": ["node", "vmid", "type", "snapshot"],
                "additionalProperties": False,
            },
        },
        {
            "name": "proxmox.vm.shutdown",
            "description": "Gracefully shut down a Proxmox VM or container",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "node": {"type": "string", "minLength": 1},
                    "vmid": {"type": "integer", "minimum": 1},
                    "type": {"type": "string", "enum": ["qemu", "lxc"]},
                },
                "required": ["node", "vmid", "type"],
                "additionalProperties": False,
            },
        },
        {
            "name": "proxmox.vm.reboot",
            "description": "Reboot a Proxmox VM or container",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "node": {"type": "string", "minLength": 1},
                    "vmid": {"type": "integer", "minimum": 1},
                    "type": {"type": "string", "enum": ["qemu", "lxc"]},
                },
                "required": ["node", "vmid", "type"],
                "additionalProperties": False,
            },
        },
        {
            "name": "proxmox.vm.stop",
            "description": "Force stop a Proxmox VM or container",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "node": {"type": "string", "minLength": 1},
                    "vmid": {"type": "integer", "minimum": 1},
                    "type": {"type": "string", "enum": ["qemu", "lxc"]},
                },
                "required": ["node", "vmid", "type"],
                "additionalProperties": False,
            },
        },
    ]
    if principal is None:
        return tools
    allowed = []
    for tool in tools:
        required = TOOL_CAPABILITIES[tool["name"]]
        if required <= principal.capabilities:
            allowed.append(tool)
    return allowed


def call_tool(tool_name: str, arguments: dict, principal, api: ProxmoxApi) -> dict:
    require_tool_access(principal, tool_name)
    validated = validate_tool_arguments(tool_name, arguments)
    if tool_name == "proxmox.nodes.list":
        return {"nodes": api.list_nodes()}
    if tool_name == "proxmox.node.get":
        return {"node": validated["node"], "status": api.get_node(validated["node"])}
    if tool_name == "proxmox.vms.list":
        return {"vms": api.list_vms()}
    if tool_name == "proxmox.vm.get":
        return {
            "node": validated["node"],
            "vmid": validated["vmid"],
            "type": validated["type"],
            "status": api.get_vm(
                node=validated["node"],
                vmid=validated["vmid"],
                vm_type=validated["type"],
            ),
        }
    if tool_name == "proxmox.tasks.list":
        return {"tasks": api.list_tasks(limit=validated["limit"])}
    if tool_name == "proxmox.task.get":
        return api.get_task(validated["upid"])
    if tool_name == "proxmox.storage.list":
        return {"storage": api.list_storage()}
    if tool_name == "proxmox.storage.get":
        return {
            "node": validated["node"],
            "storage": validated["storage"],
            "status": api.get_storage(
                node=validated["node"],
                storage=validated["storage"],
            ),
        }
    if tool_name == "proxmox.vm.snapshot.list":
        return {
            "target": {
                "node": validated["node"],
                "vmid": validated["vmid"],
                "type": validated["type"],
            },
            "snapshots": api.list_vm_snapshots(
                node=validated["node"],
                vmid=validated["vmid"],
                vm_type=validated["type"],
            ),
        }
    if tool_name == "proxmox.vm.snapshot.create":
        return api.create_vm_snapshot(
            node=validated["node"],
            vmid=validated["vmid"],
            vm_type=validated["type"],
            snapshot=validated["snapshot"],
        )
    if tool_name == "proxmox.vm.snapshot.delete":
        return api.delete_vm_snapshot(
            node=validated["node"],
            vmid=validated["vmid"],
            vm_type=validated["type"],
            snapshot=validated["snapshot"],
        )
    if tool_name == "proxmox.vm.start":
        return api.vm_action(
            node=validated["node"],
            vmid=validated["vmid"],
            vm_type=validated["type"],
            action="start",
        )
    if tool_name == "proxmox.vm.reboot":
        return api.vm_action(
            node=validated["node"],
            vmid=validated["vmid"],
            vm_type=validated["type"],
            action="reboot",
        )
    if tool_name == "proxmox.vm.shutdown":
        return api.vm_action(
            node=validated["node"],
            vmid=validated["vmid"],
            vm_type=validated["type"],
            action="shutdown",
        )
    if tool_name == "proxmox.vm.stop":
        return api.vm_action(
            node=validated["node"],
            vmid=validated["vmid"],
            vm_type=validated["type"],
            action="stop",
        )
    raise PermissionError(f"unknown or disabled tool: {tool_name}")
