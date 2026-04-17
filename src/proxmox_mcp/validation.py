from __future__ import annotations


VM_TYPES = {"qemu", "lxc"}


def _ensure_only_keys(arguments: dict, allowed: set[str]) -> None:
    extra = set(arguments) - allowed
    if extra:
        raise ValueError(f"unexpected arguments: {', '.join(sorted(extra))}")


def require_string(arguments: dict, key: str) -> str:
    value = arguments.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{key} must be a non-empty string")
    return value.strip()


def require_int(arguments: dict, key: str, *, minimum: int | None = None, maximum: int | None = None) -> int:
    value = arguments.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{key} must be an integer")
    if minimum is not None and value < minimum:
        raise ValueError(f"{key} must be >= {minimum}")
    if maximum is not None and value > maximum:
        raise ValueError(f"{key} must be <= {maximum}")
    return value


def optional_int(
    arguments: dict,
    key: str,
    *,
    default: int,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    if key not in arguments:
        return default
    return require_int(arguments, key, minimum=minimum, maximum=maximum)


def require_vm_type(arguments: dict) -> str:
    vm_type = require_string(arguments, "type")
    if vm_type not in VM_TYPES:
        raise ValueError(f"type must be one of: {', '.join(sorted(VM_TYPES))}")
    return vm_type


def require_string_list(arguments: dict, key: str) -> list[str]:
    value = arguments.get(key)
    if not isinstance(value, list) or not value:
        raise ValueError(f"{key} must be a non-empty array of strings")
    result = []
    for item in value:
        if not isinstance(item, str) or not item:
            raise ValueError(f"{key} must be a non-empty array of strings")
        result.append(item)
    return result


def validate_tool_arguments(tool_name: str, arguments: dict) -> dict:
    if tool_name == "proxmox.nodes.list":
        _ensure_only_keys(arguments, set())
        return {}
    if tool_name == "proxmox.node.get":
        _ensure_only_keys(arguments, {"node"})
        return {"node": require_string(arguments, "node")}
    if tool_name == "proxmox.vms.list":
        _ensure_only_keys(arguments, set())
        return {}
    if tool_name == "proxmox.vm.get":
        _ensure_only_keys(arguments, {"node", "vmid", "type"})
        return {
            "node": require_string(arguments, "node"),
            "vmid": require_int(arguments, "vmid", minimum=1),
            "type": require_vm_type(arguments),
        }
    if tool_name == "proxmox.tasks.list":
        _ensure_only_keys(arguments, {"limit"})
        return {"limit": optional_int(arguments, "limit", default=25, minimum=1, maximum=100)}
    if tool_name == "proxmox.task.get":
        _ensure_only_keys(arguments, {"upid"})
        return {"upid": require_string(arguments, "upid")}
    if tool_name == "proxmox.storage.list":
        _ensure_only_keys(arguments, set())
        return {}
    if tool_name == "proxmox.storage.get":
        _ensure_only_keys(arguments, {"node", "storage"})
        return {
            "node": require_string(arguments, "node"),
            "storage": require_string(arguments, "storage"),
        }
    if tool_name == "proxmox.vm.snapshot.list":
        _ensure_only_keys(arguments, {"node", "vmid", "type"})
        return {
            "node": require_string(arguments, "node"),
            "vmid": require_int(arguments, "vmid", minimum=1),
            "type": require_vm_type(arguments),
        }
    if tool_name in {"proxmox.vm.snapshot.create", "proxmox.vm.snapshot.delete"}:
        _ensure_only_keys(arguments, {"node", "vmid", "type", "snapshot"})
        return {
            "node": require_string(arguments, "node"),
            "vmid": require_int(arguments, "vmid", minimum=1),
            "type": require_vm_type(arguments),
            "snapshot": require_string(arguments, "snapshot"),
        }
    if tool_name == "proxmox.vm.guest.exec":
        _ensure_only_keys(arguments, {"node", "vmid", "type", "argv", "timeout_seconds"})
        return {
            "node": require_string(arguments, "node"),
            "vmid": require_int(arguments, "vmid", minimum=1),
            "type": require_vm_type(arguments),
            "argv": require_string_list(arguments, "argv"),
            "timeout_seconds": optional_int(
                arguments,
                "timeout_seconds",
                default=30,
                minimum=1,
                maximum=300,
            ),
        }
    if tool_name in {
        "proxmox.vm.start",
        "proxmox.vm.reboot",
        "proxmox.vm.shutdown",
        "proxmox.vm.stop",
    }:
        _ensure_only_keys(arguments, {"node", "vmid", "type"})
        return {
            "node": require_string(arguments, "node"),
            "vmid": require_int(arguments, "vmid", minimum=1),
            "type": require_vm_type(arguments),
        }
    raise ValueError(f"unknown or disabled tool: {tool_name}")
