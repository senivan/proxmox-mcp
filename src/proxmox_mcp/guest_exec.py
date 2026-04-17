from __future__ import annotations

import base64
import json
from pathlib import Path
import subprocess
import time

from proxmox_mcp.config import AppConfig, SshTargetConfig
from proxmox_mcp.proxmox_api import ProxmoxApiError


def _truncate_output(data: bytes, max_output_bytes: int) -> tuple[str, bool]:
    truncated = len(data) > max_output_bytes
    if truncated:
        data = data[:max_output_bytes]
    return data.decode("utf-8", errors="replace"), truncated


def _decode_agent_output(value: str | None) -> bytes:
    if not value:
        return b""
    try:
        return base64.b64decode(value, validate=False)
    except Exception:  # noqa: BLE001
        return value.encode("utf-8", errors="replace")


def _validate_ssh_destination_component(value: str, *, field_name: str) -> str:
    if not value:
        raise ProxmoxApiError(f"invalid ssh {field_name}")
    if value.startswith("-"):
        raise ProxmoxApiError(f"invalid ssh {field_name}")
    if any(char.isspace() or ord(char) < 32 for char in value):
        raise ProxmoxApiError(f"invalid ssh {field_name}")
    return value


def _validate_pve_path_segment(value: str, *, field_name: str) -> str:
    if not value or "/" in value or any(ord(char) < 32 for char in value):
        raise ProxmoxApiError(f"invalid {field_name}")
    return value


def _run_process(
    argv: list[str],
    *,
    timeout_seconds: int,
    runner=subprocess.run,
) -> subprocess.CompletedProcess:
    try:
        return runner(
            argv,
            capture_output=True,
            text=False,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ProxmoxApiError(f"guest exec timed out after {timeout_seconds}s") from exc
    except OSError as exc:
        raise ProxmoxApiError(f"guest exec backend failed to start: {exc}") from exc


def _ssh_command(target: SshTargetConfig, argv: list[str]) -> list[str]:
    user = _validate_ssh_destination_component(target.user, field_name="user")
    host = _validate_ssh_destination_component(target.host, field_name="host")
    cmd = [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        f"StrictHostKeyChecking={'yes' if target.strict_host_key_checking else 'no'}",
        "-p",
        str(target.port),
    ]
    if target.known_hosts_file is not None:
        cmd += ["-o", f"UserKnownHostsFile={target.known_hosts_file}"]
    if target.private_key_file is not None:
        cmd += ["-i", str(target.private_key_file)]
    cmd.append(f"{user}@{host}")
    cmd.extend(argv)
    return cmd


class GuestExecService:
    def __init__(
        self,
        config: AppConfig,
        *,
        runner=subprocess.run,
        sleep_fn=time.sleep,
    ) -> None:
        self.config = config
        self.runner = runner
        self.sleep_fn = sleep_fn

    def execute(
        self,
        *,
        node: str,
        vmid: int,
        vm_type: str,
        argv: list[str],
        timeout_seconds: int | None,
    ) -> dict:
        timeout = timeout_seconds or self.config.guest_exec.default_timeout_seconds
        node = _validate_pve_path_segment(node, field_name="node")
        if vm_type == "lxc":
            return self._exec_lxc(node=node, vmid=vmid, argv=argv, timeout_seconds=timeout)
        if vm_type == "qemu":
            try:
                return self._exec_qemu_guest_agent(
                    node=node,
                    vmid=vmid,
                    argv=argv,
                    timeout_seconds=timeout,
                )
            except ProxmoxApiError as exc:
                if not self._is_guest_agent_unavailable(str(exc)):
                    raise
                target = self.config.guest_exec.ssh_targets.get((node, vm_type, vmid))
                if target is None:
                    raise
                return self._exec_ssh(
                    target=target,
                    node=node,
                    vmid=vmid,
                    vm_type=vm_type,
                    argv=argv,
                    timeout_seconds=timeout,
                    reason="guest-agent-unavailable",
                )
        raise ProxmoxApiError(f"unsupported guest exec type: {vm_type}")

    def _exec_lxc(
        self, *, node: str, vmid: int, argv: list[str], timeout_seconds: int
    ) -> dict:
        local_node = self.config.guest_exec.local_node_name
        if local_node and node != local_node:
            remote_node = _validate_ssh_destination_component(node, field_name="node")
            cmd = ["ssh", remote_node, "pct", "exec", str(vmid), "--", *argv]
            backend = "pct-ssh"
        else:
            cmd = ["pct", "exec", str(vmid), "--", *argv]
            backend = "pct"
        result = _run_process(cmd, timeout_seconds=timeout_seconds, runner=self.runner)
        stdout, stdout_truncated = _truncate_output(
            result.stdout, self.config.guest_exec.max_output_bytes
        )
        stderr, stderr_truncated = _truncate_output(
            result.stderr, self.config.guest_exec.max_output_bytes
        )
        return {
            "backend": backend,
            "target": {"node": node, "vmid": vmid, "type": "lxc"},
            "command": {"argv": argv, "timeout_seconds": timeout_seconds},
            "result": {
                "exit_code": result.returncode,
                "stdout": stdout,
                "stderr": stderr,
                "stdout_truncated": stdout_truncated,
                "stderr_truncated": stderr_truncated,
            },
        }

    def _exec_ssh(
        self,
        *,
        target: SshTargetConfig,
        node: str,
        vmid: int,
        vm_type: str,
        argv: list[str],
        timeout_seconds: int,
        reason: str,
    ) -> dict:
        result = _run_process(
            _ssh_command(target, argv),
            timeout_seconds=timeout_seconds,
            runner=self.runner,
        )
        stdout, stdout_truncated = _truncate_output(
            result.stdout, self.config.guest_exec.max_output_bytes
        )
        stderr, stderr_truncated = _truncate_output(
            result.stderr, self.config.guest_exec.max_output_bytes
        )
        return {
            "backend": "ssh",
            "backend_reason": reason,
            "target": {"node": node, "vmid": vmid, "type": vm_type},
            "command": {"argv": argv, "timeout_seconds": timeout_seconds},
            "result": {
                "exit_code": result.returncode,
                "stdout": stdout,
                "stderr": stderr,
                "stdout_truncated": stdout_truncated,
                "stderr_truncated": stderr_truncated,
            },
        }

    def _exec_qemu_guest_agent(
        self,
        *,
        node: str,
        vmid: int,
        argv: list[str],
        timeout_seconds: int,
    ) -> dict:
        create_cmd = [
            "pvesh",
            "create",
            f"/nodes/{node}/qemu/{vmid}/agent/exec",
            "--output-format",
            "json",
        ]
        for arg in argv:
            create_cmd += ["--command", arg]
        create_result = _run_process(create_cmd, timeout_seconds=10, runner=self.runner)
        if create_result.returncode != 0:
            stderr = create_result.stderr.decode("utf-8", errors="replace").strip()
            stdout = create_result.stdout.decode("utf-8", errors="replace").strip()
            detail = stderr or stdout or "unknown pvesh error"
            raise ProxmoxApiError(detail)
        payload = json.loads(create_result.stdout.decode("utf-8"))
        pid = payload["pid"] if isinstance(payload, dict) else int(payload)
        deadline = time.monotonic() + timeout_seconds
        while True:
            status_cmd = [
                "pvesh",
                "get",
                f"/nodes/{node}/qemu/{vmid}/agent/exec-status",
                "--pid",
                str(pid),
                "--output-format",
                "json",
            ]
            status_result = _run_process(status_cmd, timeout_seconds=10, runner=self.runner)
            if status_result.returncode != 0:
                stderr = status_result.stderr.decode("utf-8", errors="replace").strip()
                stdout = status_result.stdout.decode("utf-8", errors="replace").strip()
                detail = stderr or stdout or "unknown pvesh error"
                raise ProxmoxApiError(detail)
            status_payload = json.loads(status_result.stdout.decode("utf-8"))
            if status_payload.get("exited"):
                stdout, stdout_truncated = _truncate_output(
                    _decode_agent_output(status_payload.get("out-data")),
                    self.config.guest_exec.max_output_bytes,
                )
                stderr, stderr_truncated = _truncate_output(
                    _decode_agent_output(status_payload.get("err-data")),
                    self.config.guest_exec.max_output_bytes,
                )
                return {
                    "backend": "qemu-guest-agent",
                    "target": {"node": node, "vmid": vmid, "type": "qemu"},
                    "command": {"argv": argv, "timeout_seconds": timeout_seconds},
                    "result": {
                        "exit_code": int(status_payload.get("exitcode", 0)),
                        "stdout": stdout,
                        "stderr": stderr,
                        "stdout_truncated": stdout_truncated,
                        "stderr_truncated": stderr_truncated,
                    },
                }
            if time.monotonic() >= deadline:
                raise ProxmoxApiError(f"guest exec timed out after {timeout_seconds}s")
            self.sleep_fn(self.config.guest_exec.poll_interval_seconds)

    def _is_guest_agent_unavailable(self, message: str) -> bool:
        lowered = message.lower()
        return "guest agent" in lowered and (
            "not running" in lowered or "not enabled" in lowered or "not available" in lowered
        )
