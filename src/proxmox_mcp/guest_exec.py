from __future__ import annotations

import base64
import json
import subprocess
import time

from proxmox_mcp.config import AppConfig, SshTargetConfig
from proxmox_mcp.proxmox_api import ProxmoxApiError


def _output_payload(data: bytes, max_output_bytes: int) -> dict[str, object]:
    original_bytes = len(data)
    truncated = original_bytes > max_output_bytes
    if truncated:
        data = data[:max_output_bytes]
    return {
        "text": data.decode("utf-8", errors="replace"),
        "truncated": truncated,
        "original_bytes": original_bytes,
    }


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
    backend_name: str,
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
        raise ProxmoxApiError(
            f"guest exec via {backend_name} timed out after {timeout_seconds}s"
        ) from exc
    except OSError as exc:
        raise ProxmoxApiError(
            f"guest exec via {backend_name} failed to start: {exc}"
        ) from exc


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


def _result_payload(
    *,
    exit_code: int,
    stdout_bytes: bytes,
    stderr_bytes: bytes,
    max_output_bytes: int,
) -> dict[str, object]:
    stdout = _output_payload(stdout_bytes, max_output_bytes)
    stderr = _output_payload(stderr_bytes, max_output_bytes)
    return {
        "exit_code": exit_code,
        "stdout": stdout["text"],
        "stderr": stderr["text"],
        "stdout_truncated": stdout["truncated"],
        "stderr_truncated": stderr["truncated"],
        "stdout_original_bytes": stdout["original_bytes"],
        "stderr_original_bytes": stderr["original_bytes"],
        "max_output_bytes": max_output_bytes,
    }


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
                    raise ProxmoxApiError(
                        "qemu guest agent is unavailable for "
                        f"{node}/{vmid} and no ssh fallback is configured"
                    ) from exc
                return self._exec_ssh(
                    target=target,
                    node=node,
                    vmid=vmid,
                    vm_type=vm_type,
                    argv=argv,
                    timeout_seconds=timeout,
                    reason="guest-agent-unavailable",
                )
        raise ProxmoxApiError(
            f"unsupported guest exec type: {vm_type} (expected qemu or lxc)"
        )

    def _exec_lxc(
        self, *, node: str, vmid: int, argv: list[str], timeout_seconds: int
    ) -> dict:
        local_node = self.config.guest_exec.local_node_name
        if local_node and node != local_node:
            remote_node = _validate_ssh_destination_component(node, field_name="node")
            cmd = ["ssh", remote_node, "pct", "exec", str(vmid), "--", *argv]
            backend = "pct-ssh"
            backend_reason = f"target node {node} differs from local node {local_node}"
        else:
            cmd = ["pct", "exec", str(vmid), "--", *argv]
            backend = "pct"
            backend_reason = None
        result = _run_process(
            cmd,
            timeout_seconds=timeout_seconds,
            backend_name=backend,
            runner=self.runner,
        )
        payload = {
            "backend": backend,
            "target": {"node": node, "vmid": vmid, "type": "lxc"},
            "command": {"argv": argv, "timeout_seconds": timeout_seconds},
            "result": _result_payload(
                exit_code=result.returncode,
                stdout_bytes=result.stdout,
                stderr_bytes=result.stderr,
                max_output_bytes=self.config.guest_exec.max_output_bytes,
            ),
        }
        if backend_reason is not None:
            payload["backend_reason"] = backend_reason
        return payload

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
            backend_name="ssh",
            runner=self.runner,
        )
        return {
            "backend": "ssh",
            "backend_reason": reason,
            "target": {"node": node, "vmid": vmid, "type": vm_type},
            "command": {"argv": argv, "timeout_seconds": timeout_seconds},
            "result": _result_payload(
                exit_code=result.returncode,
                stdout_bytes=result.stdout,
                stderr_bytes=result.stderr,
                max_output_bytes=self.config.guest_exec.max_output_bytes,
            ),
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
        create_result = _run_process(
            create_cmd,
            timeout_seconds=10,
            backend_name="qemu-guest-agent-create",
            runner=self.runner,
        )
        if create_result.returncode != 0:
            stderr = create_result.stderr.decode("utf-8", errors="replace").strip()
            stdout = create_result.stdout.decode("utf-8", errors="replace").strip()
            detail = stderr or stdout or "unknown pvesh error"
            raise ProxmoxApiError(detail)
        try:
            payload = json.loads(create_result.stdout.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise ProxmoxApiError("invalid qemu guest agent create response") from exc
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
            status_result = _run_process(
                status_cmd,
                timeout_seconds=10,
                backend_name="qemu-guest-agent-status",
                runner=self.runner,
            )
            if status_result.returncode != 0:
                stderr = status_result.stderr.decode("utf-8", errors="replace").strip()
                stdout = status_result.stdout.decode("utf-8", errors="replace").strip()
                detail = stderr or stdout or "unknown pvesh error"
                raise ProxmoxApiError(detail)
            try:
                status_payload = json.loads(status_result.stdout.decode("utf-8"))
            except json.JSONDecodeError as exc:
                raise ProxmoxApiError("invalid qemu guest agent status response") from exc
            if status_payload.get("exited"):
                return {
                    "backend": "qemu-guest-agent",
                    "target": {"node": node, "vmid": vmid, "type": "qemu"},
                    "command": {"argv": argv, "timeout_seconds": timeout_seconds},
                    "result": _result_payload(
                        exit_code=int(status_payload.get("exitcode", 0)),
                        stdout_bytes=_decode_agent_output(status_payload.get("out-data")),
                        stderr_bytes=_decode_agent_output(status_payload.get("err-data")),
                        max_output_bytes=self.config.guest_exec.max_output_bytes,
                    ),
                }
            if time.monotonic() >= deadline:
                raise ProxmoxApiError(f"guest exec timed out after {timeout_seconds}s")
            self.sleep_fn(self.config.guest_exec.poll_interval_seconds)

    def _is_guest_agent_unavailable(self, message: str) -> bool:
        lowered = message.lower()
        return "guest agent" in lowered and (
            "not running" in lowered or "not enabled" in lowered or "not available" in lowered
        )
