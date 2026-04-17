from __future__ import annotations

import json
import ssl
from urllib import error, request

from proxmox_mcp.config import ProxmoxConfig


class ProxmoxApiError(RuntimeError):
    pass


class ProxmoxApi:
    def __init__(self, config: ProxmoxConfig) -> None:
        self.config = config

    def _build_request(
        self,
        path: str,
        *,
        method: str = "GET",
        data: bytes | None = None,
    ) -> request.Request:
        req = request.Request(f"{self.config.base_url}{path}", method=method, data=data)
        req.add_header(
            "Authorization",
            f"PVEAPIToken={self.config.token_id}={self.config.token_secret}",
        )
        req.add_header("Accept", "application/json")
        if data is not None:
            req.add_header("Content-Type", "application/x-www-form-urlencoded")
        return req

    def _context(self) -> ssl.SSLContext | None:
        if self.config.verify_tls:
            return None
        return ssl._create_unverified_context()

    def _request(
        self,
        path: str,
        *,
        method: str = "GET",
        data: bytes | None = None,
    ) -> dict:
        req = self._build_request(path, method=method, data=data)
        try:
            with request.urlopen(req, context=self._context(), timeout=10) as response:
                payload = json.load(response)
        except error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise ProxmoxApiError(
                f"proxmox api request failed with status {exc.code}: {body}"
            ) from exc
        except error.URLError as exc:
            raise ProxmoxApiError(f"proxmox api connection failed: {exc.reason}") from exc
        if not isinstance(payload, dict) or "data" not in payload:
            raise ProxmoxApiError("proxmox api returned invalid payload")
        return payload["data"]

    def get(self, path: str) -> dict:
        return self._request(path, method="GET")

    def post(self, path: str) -> dict:
        return self._request(path, method="POST", data=b"")

    def list_nodes(self) -> list[dict]:
        data = self.get("/nodes")
        if not isinstance(data, list):
            raise ProxmoxApiError("expected list for /nodes")
        return data

    def list_vms(self) -> list[dict]:
        data = self.get("/cluster/resources?type=vm")
        if not isinstance(data, list):
            raise ProxmoxApiError("expected list for vm resources")
        return data

    def get_node(self, node: str) -> dict:
        data = self.get(f"/nodes/{node}/status")
        if not isinstance(data, dict):
            raise ProxmoxApiError("expected object for node status")
        return data

    def get_vm(self, *, node: str, vmid: int, vm_type: str) -> dict:
        if vm_type not in {"qemu", "lxc"}:
            raise ProxmoxApiError(f"unsupported vm type: {vm_type}")
        data = self.get(f"/nodes/{node}/{vm_type}/{vmid}/status/current")
        if not isinstance(data, dict):
            raise ProxmoxApiError("expected object for vm status")
        return data

    def list_tasks(self, limit: int = 25) -> list[dict]:
        data = self.get(f"/cluster/tasks?limit={limit}")
        if not isinstance(data, list):
            raise ProxmoxApiError("expected list for cluster tasks")
        return data

    def get_task(self, upid: str) -> dict:
        node = self._node_from_upid(upid)
        data = self.get(f"/nodes/{node}/tasks/{upid}/status")
        if not isinstance(data, dict):
            raise ProxmoxApiError("expected object for task status")
        return {"node": node, "upid": upid, "status": data}

    def list_storage(self) -> list[dict]:
        data = self.get("/storage")
        if not isinstance(data, list):
            raise ProxmoxApiError("expected list for storage")
        return data

    def get_storage(self, *, node: str, storage: str) -> dict:
        data = self.get(f"/nodes/{node}/storage/{storage}/status")
        if not isinstance(data, dict):
            raise ProxmoxApiError("expected object for storage status")
        return data

    def list_vm_snapshots(self, *, node: str, vmid: int, vm_type: str) -> list[dict]:
        if vm_type not in {"qemu", "lxc"}:
            raise ProxmoxApiError(f"unsupported vm type: {vm_type}")
        data = self.get(f"/nodes/{node}/{vm_type}/{vmid}/snapshot")
        if not isinstance(data, list):
            raise ProxmoxApiError("expected list for vm snapshots")
        return data

    def create_vm_snapshot(
        self, *, node: str, vmid: int, vm_type: str, snapshot: str
    ) -> dict:
        if vm_type not in {"qemu", "lxc"}:
            raise ProxmoxApiError(f"unsupported vm type: {vm_type}")
        upid = self.post(f"/nodes/{node}/{vm_type}/{vmid}/snapshot/{snapshot}")
        return {
            "action": "snapshot.create",
            "target": {
                "node": node,
                "vmid": vmid,
                "type": vm_type,
                "snapshot": snapshot,
            },
            "task": {
                "upid": upid,
            },
        }

    def delete_vm_snapshot(
        self, *, node: str, vmid: int, vm_type: str, snapshot: str
    ) -> dict:
        if vm_type not in {"qemu", "lxc"}:
            raise ProxmoxApiError(f"unsupported vm type: {vm_type}")
        upid = self._request(
            f"/nodes/{node}/{vm_type}/{vmid}/snapshot/{snapshot}",
            method="DELETE",
        )
        return {
            "action": "snapshot.delete",
            "target": {
                "node": node,
                "vmid": vmid,
                "type": vm_type,
                "snapshot": snapshot,
            },
            "task": {
                "upid": upid,
            },
        }

    def vm_action(self, *, node: str, vmid: int, vm_type: str, action: str) -> dict:
        if vm_type not in {"qemu", "lxc"}:
            raise ProxmoxApiError(f"unsupported vm type: {vm_type}")
        if action not in {"start", "reboot", "shutdown", "stop"}:
            raise ProxmoxApiError(f"unsupported vm action: {action}")
        upid = self.post(f"/nodes/{node}/{vm_type}/{vmid}/status/{action}")
        return {
            "action": action,
            "target": {
                "node": node,
                "vmid": vmid,
                "type": vm_type,
            },
            "task": {
                "upid": upid,
            },
        }

    def _node_from_upid(self, upid: str) -> str:
        parts = upid.split(":")
        if len(parts) < 2 or parts[0] != "UPID":
            raise ProxmoxApiError("invalid UPID format")
        node = parts[1].strip()
        if not node:
            raise ProxmoxApiError("invalid UPID format")
        return node
