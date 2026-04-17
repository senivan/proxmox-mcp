from __future__ import annotations

from datetime import UTC, datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import logging
import ssl
from typing import Any

from proxmox_mcp.approval_store import ApprovalStore
from proxmox_mcp.audit import AuditLogger
from proxmox_mcp.auth import authenticate, extract_tls_peer_identity
from proxmox_mcp.config import AppConfig
from proxmox_mcp.proxmox_api import ProxmoxApi, ProxmoxApiError
from proxmox_mcp.tools import call_tool, list_tools


LOG = logging.getLogger(__name__)
MUTATING_TOOLS = {
    "proxmox.vm.start",
    "proxmox.vm.reboot",
    "proxmox.vm.shutdown",
    "proxmox.vm.stop",
}


def create_server(config: AppConfig) -> ThreadingHTTPServer:
    approval_store = ApprovalStore(config.remote.approval_store)
    audit_logger = AuditLogger(config.audit.file)
    proxmox_api = ProxmoxApi(config.proxmox)

    class Handler(BaseHTTPRequestHandler):
        server_version = "ProxmoxMCP/0.1"

        def _send_json(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _json_rpc_error(self, request_id: Any, code: int, message: str) -> None:
            self._send_json(
                HTTPStatus.OK,
                {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}},
            )

        def _require_remote_approval(self, client_id: str) -> None:
            mode = config.remote.mode
            if mode == "deny":
                raise PermissionError("remote access is disabled")
            if mode == "open":
                return
            if not approval_store.is_approved(client_id, now=datetime.now(UTC)):
                raise PermissionError(f"client {client_id} is not approved")

        def _request_target(self, arguments: dict[str, Any]) -> dict[str, Any] | None:
            target = {key: arguments[key] for key in ("node", "vmid", "type") if key in arguments}
            return target or None

        def _tls_peer_identity(self):
            getpeercert = getattr(self.connection, "getpeercert", None)
            if getpeercert is None:
                return None
            peer_cert = getpeercert()
            peer_cert_der = getpeercert(binary_form=True)
            return extract_tls_peer_identity(peer_cert, peer_cert_der)

        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/healthz":
                self._send_json(HTTPStatus.OK, {"status": "ok"})
                return
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})

        def do_POST(self) -> None:  # noqa: N802
            if self.path != "/mcp":
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
                return

            authn = None
            request_id = None
            method = None
            tool_name = None
            arguments: dict[str, Any] = {}
            audit_kind = None
            try:
                length = int(self.headers.get("Content-Length", "0"))
                raw_body = self.rfile.read(length)
                request_body = json.loads(raw_body)
                request_id = request_body.get("id")
                method = request_body.get("method")
                params = request_body.get("params", {})

                authn = authenticate(
                    config,
                    authorization_header=self.headers.get("Authorization"),
                    client_id_header=self.headers.get("X-Client-Id"),
                    tls_peer_identity=self._tls_peer_identity(),
                )
                self._require_remote_approval(authn.principal.client_id)

                if method == "initialize":
                    audit_logger.write(
                        event="mcp_request",
                        client_id=authn.principal.client_id,
                        profile=authn.principal.profile,
                        tls_client_common_name=authn.tls_peer_identity.common_name if authn.tls_peer_identity else None,
                        tls_client_fingerprint_sha256=authn.tls_peer_identity.fingerprint_sha256 if authn.tls_peer_identity else None,
                        method=method,
                        tool_name=None,
                        kind="read",
                        outcome="allowed",
                    )
                    self._send_json(
                        HTTPStatus.OK,
                        {
                            "jsonrpc": "2.0",
                            "id": request_id,
                            "result": {
                                "protocolVersion": "2025-03-26",
                                "serverInfo": {"name": "proxmox-mcp-server", "version": "0.1.0"},
                                "capabilities": {"tools": {}},
                            },
                        },
                    )
                    return

                if method == "tools/list":
                    audit_logger.write(
                        event="mcp_request",
                        client_id=authn.principal.client_id,
                        profile=authn.principal.profile,
                        tls_client_common_name=authn.tls_peer_identity.common_name if authn.tls_peer_identity else None,
                        tls_client_fingerprint_sha256=authn.tls_peer_identity.fingerprint_sha256 if authn.tls_peer_identity else None,
                        method=method,
                        tool_name=None,
                        kind="read",
                        outcome="allowed",
                    )
                    self._send_json(
                        HTTPStatus.OK,
                        {
                            "jsonrpc": "2.0",
                            "id": request_id,
                            "result": {"tools": list_tools(authn.principal)},
                        },
                    )
                    return

                if method == "tools/call":
                    tool_name = params.get("name")
                    arguments = params.get("arguments", {})
                    if not isinstance(tool_name, str):
                        raise ValueError("missing tool name")
                    if not isinstance(arguments, dict):
                        raise ValueError("tool arguments must be an object")
                    audit_kind = "mutating" if tool_name in MUTATING_TOOLS else "read"
                    LOG.info(
                        "tool call kind=%s client=%s profile=%s tool=%s",
                        audit_kind,
                        authn.principal.client_id,
                        authn.principal.profile,
                        tool_name,
                    )
                    result = call_tool(tool_name, arguments, authn.principal, proxmox_api)
                    audit_logger.write(
                        event="mcp_request",
                        client_id=authn.principal.client_id,
                        profile=authn.principal.profile,
                        tls_client_common_name=authn.tls_peer_identity.common_name if authn.tls_peer_identity else None,
                        tls_client_fingerprint_sha256=authn.tls_peer_identity.fingerprint_sha256 if authn.tls_peer_identity else None,
                        method=method,
                        tool_name=tool_name,
                        kind=audit_kind,
                        outcome="allowed",
                        target=self._request_target(arguments),
                    )
                    self._send_json(
                        HTTPStatus.OK,
                        {
                            "jsonrpc": "2.0",
                            "id": request_id,
                            "result": {"content": [{"type": "text", "text": json.dumps(result, indent=2)}]},
                        },
                    )
                    return

                if method == "ping":
                    audit_logger.write(
                        event="mcp_request",
                        client_id=authn.principal.client_id,
                        profile=authn.principal.profile,
                        tls_client_common_name=authn.tls_peer_identity.common_name if authn.tls_peer_identity else None,
                        tls_client_fingerprint_sha256=authn.tls_peer_identity.fingerprint_sha256 if authn.tls_peer_identity else None,
                        method=method,
                        tool_name=None,
                        kind="read",
                        outcome="allowed",
                    )
                    self._send_json(
                        HTTPStatus.OK,
                        {"jsonrpc": "2.0", "id": request_id, "result": {}},
                    )
                    return

                audit_logger.write(
                    event="mcp_request",
                    client_id=authn.principal.client_id,
                    profile=authn.principal.profile,
                    tls_client_common_name=authn.tls_peer_identity.common_name if authn.tls_peer_identity else None,
                    tls_client_fingerprint_sha256=authn.tls_peer_identity.fingerprint_sha256 if authn.tls_peer_identity else None,
                    method=method,
                    tool_name=tool_name,
                    kind=audit_kind,
                    outcome="denied",
                    detail=f"method not found: {method}",
                    target=self._request_target(arguments),
                )
                self._json_rpc_error(request_id, -32601, f"method not found: {method}")
            except PermissionError as exc:
                LOG.warning("request denied: %s", exc)
                audit_logger.write(
                    event="mcp_request",
                    client_id=authn.principal.client_id if authn else None,
                    profile=authn.principal.profile if authn else None,
                    tls_client_common_name=authn.tls_peer_identity.common_name if authn and authn.tls_peer_identity else None,
                    tls_client_fingerprint_sha256=authn.tls_peer_identity.fingerprint_sha256 if authn and authn.tls_peer_identity else None,
                    method=method,
                    tool_name=tool_name,
                    kind=audit_kind,
                    outcome="denied",
                    detail=str(exc),
                    target=self._request_target(arguments),
                )
                self._json_rpc_error(request_id if "request_id" in locals() else None, -32001, str(exc))
            except ProxmoxApiError as exc:
                LOG.error("proxmox api failure: %s", exc)
                audit_logger.write(
                    event="mcp_request",
                    client_id=authn.principal.client_id if authn else None,
                    profile=authn.principal.profile if authn else None,
                    tls_client_common_name=authn.tls_peer_identity.common_name if authn and authn.tls_peer_identity else None,
                    tls_client_fingerprint_sha256=authn.tls_peer_identity.fingerprint_sha256 if authn and authn.tls_peer_identity else None,
                    method=method,
                    tool_name=tool_name,
                    kind=audit_kind,
                    outcome="error",
                    detail=str(exc),
                    target=self._request_target(arguments),
                )
                self._json_rpc_error(request_id if "request_id" in locals() else None, -32002, str(exc))
            except json.JSONDecodeError:
                audit_logger.write(
                    event="mcp_request",
                    client_id=None,
                    profile=None,
                    tls_client_common_name=None,
                    tls_client_fingerprint_sha256=None,
                    method=method,
                    tool_name=tool_name,
                    kind=audit_kind,
                    outcome="error",
                    detail="invalid json",
                    target=None,
                )
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid json"})
            except ValueError as exc:
                audit_logger.write(
                    event="mcp_request",
                    client_id=authn.principal.client_id if authn else None,
                    profile=authn.principal.profile if authn else None,
                    tls_client_common_name=authn.tls_peer_identity.common_name if authn and authn.tls_peer_identity else None,
                    tls_client_fingerprint_sha256=authn.tls_peer_identity.fingerprint_sha256 if authn and authn.tls_peer_identity else None,
                    method=method,
                    tool_name=tool_name,
                    kind=audit_kind,
                    outcome="error",
                    detail=str(exc),
                    target=self._request_target(arguments),
                )
                self._json_rpc_error(request_id if "request_id" in locals() else None, -32602, str(exc))
            except Exception as exc:  # noqa: BLE001
                LOG.exception("unhandled request failure")
                audit_logger.write(
                    event="mcp_request",
                    client_id=authn.principal.client_id if authn else None,
                    profile=authn.principal.profile if authn else None,
                    tls_client_common_name=authn.tls_peer_identity.common_name if authn and authn.tls_peer_identity else None,
                    tls_client_fingerprint_sha256=authn.tls_peer_identity.fingerprint_sha256 if authn and authn.tls_peer_identity else None,
                    method=method,
                    tool_name=tool_name,
                    kind=audit_kind,
                    outcome="error",
                    detail=str(exc),
                    target=self._request_target(arguments),
                )
                self._json_rpc_error(request_id if "request_id" in locals() else None, -32000, str(exc))

        def log_message(self, fmt: str, *args: Any) -> None:
            LOG.info("%s - %s", self.address_string(), fmt % args)

    httpd = ThreadingHTTPServer((config.server.host, config.server.port), Handler)
    if config.tls.enabled:
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(
            certfile=str(config.tls.cert_file),
            keyfile=str(config.tls.key_file),
        )
        if config.tls.client_ca_file is not None:
            context.load_verify_locations(cafile=str(config.tls.client_ca_file))
        context.verify_mode = (
            ssl.CERT_REQUIRED if config.tls.require_client_cert else ssl.CERT_OPTIONAL
        )
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    return httpd
