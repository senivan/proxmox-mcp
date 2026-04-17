from __future__ import annotations

from dataclasses import dataclass

from proxmox_mcp.config import AppConfig
from proxmox_mcp.policy import Principal


@dataclass(frozen=True)
class AuthenticatedClient:
    principal: Principal


def authenticate(
    config: AppConfig,
    authorization_header: str | None,
    client_id_header: str | None,
) -> AuthenticatedClient:
    if not client_id_header:
        raise PermissionError("missing X-Client-Id header")
    client = config.clients.get(client_id_header)
    if client is None:
        raise PermissionError("unknown client")
    if not authorization_header or not authorization_header.startswith("Bearer "):
        raise PermissionError("missing bearer token")
    token = authorization_header.removeprefix("Bearer ").strip()
    if token != client.token:
        raise PermissionError("invalid bearer token")
    return AuthenticatedClient(
        principal=Principal(
            client_id=client.client_id,
            profile=client.profile,
            capabilities=set(config.profiles[client.profile]),
        )
    )
