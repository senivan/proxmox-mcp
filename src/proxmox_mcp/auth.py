from __future__ import annotations

from dataclasses import dataclass
import hashlib

from proxmox_mcp.config import AppConfig
from proxmox_mcp.policy import Principal


@dataclass(frozen=True)
class TlsPeerIdentity:
    common_name: str | None
    fingerprint_sha256: str | None


@dataclass(frozen=True)
class AuthenticatedClient:
    principal: Principal
    tls_peer_identity: TlsPeerIdentity | None


def extract_tls_peer_identity(
    peer_cert: dict | None,
    peer_cert_der: bytes | None,
) -> TlsPeerIdentity | None:
    if not peer_cert and not peer_cert_der:
        return None

    common_name = None
    if isinstance(peer_cert, dict):
        subject = peer_cert.get("subject", ())
        for rdn in subject:
            for key, value in rdn:
                if key == "commonName" and isinstance(value, str) and value.strip():
                    common_name = value.strip()
                    break
            if common_name is not None:
                break

    fingerprint_sha256 = None
    if isinstance(peer_cert_der, bytes) and peer_cert_der:
        fingerprint_sha256 = hashlib.sha256(peer_cert_der).hexdigest()

    return TlsPeerIdentity(
        common_name=common_name,
        fingerprint_sha256=fingerprint_sha256,
    )


def authenticate(
    config: AppConfig,
    authorization_header: str | None,
    client_id_header: str | None,
    tls_peer_identity: TlsPeerIdentity | None = None,
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
    if client.tls_client_common_name is not None:
        if tls_peer_identity is None or tls_peer_identity.common_name is None:
            raise PermissionError("missing required client certificate common name")
        if tls_peer_identity.common_name != client.tls_client_common_name:
            raise PermissionError("client certificate common name mismatch")
    if client.tls_client_fingerprint_sha256 is not None:
        if tls_peer_identity is None or tls_peer_identity.fingerprint_sha256 is None:
            raise PermissionError("missing required client certificate fingerprint")
        if tls_peer_identity.fingerprint_sha256 != client.tls_client_fingerprint_sha256:
            raise PermissionError("client certificate fingerprint mismatch")
    return AuthenticatedClient(
        principal=Principal(
            client_id=client.client_id,
            profile=client.profile,
            capabilities=set(config.profiles[client.profile]),
        ),
        tls_peer_identity=tls_peer_identity,
    )
