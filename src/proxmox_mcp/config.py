from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import tomllib


VALID_REMOTE_MODES = {"deny", "allow-listed", "open"}


@dataclass(frozen=True)
class ServerConfig:
    host: str
    port: int


@dataclass(frozen=True)
class TlsConfig:
    enabled: bool
    cert_file: Path | None
    key_file: Path | None
    client_ca_file: Path | None
    require_client_cert: bool


@dataclass(frozen=True)
class RemoteConfig:
    mode: str
    approval_store: Path


@dataclass(frozen=True)
class AuditConfig:
    file: Path


@dataclass(frozen=True)
class ProxmoxConfig:
    base_url: str
    token_id: str
    token_secret: str
    verify_tls: bool


@dataclass(frozen=True)
class ClientConfig:
    client_id: str
    token: str
    profile: str


@dataclass(frozen=True)
class AppConfig:
    server: ServerConfig
    tls: TlsConfig
    remote: RemoteConfig
    audit: AuditConfig
    proxmox: ProxmoxConfig
    profiles: dict[str, set[str]]
    clients: dict[str, ClientConfig]


def _require_table(raw: dict, key: str) -> dict:
    value = raw.get(key)
    if not isinstance(value, dict):
        raise ValueError(f"missing or invalid [{key}] table")
    return value


def load_config(path: str | Path) -> AppConfig:
    config_path = Path(path)
    with config_path.open("rb") as fh:
        raw = tomllib.load(fh)

    server_raw = _require_table(raw, "server")
    tls_raw = _require_table(raw, "tls")
    remote_raw = _require_table(raw, "remote")
    audit_raw = _require_table(raw, "audit")
    proxmox_raw = _require_table(raw, "proxmox")
    profiles_raw = _require_table(raw, "profiles")
    clients_raw = _require_table(raw, "clients")

    mode = remote_raw.get("mode", "deny")
    if mode not in VALID_REMOTE_MODES:
        raise ValueError(f"invalid remote mode: {mode}")

    def _resolve_optional_path(value: object) -> Path | None:
        if value is None:
            return None
        if not isinstance(value, str) or not value:
            raise ValueError("invalid path value")
        return (config_path.parent / value).resolve()

    tls_enabled = bool(tls_raw.get("enabled", False))
    cert_file = _resolve_optional_path(tls_raw.get("cert_file"))
    key_file = _resolve_optional_path(tls_raw.get("key_file"))
    client_ca_file = _resolve_optional_path(tls_raw.get("client_ca_file"))
    require_client_cert = bool(tls_raw.get("require_client_cert", False))
    if require_client_cert and not tls_enabled:
        raise ValueError("tls.require_client_cert requires tls.enabled = true")
    if tls_enabled and (cert_file is None or key_file is None):
        raise ValueError("tls.enabled requires tls.cert_file and tls.key_file")
    if require_client_cert and client_ca_file is None:
        raise ValueError("tls.require_client_cert requires tls.client_ca_file")

    profiles: dict[str, set[str]] = {}
    for profile_name, profile_data in profiles_raw.items():
        if not isinstance(profile_data, dict):
            raise ValueError(f"invalid profile definition for {profile_name}")
        capabilities = profile_data.get("capabilities", [])
        if not isinstance(capabilities, list) or not all(
            isinstance(item, str) for item in capabilities
        ):
            raise ValueError(f"invalid capabilities for profile {profile_name}")
        profiles[profile_name] = set(capabilities)

    clients: dict[str, ClientConfig] = {}
    for client_id, client_data in clients_raw.items():
        if not isinstance(client_data, dict):
            raise ValueError(f"invalid client definition for {client_id}")
        token = client_data.get("token")
        profile = client_data.get("profile")
        if not isinstance(token, str) or not token:
            raise ValueError(f"missing token for client {client_id}")
        if not isinstance(profile, str) or not profile:
            raise ValueError(f"missing profile for client {client_id}")
        if profile not in profiles:
            raise ValueError(
                f"client {client_id} references unknown profile {profile}"
            )
        clients[client_id] = ClientConfig(
            client_id=client_id,
            token=token,
            profile=profile,
        )

    return AppConfig(
        server=ServerConfig(
            host=str(server_raw.get("host", "127.0.0.1")),
            port=int(server_raw.get("port", 8080)),
        ),
        tls=TlsConfig(
            enabled=tls_enabled,
            cert_file=cert_file,
            key_file=key_file,
            client_ca_file=client_ca_file,
            require_client_cert=require_client_cert,
        ),
        remote=RemoteConfig(
            mode=mode,
            approval_store=(config_path.parent / str(remote_raw["approval_store"])).resolve(),
        ),
        audit=AuditConfig(
            file=(config_path.parent / str(audit_raw["file"])).resolve(),
        ),
        proxmox=ProxmoxConfig(
            base_url=str(proxmox_raw["base_url"]).rstrip("/"),
            token_id=str(proxmox_raw["token_id"]),
            token_secret=str(proxmox_raw["token_secret"]),
            verify_tls=bool(proxmox_raw.get("verify_tls", True)),
        ),
        profiles=profiles,
        clients=clients,
    )
