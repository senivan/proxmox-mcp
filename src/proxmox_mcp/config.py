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
class SshTargetConfig:
    node: str
    vmid: int
    type: str
    host: str
    user: str
    port: int
    private_key_file: Path | None
    known_hosts_file: Path | None
    strict_host_key_checking: bool


@dataclass(frozen=True)
class GuestExecConfig:
    default_timeout_seconds: int
    max_output_bytes: int
    poll_interval_seconds: int
    local_node_name: str | None
    ssh_targets: dict[tuple[str, str, int], SshTargetConfig]


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
    tls_client_common_name: str | None
    tls_client_fingerprint_sha256: str | None


@dataclass(frozen=True)
class AppConfig:
    server: ServerConfig
    tls: TlsConfig
    remote: RemoteConfig
    audit: AuditConfig
    guest_exec: GuestExecConfig
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
    guest_exec_raw = raw.get("guest_exec", {})
    if guest_exec_raw is None:
        guest_exec_raw = {}
    if not isinstance(guest_exec_raw, dict):
        raise ValueError("invalid [guest_exec] table")
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

    guest_exec_timeout = int(guest_exec_raw.get("default_timeout_seconds", 30))
    guest_exec_max_output = int(guest_exec_raw.get("max_output_bytes", 65536))
    guest_exec_poll = int(guest_exec_raw.get("poll_interval_seconds", 1))
    local_node_name_raw = guest_exec_raw.get("local_node_name")
    if guest_exec_timeout < 1:
        raise ValueError("guest_exec.default_timeout_seconds must be >= 1")
    if guest_exec_max_output < 1:
        raise ValueError("guest_exec.max_output_bytes must be >= 1")
    if guest_exec_poll < 1:
        raise ValueError("guest_exec.poll_interval_seconds must be >= 1")
    if local_node_name_raw is not None and (
        not isinstance(local_node_name_raw, str) or not local_node_name_raw.strip()
    ):
        raise ValueError("guest_exec.local_node_name must be a non-empty string")

    ssh_targets_raw = guest_exec_raw.get("ssh_targets", {})
    if ssh_targets_raw is None:
        ssh_targets_raw = {}
    if not isinstance(ssh_targets_raw, dict):
        raise ValueError("guest_exec.ssh_targets must be a table")
    ssh_targets: dict[tuple[str, str, int], SshTargetConfig] = {}
    ssh_target_names: dict[tuple[str, str, int], str] = {}
    for target_name, target_raw in ssh_targets_raw.items():
        if not isinstance(target_raw, dict):
            raise ValueError(f"invalid guest_exec ssh target {target_name}")
        node = target_raw.get("node")
        vmid = target_raw.get("vmid")
        vm_type = target_raw.get("type")
        host = target_raw.get("host")
        user = target_raw.get("user")
        if not isinstance(node, str) or not node.strip():
            raise ValueError(f"missing node for guest_exec ssh target {target_name}")
        if isinstance(vmid, bool) or not isinstance(vmid, int) or vmid < 1:
            raise ValueError(f"invalid vmid for guest_exec ssh target {target_name}")
        if vm_type not in {"qemu", "lxc"}:
            raise ValueError(f"invalid type for guest_exec ssh target {target_name}")
        if not isinstance(host, str) or not host.strip():
            raise ValueError(f"missing host for guest_exec ssh target {target_name}")
        if not isinstance(user, str) or not user.strip():
            raise ValueError(f"missing user for guest_exec ssh target {target_name}")
        port = int(target_raw.get("port", 22))
        if port < 1:
            raise ValueError(f"invalid port for guest_exec ssh target {target_name}")
        private_key_file = _resolve_optional_path(target_raw.get("private_key_file"))
        known_hosts_file = _resolve_optional_path(target_raw.get("known_hosts_file"))
        strict_host_key_checking = bool(target_raw.get("strict_host_key_checking", True))
        ssh_target = SshTargetConfig(
            node=node.strip(),
            vmid=vmid,
            type=vm_type,
            host=host.strip(),
            user=user.strip(),
            port=port,
            private_key_file=private_key_file,
            known_hosts_file=known_hosts_file,
            strict_host_key_checking=strict_host_key_checking,
        )
        logical_key = (ssh_target.node, ssh_target.type, ssh_target.vmid)
        if logical_key in ssh_targets:
            previous_name = ssh_target_names[logical_key]
            raise ValueError(
                "duplicate guest_exec ssh target for "
                f"{logical_key}: {previous_name} and {target_name}"
            )
        ssh_targets[logical_key] = ssh_target
        ssh_target_names[logical_key] = target_name

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
        tls_client_common_name = client_data.get("tls_client_common_name")
        tls_client_fingerprint_sha256 = client_data.get("tls_client_fingerprint_sha256")
        if not isinstance(token, str) or not token:
            raise ValueError(f"missing token for client {client_id}")
        if not isinstance(profile, str) or not profile:
            raise ValueError(f"missing profile for client {client_id}")
        if tls_client_common_name is not None and (
            not isinstance(tls_client_common_name, str) or not tls_client_common_name.strip()
        ):
            raise ValueError(f"invalid tls_client_common_name for client {client_id}")
        if tls_client_fingerprint_sha256 is not None and (
            not isinstance(tls_client_fingerprint_sha256, str)
            or not tls_client_fingerprint_sha256.strip()
        ):
            raise ValueError(
                f"invalid tls_client_fingerprint_sha256 for client {client_id}"
            )
        if profile not in profiles:
            raise ValueError(
                f"client {client_id} references unknown profile {profile}"
            )
        clients[client_id] = ClientConfig(
            client_id=client_id,
            token=token,
            profile=profile,
            tls_client_common_name=tls_client_common_name.strip()
            if isinstance(tls_client_common_name, str)
            else None,
            tls_client_fingerprint_sha256=tls_client_fingerprint_sha256.strip().lower()
            if isinstance(tls_client_fingerprint_sha256, str)
            else None,
        )

    verify_tls_raw = proxmox_raw.get("verify_tls", True)
    if not isinstance(verify_tls_raw, bool):
        raise ValueError("proxmox.verify_tls must be a boolean")
    verify_tls = verify_tls_raw
    allow_insecure_tls = proxmox_raw.get("allow_insecure_tls", False)
    if not isinstance(allow_insecure_tls, bool):
        raise ValueError("proxmox.allow_insecure_tls must be a boolean")
    if not verify_tls and not allow_insecure_tls:
        raise ValueError(
            "proxmox.verify_tls = false requires proxmox.allow_insecure_tls = true"
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
        guest_exec=GuestExecConfig(
            default_timeout_seconds=guest_exec_timeout,
            max_output_bytes=guest_exec_max_output,
            poll_interval_seconds=guest_exec_poll,
            local_node_name=local_node_name_raw.strip()
            if isinstance(local_node_name_raw, str)
            else None,
            ssh_targets=ssh_targets,
        ),
        proxmox=ProxmoxConfig(
            base_url=str(proxmox_raw["base_url"]).rstrip("/"),
            token_id=str(proxmox_raw["token_id"]),
            token_secret=str(proxmox_raw["token_secret"]),
            verify_tls=verify_tls,
        ),
        profiles=profiles,
        clients=clients,
    )
