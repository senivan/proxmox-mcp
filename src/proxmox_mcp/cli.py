from __future__ import annotations

import argparse
from datetime import timedelta
import logging
import sys

from proxmox_mcp.approval_store import ApprovalStore
from proxmox_mcp.config import VALID_REMOTE_MODES, load_config
from proxmox_mcp.server import create_server


def parse_ttl(value: str | None) -> timedelta | None:
    if value is None:
        return None
    if value.endswith("m"):
        ttl = timedelta(minutes=int(value[:-1]))
    elif value.endswith("h"):
        ttl = timedelta(hours=int(value[:-1]))
    elif value.endswith("d"):
        ttl = timedelta(days=int(value[:-1]))
    else:
        raise ValueError("ttl must use m, h, or d suffix")
    if ttl <= timedelta(0):
        raise ValueError("ttl must be greater than zero")
    return ttl


def build_server_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="proxmox-mcp-server")
    parser.add_argument("--config", required=True, help="Path to config.toml")
    return parser


def build_admin_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="proxmox-mcpctl")
    parser.add_argument("--config", required=True, help="Path to config.toml")
    subparsers = parser.add_subparsers(dest="command", required=True)

    approve_parser = subparsers.add_parser("approve")
    approve_parser.add_argument("client_id")
    approve_parser.add_argument("--ttl", help="Approval duration, for example 30m or 12h")

    revoke_parser = subparsers.add_parser("revoke")
    revoke_parser.add_argument("client_id")

    mode_parser = subparsers.add_parser("mode")
    mode_parser.add_argument("value", choices=sorted(VALID_REMOTE_MODES))

    subparsers.add_parser("list")
    subparsers.add_parser("validate-config")
    subparsers.add_parser("show-mode")
    subparsers.add_parser("show-clients")
    return parser


def run_server(argv: list[str] | None = None) -> int:
    args = build_server_parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    config = load_config(args.config)
    httpd = create_server(config)
    logging.info(
        "listening on %s:%s tls=%s mtls=%s audit=%s",
        config.server.host,
        config.server.port,
        config.tls.enabled,
        config.tls.require_client_cert,
        config.audit.file,
    )
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logging.info("shutting down")
    finally:
        httpd.server_close()
    return 0


def _set_mode(config_path: str, value: str) -> None:
    with open(config_path, "r", encoding="utf-8") as fh:
        content = fh.read()
    replaced = []
    changed = False
    in_remote = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            in_remote = stripped == "[remote]"
        if in_remote and stripped.startswith("mode ="):
            replaced.append(f'mode = "{value}"')
            changed = True
        else:
            replaced.append(line)
    if not changed:
        raise ValueError("could not find mode setting in [remote] section")
    with open(config_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(replaced) + "\n")


def run_admin(argv: list[str] | None = None) -> int:
    args = build_admin_parser().parse_args(argv)
    config = load_config(args.config)
    store = ApprovalStore(config.remote.approval_store)

    if args.command == "validate-config":
        print(f"config ok: {args.config}")
        return 0

    if args.command == "show-mode":
        print(config.remote.mode)
        return 0

    if args.command == "show-clients":
        for client in sorted(config.clients.values(), key=lambda item: item.client_id):
            print(f"{client.client_id}\t{client.profile}")
        return 0

    if args.command == "approve":
        if args.client_id not in config.clients:
            raise ValueError(f"unknown configured client: {args.client_id}")
        record = store.approve(args.client_id, parse_ttl(args.ttl))
        print(
            f"approved {record.client_id} until {record.expires_at.isoformat() if record.expires_at else 'manual revoke'}"
        )
        return 0

    if args.command == "revoke":
        existed = store.revoke(args.client_id)
        if existed:
            print(f"revoked {args.client_id}")
        else:
            print(f"client {args.client_id} was not approved")
        return 0

    if args.command == "list":
        for record in store.list():
            print(
                f"{record.client_id}\t{record.expires_at.isoformat() if record.expires_at else 'manual revoke'}"
            )
        return 0

    if args.command == "mode":
        _set_mode(args.config, args.value)
        print(f"set remote mode to {args.value}")
        return 0

    print(f"unknown command: {args.command}", file=sys.stderr)
    return 1
