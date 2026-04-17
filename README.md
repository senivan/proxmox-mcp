# Proxmox MCP Server

Human-readable MCP server for Proxmox VE 9+ with:

- remote HTTP access
- explicit remote connection approval
- capability-based scope separation
- minimal, auditable Python code

## Current status

This repository contains the v0 scaffold and first vertical slice:

- JSON-RPC over HTTP endpoint at `/mcp`
- local health endpoint at `/healthz`
- optional TLS listener with optional mTLS client verification
- static bearer-token authentication
- client approval gate with `deny`, `allow-listed`, and `open` modes
- structured local audit log in JSON lines format
- capability profiles enforced per tool
- initial read-only Proxmox tools
- read-only detail tools for nodes, VMs, tasks, and storage
- initial operator-only VM power tools: start, shutdown, stop

The current implementation intentionally avoids destructive actions and
arbitrary command execution.

## Layout

```text
src/proxmox_mcp/
  auth.py
  approval_store.py
  cli.py
  config.py
  policy.py
  proxmox_api.py
  server.py
  tools/
tests/
```

## Quick start

1. Create a config:

```toml
[server]
host = "127.0.0.1"
port = 8080

[tls]
enabled = false
cert_file = "./tls/server.crt"
key_file = "./tls/server.key"
client_ca_file = "./tls/ca.crt"
require_client_cert = false

[remote]
mode = "allow-listed"
approval_store = "./state/approvals.json"

[audit]
file = "./state/audit.jsonl"

[proxmox]
base_url = "https://127.0.0.1:8006/api2/json"
token_id = "mcp@pam!default"
token_secret = "replace-me"
verify_tls = false

[profiles.readonly]
capabilities = ["inventory.read", "node.read", "vm.read", "task.read", "storage.read"]

[profiles.operator]
capabilities = ["inventory.read", "node.read", "vm.read", "task.read", "storage.read", "vm.power"]

[clients.ops_laptop]
token = "replace-me"
profile = "readonly"

[clients.ops_console]
token = "replace-me-too"
profile = "operator"
```

2. Allow a client:

```bash
proxmox-mcpctl --config ./config.toml approve ops-laptop --ttl 30m
```

3. Run the server:

```bash
proxmox-mcp-server --config ./config.toml
```

## Admin commands

```bash
proxmox-mcpctl --config ./config.toml mode deny
proxmox-mcpctl --config ./config.toml mode allow-listed
proxmox-mcpctl --config ./config.toml approve ops-laptop --ttl 30m
proxmox-mcpctl --config ./config.toml revoke ops-laptop
proxmox-mcpctl --config ./config.toml list
```

## CI

GitHub Actions runs on every push to `main`/`master`, on pull requests, and on
manual dispatch. The current suite is intentionally small and deterministic:

- `python -m compileall src`
- `python -m unittest discover -s tests -v`

This keeps CI aligned with the checks used during local development.

## Notes

- `allow-listed` is the recommended default.
- The approval gate is local state on the Proxmox host. Remote clients cannot
  self-approve.
- Proxmox access uses API tokens instead of shelling out to `qm` or `pct`.
- Mutating tools are intentionally limited to explicit power actions in v0.
- Storage visibility is separated behind `storage.read`.
- Enable TLS before exposing the listener beyond localhost.
- Enable mTLS by setting `tls.require_client_cert = true` and configuring `tls.client_ca_file`.
- Audit records are appended to `audit.file` as one JSON object per line.
