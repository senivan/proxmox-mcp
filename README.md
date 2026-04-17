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

For planned feature work and parallelization boundaries, see [ROADMAP.md](ROADMAP.md).

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

   Use [examples/config.toml](examples/config.toml) as the starting point.

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
proxmox-mcpctl --config ./config.toml validate-config
proxmox-mcpctl --config ./config.toml show-mode
proxmox-mcpctl --config ./config.toml show-clients
```

## CI

GitHub Actions runs on every push to `main`/`master`, on pull requests, and on
manual dispatch. The current suite is intentionally small and deterministic:

- `python -m compileall src`
- `python -m unittest discover -s tests -v`

This keeps CI aligned with the checks used during local development.

## Deployment

Target layout on the Proxmox host:

- application: `/opt/proxmox-mcp-server`
- config: `/etc/proxmox-mcp/config.toml`
- TLS: `/etc/proxmox-mcp/tls/`
- SSH fallback material: `/etc/proxmox-mcp/ssh/`
- mutable state: `/var/lib/proxmox-mcp/`
- systemd unit: `/etc/systemd/system/proxmox-mcp.service`

Install from a checked-out repo on the host:

```bash
sudo ./deploy/install.sh
```

Redeploy after pulling new commits while preserving the existing config:

```bash
sudo ./deploy/redeploy.sh
```

After install:

1. Edit `/etc/proxmox-mcp/config.toml`
2. Place TLS cert/key files in `/etc/proxmox-mcp/tls/`
3. Validate the config:

```bash
sudo /opt/proxmox-mcp-server/.venv/bin/proxmox-mcpctl --config /etc/proxmox-mcp/config.toml validate-config
```

4. Enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now proxmox-mcp.service
sudo systemctl status proxmox-mcp.service
```

Useful operational commands:

```bash
sudo journalctl -u proxmox-mcp.service -f
sudo /opt/proxmox-mcp-server/.venv/bin/proxmox-mcpctl --config /etc/proxmox-mcp/config.toml approve ops_console --ttl 30m
sudo /opt/proxmox-mcp-server/.venv/bin/proxmox-mcpctl --config /etc/proxmox-mcp/config.toml list
```

Minimal Proxmox preparation:

1. Create a dedicated Proxmox user and API token for this service
2. Grant only the permissions needed for the enabled tool families
3. If using SSH fallback for guest exec, provision a dedicated key with the narrowest practical guest-side privileges

## Notes

- `allow-listed` is the recommended default.
- The approval gate is local state on the Proxmox host. Remote clients cannot
  self-approve.
- Proxmox access uses API tokens instead of shelling out to `qm` or `pct`.
- Mutating tools are intentionally limited to explicit power actions in v0.
- Storage visibility is separated behind `storage.read`.
- Enable TLS before exposing the listener beyond localhost.
- Enable mTLS by setting `tls.require_client_cert = true` and configuring `tls.client_ca_file`.
- `proxmox.verify_tls` should stay enabled. Setting it to `false` now also requires
  `proxmox.allow_insecure_tls = true` as an explicit opt-in.
- Audit records are appended to `audit.file` as one JSON object per line.
