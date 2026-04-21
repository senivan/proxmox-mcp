# Repository Guidelines

## Project Structure & Module Organization

This is a Python 3.11+ package using a `src/` layout. Core code lives in
`src/proxmox_mcp/`: `server.py` handles HTTP/MCP requests, `cli.py` exposes
console entry points, `config.py` loads TOML configuration, `policy.py` enforces
capabilities, and `proxmox_api.py` wraps Proxmox API calls. Tests are in
`tests/` and mirror the main modules with `test_*.py` files. Example
configuration lives in `examples/config.toml`. Deployment assets are under
`deploy/`, including the systemd unit and install/redeploy scripts.

## Build, Test, and Development Commands

- `python -m compileall src` checks that source files compile.
- `python -m unittest discover -s tests -v` runs the full local test suite.
- `pip install -e .` installs the package and exposes `proxmox-mcp-server` and
  `proxmox-mcpctl` for local development.
- `proxmox-mcpctl --config ./config.toml validate-config` validates a runtime
  configuration file.
- `proxmox-mcp-server --config ./config.toml` starts the MCP HTTP server.

## Coding Style & Naming Conventions

Keep code straightforward and stdlib-oriented unless a dependency is clearly
justified. Follow the existing style: 4-space indentation, type annotations for
public functions and helpers, dataclass-style configuration objects where
appropriate, and explicit error messages. Use `snake_case` for modules,
functions, variables, and test methods. Preserve the current small-module
organization instead of adding broad abstractions.

## Testing Guidelines

Tests use Python `unittest` and are run by discovery from `tests/`. Name test
files `test_<module>.py` and test methods `test_<behavior>`. Add focused tests
next to the affected module, especially for policy decisions, config parsing,
authentication, audit output, and request handling. Keep tests deterministic and
avoid requiring a live Proxmox host.

## Commit & Pull Request Guidelines

Recent history mostly uses concise imperative commit subjects such as
`policy: relax cluster summary access scope` and `test: expand coverage across auth and config`.
Prefer `<area>: <specific change>` under 72 characters. Pull requests should
state the summary, rationale, scope, validation run, and any compatibility or
deployment impact. For behavior changes, include the affected commands,
configuration keys, API/tool names, or security posture.

## Security & Configuration Notes

Treat `examples/config.toml` as a template only. Do not commit real Proxmox API
tokens, TLS keys, approval stores, audit logs, or SSH material. Keep TLS
verification enabled unless explicitly testing insecure local setups, and note
any change that expands mutating capabilities or remote access behavior.
