# Copilot instructions for proxmox-mcp

Treat this repository as security-sensitive infrastructure code for a Proxmox MCP server.

## Core expectations
- Prefer correctness, explicitness, and auditability over cleverness.
- Keep diffs small and focused.
- Do not refactor unrelated code.
- Do not introduce new dependencies unless there is a clear need. Prefer the Python standard library when practical.
- Preserve the repository’s minimal and debuggable style.

## Project shape
- This project is a Python 3.11+ setuptools repo.
- The main entrypoints are `proxmox-mcp-server` and `proxmox-mcpctl`.
- The server exposes a JSON-RPC MCP endpoint at `/mcp` and a health endpoint at `/healthz`.
- Remote access, authentication, approval, capability checks, and audit logging are core features, not optional decoration.

## Safety and security
- Do not weaken TLS, mTLS, bearer auth, client approval, capability checks, or audit logging.
- Treat `deny`, `allow-listed`, and `open` remote modes as security-sensitive behavior.
- Prefer `allow-listed` behavior and least privilege by default.
- Never hardcode tokens, secrets, hostnames, fingerprints, or local filesystem paths that are environment-specific.
- Do not bypass approval checks, capability checks, or argument validation for convenience.
- Treat guest execution, snapshot deletion, stop, reboot, and shutdown flows as high-risk paths.
- Do not add destructive actions or broaden mutating behavior unless explicitly requested.

## Proxmox API expectations
- Use the Proxmox API, not shell-outs to `qm`, `pct`, or ad hoc command wrappers.
- Do not invent Proxmox endpoints, parameters, or response shapes.
- Validate node, vmid, type, storage, snapshot, and task identifiers explicitly.
- Keep tool outputs structured, stable, and easy to inspect.
- For mutating operations, preserve task visibility and return enough context to understand what target was affected.

## MCP and tooling behavior
- Keep MCP method handling explicit and predictable.
- Preserve clear separation between:
  - auth
  - approval
  - policy/capabilities
  - validation
  - Proxmox API calls
  - transport/server behavior
- When adding a tool:
  - add or update capability mapping
  - add or update argument validation
  - keep the schema strict
  - add tests
  - update docs and examples if behavior changes
- Do not silently expand a profile’s capabilities.

## Configuration rules
- Keep config parsing strict and fail fast on invalid values.
- Preserve explicit validation for TLS, client certs, insecure TLS opt-ins, guest exec config, profiles, and clients.
- Resolve paths carefully and keep config behavior deterministic.
- If you change config surface area, update docs and example config together.

## Testing and validation
- Before finalizing changes, run:
  - `python -m compileall src`
  - `python -m unittest discover -s tests -v`
- Add or update tests for behavior changes, especially around:
  - auth
  - approval
  - config validation
  - policy/capability enforcement
  - server request handling
  - TLS behavior
  - tool validation
  - Proxmox API behavior
- Do not claim a change is tested unless the tests were actually run.

## Documentation and operations
- If a change affects config, deployment, auth, TLS, approval, capabilities, tool surface, or operator workflow, update README and relevant example/deploy files.
- Keep deployment guidance aligned with actual install and runtime behavior.
- Prefer operator-readable error messages over vague exceptions.

## Style preferences
- Prefer straightforward functions and dataclasses over unnecessary abstraction.
- Make error handling explicit.
- Favor readable control flow over compact tricks.
- Do not add framework-like complexity to simple modules.
- Keep names technical and literal.

## What to avoid
- Do not invent tests, validation results, or security properties.
- Do not silently change authentication semantics.
- Do not silently widen capabilities or approval behavior.
- Do not hide risky behavior behind “helper” abstractions.
- Do not make mutating operations easier to trigger without strong justification.
