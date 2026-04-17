# Roadmap

This document defines the next feature tracks for `proxmox-mcp-server`, the
capability boundaries they require, and which work can safely run in parallel.

The goal is to keep the codebase boring, auditable, and safe on a Proxmox host.
We should prefer narrow tools and explicit policy over generic escape hatches.

## Current baseline

Implemented today:

- remote HTTP MCP endpoint with TLS and optional mTLS
- approval-gated remote access
- bearer-token auth with optional TLS client identity binding
- structured audit log
- read-only inventory, node, task, VM, and storage tools
- VM power tools: `start`, `shutdown`, `reboot`, `stop`
- snapshot tools: `list`, `create`, `delete`
- bounded guest exec with guest-agent, LXC, and SSH fallback paths
- deployment scripts and `systemd` unit

Not implemented yet:

- typed VM/CT config mutation
- destructive lifecycle actions
- snapshot rollback
- restore flows
- richer cluster/network read-only tools
- higher-fidelity guest exec diagnostics and output metadata

## Priorities

The next feature work should follow this order:

1. Read-only expansion
2. Guest exec hardening
3. Snapshot rollback with stronger safety semantics
4. Typed config mutation
5. Destructive-action framework
6. Destructive lifecycle actions

This order is intentional. It keeps the highest-risk capabilities gated until
the policy, confirmation, and audit model are stronger.

## Capability roadmap

Existing capabilities:

- `inventory.read`
- `vm.read`
- `task.read`
- `storage.read`
- `vm.power`
- `vm.snapshot.read`
- `vm.snapshot.write`
- `vm.guest.exec`

Planned additions:

- `network.read`
- `cluster.read`
- `vm.snapshot.rollback`
- `vm.config.metadata`
- `vm.config.compute`
- `vm.config.disk`
- `vm.lifecycle.destructive`
- `ct.lifecycle.destructive`

Rules:

- Do not introduce a generic `admin` or `write-all` capability.
- Keep read, mutating, and destructive scopes separate.
- Favor one capability family per feature family.
- New mutating tools should emit structured audit events with explicit targets.

## Feature tracks

### Track 1: Read-only expansion

Scope:

- cluster summary tool(s)
- network read-only tools
- richer VM/CT detail normalization
- better storage detail consistency

Why:

- low operational risk
- high operator value
- low policy complexity

Likely files:

- `src/proxmox_mcp/proxmox_api.py`
- `src/proxmox_mcp/tools/__init__.py`
- `src/proxmox_mcp/validation.py`
- tests covering tool and adapter behavior

Parallelization:

- safe to parallelize if the worker stays inside new read-only tools and related
  tests

### Track 2: Guest exec hardening

Scope:

- clearer backend-selection diagnostics
- explicit output truncation metadata
- more precise timeout and transport errors
- remote-node awareness for LXC execution

Why:

- the current feature exists, but operational failure modes are still opaque

Likely files:

- `src/proxmox_mcp/guest_exec.py`
- `src/proxmox_mcp/config.py`
- `src/proxmox_mcp/tools/__init__.py`
- guest-exec-specific tests

Parallelization:

- safe to parallelize if the worker avoids broad config/policy changes

### Track 3: Snapshot rollback

Scope:

- `proxmox.vm.snapshot.rollback`
- separate capability gate
- stricter audit trail than create/delete
- request confirmation semantics if needed

Why:

- more dangerous than create/delete, but still narrower than delete/restore

Likely files:

- `src/proxmox_mcp/policy.py`
- `src/proxmox_mcp/validation.py`
- `src/proxmox_mcp/proxmox_api.py`
- `src/proxmox_mcp/tools/__init__.py`
- `src/proxmox_mcp/server.py`

Parallelization:

- should stay on the main thread because it touches shared policy and
  mutating-tool boundaries

### Track 4: Typed config mutation

Scope:

- metadata changes first: tags, description/name
- compute changes second: cores, memory
- explicit typed tools only

Non-goals:

- no generic "set any key" tool
- no pass-through config update endpoint

Why:

- config changes have real blast radius and need narrow interfaces

Likely files:

- `src/proxmox_mcp/policy.py`
- `src/proxmox_mcp/validation.py`
- `src/proxmox_mcp/proxmox_api.py`
- `src/proxmox_mcp/tools/__init__.py`
- `src/proxmox_mcp/server.py`

Parallelization:

- should stay on the main thread

### Track 5: Destructive-action framework

Scope:

- explicit confirmation token in request
- runtime switch to disable destructive tools entirely
- stronger audit event schema for dangerous actions

Why:

- destructive tools should not exist before the framework does

Likely files:

- `src/proxmox_mcp/config.py`
- `src/proxmox_mcp/policy.py`
- `src/proxmox_mcp/validation.py`
- `src/proxmox_mcp/server.py`
- tests for negative paths and audit coverage

Parallelization:

- keep on the main thread

### Track 6: Destructive lifecycle actions

Scope:

- `vm.delete`
- `ct.delete`
- restore flows only after delete semantics are proven

Non-goals:

- no bulk destructive operations
- no host shell passthrough

Parallelization:

- only after the destructive framework is merged

## Parallel work rules

Good worker tasks:

- bounded read-only tool additions
- guest exec diagnostics and output-shape hardening
- deployment/docs polish
- isolated test additions

Main-thread tasks:

- policy model changes
- auth changes
- config schema changes with broad blast radius
- core server protocol behavior
- destructive-action scaffolding
- typed config mutation

## First parallel batch

The first delegated batch should stay low-conflict:

1. Read-only expansion
   Owner area:
   `src/proxmox_mcp/proxmox_api.py`, `src/proxmox_mcp/tools/__init__.py`,
   read-only validation/tests

2. Guest exec hardening
   Owner area:
   `src/proxmox_mcp/guest_exec.py`, guest-exec-specific config/tests

3. Deployment and operator polish
   Owner area:
   `deploy/`, `README.md`, CLI/config validation tests

The main thread should reserve:

- policy changes
- server mutating-action model
- snapshot rollback design
- future config mutation design

## PR guidelines for this roadmap

Each feature PR should:

- stay inside one track
- add or update tests for the changed contract
- document config or capability changes explicitly
- avoid opportunistic refactors
- call out rollout or compatibility impact in the PR body
