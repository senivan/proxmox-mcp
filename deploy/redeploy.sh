#!/bin/sh
set -eu

PREFIX=${PREFIX:-/opt/proxmox-mcp-server}
CONFIG_PATH=${CONFIG_PATH:-/etc/proxmox-mcp/config.toml}
SYSTEMD_UNIT=${SYSTEMD_UNIT:-proxmox-mcp.service}
REPO_ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)

if [ "$(id -u)" -ne 0 ]; then
  echo "redeploy.sh must run as root" >&2
  exit 1
fi

echo "Redeploying proxmox-mcp-server from ${REPO_ROOT}"

"${REPO_ROOT}/deploy/install.sh"
"${PREFIX}/.venv/bin/proxmox-mcpctl" --config "${CONFIG_PATH}" validate-config

systemctl daemon-reload
if systemctl is-enabled "${SYSTEMD_UNIT}" >/dev/null 2>&1; then
  systemctl restart "${SYSTEMD_UNIT}"
else
  systemctl enable --now "${SYSTEMD_UNIT}"
fi

systemctl --no-pager --full status "${SYSTEMD_UNIT}"
