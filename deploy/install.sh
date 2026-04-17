#!/bin/sh
set -eu

PREFIX=${PREFIX:-/opt/proxmox-mcp-server}
ETC_DIR=${ETC_DIR:-/etc/proxmox-mcp}
STATE_DIR=${STATE_DIR:-/var/lib/proxmox-mcp}
SYSTEMD_UNIT_DIR=${SYSTEMD_UNIT_DIR:-/etc/systemd/system}
REPO_ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)

echo "Installing proxmox-mcp-server into ${PREFIX}"

install -d -m 0755 "${PREFIX}"
install -d -m 0755 "${ETC_DIR}"
install -d -m 0700 "${ETC_DIR}/tls"
install -d -m 0700 "${ETC_DIR}/ssh"
install -d -m 0750 "${STATE_DIR}"

python3 -m venv "${PREFIX}/.venv"
"${PREFIX}/.venv/bin/pip" install --upgrade pip setuptools >/dev/null
"${PREFIX}/.venv/bin/pip" install --no-build-isolation "${REPO_ROOT}" >/dev/null

if [ ! -f "${ETC_DIR}/config.toml" ]; then
  install -m 0640 "${REPO_ROOT}/examples/config.toml" "${ETC_DIR}/config.toml"
  echo "Installed default config to ${ETC_DIR}/config.toml"
fi

install -m 0644 "${REPO_ROOT}/deploy/proxmox-mcp.service" "${SYSTEMD_UNIT_DIR}/proxmox-mcp.service"

echo "Installation complete."
echo "Next steps:"
echo "  1. Edit ${ETC_DIR}/config.toml"
echo "  2. Place TLS materials in ${ETC_DIR}/tls/"
echo "  3. Run: systemctl daemon-reload"
echo "  4. Run: systemctl enable --now proxmox-mcp.service"
