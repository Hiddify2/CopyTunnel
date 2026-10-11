#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# CopyTunnel lifecycle manager
#
#   install            Build in release mode and install the binary to
#                      /usr/local/bin/copytunnel
#   service <role>     Create and start a systemd unit for the given role
#                      (client|server), using /etc/copytunnel/<role>.toml
#   start|stop|restart Control the systemd service
#   status             Show service + interface status
#   logs               Follow the service journal
#   uninstall          Stop service, remove unit, binary, and config dir
#
# Requires: bash, cargo (for install), systemd, root for most actions.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

BIN_PATH="/usr/local/bin/copytunnel"
CONF_DIR="/etc/copytunnel"
UNIT="/etc/systemd/system/copytunnel.service"
ROLE_DEFAULT="server"

need_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "error: this command must run as root (try: sudo $0 $*)" >&2
        exit 1
    fi
}

cmd_install() {
    need_root
    echo "==> building release binary"
    cargo build --release
    echo "==> installing to ${BIN_PATH}"
    install -m 0755 target/release/copytunnel "${BIN_PATH}"
    setcap cap_net_admin+ep "${BIN_PATH}" 2>/dev/null || true
    mkdir -p "${CONF_DIR}"
    for role in client server; do
        if [[ ! -f "${CONF_DIR}/${role}.toml" && -f "config/${role}.toml" ]]; then
            cp "config/${role}.toml" "${CONF_DIR}/${role}.toml"
            echo "    installed default ${CONF_DIR}/${role}.toml (edit before use!)"
        fi
    done
    echo "==> done. Edit ${CONF_DIR}/<role>.toml, then: sudo $0 service <role>"
}

cmd_service() {
    need_root
    local role="${1:-$ROLE_DEFAULT}"
    if [[ "${role}" != "client" && "${role}" != "server" ]]; then
        echo "error: role must be 'client' or 'server'" >&2
        exit 1
    fi
    local conf="${CONF_DIR}/${role}.toml"
    if [[ ! -f "${conf}" ]]; then
        echo "error: ${conf} not found. Run 'install' first and edit it." >&2
        exit 1
    fi
    echo "==> writing ${UNIT}"
    cat > "${UNIT}" <<EOF
[Unit]
Description=CopyTunnel (${role})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${BIN_PATH} --config ${conf}
Restart=on-failure
RestartSec=2
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now copytunnel.service
    echo "==> started. Follow logs with: sudo $0 logs"
}

cmd_start()   { need_root; systemctl start copytunnel.service; }
cmd_stop()    { need_root; systemctl stop copytunnel.service; }
cmd_restart() { need_root; systemctl restart copytunnel.service; }
cmd_status()  {
    systemctl status copytunnel.service --no-pager || true
    echo
    ip -brief addr show copy0 2>/dev/null || echo "copy0: not up"
}
cmd_logs()    { journalctl -u copytunnel.service -f --no-pager; }

cmd_uninstall() {
    need_root
    systemctl disable --now copytunnel.service 2>/dev/null || true
    rm -f "${UNIT}"
    systemctl daemon-reload
    rm -f "${BIN_PATH}"
    echo "==> removed binary and service. Config left in ${CONF_DIR} (delete manually if desired)."
}

usage() {
    sed -n '2,20p' "$0"
    exit 1
}

case "${1:-}" in
    install)   shift; cmd_install "$@" ;;
    service)   shift; cmd_service "$@" ;;
    start)     cmd_start ;;
    stop)      cmd_stop ;;
    restart)   cmd_restart ;;
    status)    cmd_status ;;
    logs)      cmd_logs ;;
    uninstall) cmd_uninstall ;;
    *)         usage ;;
esac
