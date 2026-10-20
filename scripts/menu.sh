#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# CopyTunnel — interactive manager (whiptail)
#
# Two forwarding methods:
#   • TUN              encrypted layer-3 tunnel (TUN device + UDP transport)
#   • Transparent Proxy  sing-box tproxy + iptables → CopyTunnel SOCKS5 → TCP
#
# Per method: Install / Status / (Add / Remove) / Uninstall.
# Options: DNS · Update · Generate key · Connectivity test · Uninstall all.
#
# Re-open anytime with:  copytunnel-menu   (or: ct)
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail

# ── Paths ─────────────────────────────────────────────────────────────────────
CT_DIR="/opt/copytunnel"
CONF_DIR="/etc/copytunnel"
BIN="/usr/local/bin/copytunnel"
REPO="Hiddify2/CopyTunnel"
SB_BIN="/usr/local/bin/sing-box"

TUN_CONF="$CONF_DIR/tun.toml"
PROXY_CONF="$CONF_DIR/proxy.toml"
SB_CONF="$CONF_DIR/singbox.json"
BYPASS_LIST="$CONF_DIR/bypass.list"

TUN_SVC="copytunnel-tun"
PROXY_SVC="copytunnel-proxy"
TPROXY_SVC="copytunnel-tproxy"
SB_SVC="sing-box"

BACKTITLE="CopyTunnel Manager"

# ── Root check ────────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    if command -v sudo >/dev/null 2>&1; then exec sudo -E bash "$0" "$@"; fi
    echo "Please run as root (sudo)." >&2; exit 1
fi
mkdir -p "$CONF_DIR"
command -v whiptail >/dev/null 2>&1 || { echo "whiptail is required. Run scripts/install.sh first." >&2; exit 1; }

# ── Package manager ───────────────────────────────────────────────────────────
if   command -v apt-get >/dev/null 2>&1; then PKG=apt
elif command -v dnf      >/dev/null 2>&1; then PKG=dnf
elif command -v yum      >/dev/null 2>&1; then PKG=yum
else PKG=""; fi

pkg_install() {
    case "$PKG" in
        apt) DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" ;;
        dnf|yum) "$PKG" install -y "$@" ;;
        *) return 1 ;;
    esac
}

# ── whiptail helpers ──────────────────────────────────────────────────────────
wt_menu()  { # title  text  tag1 item1 tag2 item2 ...
    local title="$1" text="$2"; shift 2
    whiptail --backtitle "$BACKTITLE" --title "$title" --menu "$text" 22 74 12 "$@" 3>&1 1>&2 2>&3
}
wt_input() { # title  text  default
    whiptail --backtitle "$BACKTITLE" --title "$1" --inputbox "$2" 10 70 "${3:-}" 3>&1 1>&2 2>&3
}
wt_pass()  { whiptail --backtitle "$BACKTITLE" --title "$1" --passwordbox "$2" 10 70 3>&1 1>&2 2>&3; }
wt_yesno() { whiptail --backtitle "$BACKTITLE" --title "$1" --yesno "$2" 12 70; }
wt_msg()   { whiptail --backtitle "$BACKTITLE" --title "$1" --msgbox "$2" 16 74; }

# Numeric port prompt with 1-65535 validation loop.
ask_port() { # title  text  default  -> echoes port
    local v
    while true; do
        v="$(wt_input "$1" "$2" "$3")" || return 1
        if [[ "$v" =~ ^[0-9]+$ ]] && (( v >= 1 && v <= 65535 )); then echo "$v"; return 0; fi
        wt_msg "Invalid port" "Please enter a number between 1 and 65535."
    done
}

svc_active() { systemctl is-active --quiet "$1" && echo "active" || echo "inactive"; }

# ── Cipher chooser ────────────────────────────────────────────────────────────
choose_cipher() {
    wt_menu "Encryption method" "Pick the wire cipher (must match the other side):" \
        "chacha20poly1305"  "AEAD · fast on any CPU (recommended)" \
        "xchacha20poly1305" "AEAD · 192-bit nonce, best at high rates" \
        "aes256gcm"         "AEAD · fastest with AES-NI" \
        "aes128gcm"         "AEAD · 128-bit key, slightly faster AES" \
        "xor"               "Obfuscation only (NOT confidential)" \
        "none"              "Plaintext (debugging only)"
}

gen_key() { openssl rand -hex 32 2>/dev/null || head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n'; }

# Ask for / generate a pre-shared key.
ask_psk() {
    if wt_yesno "Pre-shared key" "Generate a strong random key automatically?\n\n(Choose No to type your own; it must match the peer and be >= 16 chars.)"; then
        gen_key
    else
        local k
        while true; do
            k="$(wt_pass "Pre-shared key" "Enter the shared secret (>= 16 characters):")" || return 1
            [[ ${#k} -ge 16 ]] && { echo "$k"; return 0; }
            wt_msg "Too short" "The key must be at least 16 characters."
        done
    fi
}

default_iface() { ip route show default 2>/dev/null | awk '/default/{print $5; exit}'; }

# ── Binary / sing-box provisioning ────────────────────────────────────────────
detect_arch_rust() {
    case "$(uname -m)" in
        x86_64|amd64)  echo "x86_64-unknown-linux-gnu" ;;
        aarch64|arm64) echo "aarch64-unknown-linux-gnu" ;;
        *) echo "" ;;
    esac
}
detect_arch_sb() {
    case "$(uname -m)" in
        x86_64|amd64)  echo "amd64" ;;
        aarch64|arm64) echo "arm64" ;;
        armv7l)        echo "armv7" ;;
        *) echo "" ;;
    esac
}

ensure_binary() {
    [[ -x "$BIN" ]] && return 0
    local arch url; arch="$(detect_arch_rust)"
    if [[ -n "$arch" ]]; then
        url="https://github.com/${REPO}/releases/latest/download/copytunnel-${arch}"
        curl -fsSL "$url" -o "$BIN.tmp" 2>/dev/null && chmod +x "$BIN.tmp" && mv "$BIN.tmp" "$BIN" && return 0
        rm -f "$BIN.tmp"
    fi
    if command -v cargo >/dev/null 2>&1 && [[ -f "$CT_DIR/Cargo.toml" ]]; then
        ( cd "$CT_DIR" && cargo build --release ) && install -m0755 "$CT_DIR/target/release/copytunnel" "$BIN" && return 0
    fi
    return 1
}

install_singbox() {
    [[ -x "$SB_BIN" ]] && return 0
    local arch ver tarball url tmp; arch="$(detect_arch_sb)"
    [[ -n "$arch" ]] || return 1
    ver="$(curl -fsSL https://api.github.com/repos/SagerNet/sing-box/releases/latest 2>/dev/null | jq -r '.tag_name' | sed 's/^v//')"
    [[ -n "$ver" && "$ver" != "null" ]] || ver="1.11.0"
    tarball="sing-box-${ver}-linux-${arch}.tar.gz"
    url="https://github.com/SagerNet/sing-box/releases/download/v${ver}/${tarball}"
    tmp="$(mktemp -d)"
    if curl -fsSL "$url" -o "$tmp/$tarball" 2>/dev/null; then
        tar -xzf "$tmp/$tarball" -C "$tmp" 2>/dev/null
        local f; f="$(find "$tmp" -name sing-box -type f | head -1)"
        [[ -n "$f" ]] && install -m0755 "$f" "$SB_BIN" && { rm -rf "$tmp"; return 0; }
    fi
    rm -rf "$tmp"; return 1
}

# ── systemd unit writer ───────────────────────────────────────────────────────
write_unit() { # name  description  execstart  [after] [extra-exec]
    local name="$1" desc="$2" exec="$3" after="${4:-network-online.target}" extra="${5:-}"
    cat > "/etc/systemd/system/${name}.service" <<EOF
[Unit]
Description=${desc}
After=${after}
Wants=network-online.target

[Service]
Type=simple
ExecStart=${exec}
${extra}
Restart=on-failure
RestartSec=2
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
}

enable_start() { systemctl enable --now "$1" >/dev/null 2>&1; }
stop_disable() { systemctl disable --now "$1" >/dev/null 2>&1 || true; rm -f "/etc/systemd/system/$1.service"; systemctl daemon-reload; }

# ═════════════════════════════════════════════════════════════════════════════
#  METHOD 1 — TUN
# ═════════════════════════════════════════════════════════════════════════════
tun_install() {
    ensure_binary || { wt_msg "Binary missing" "Could not obtain the copytunnel binary. Try Options → Update, or install Rust and rebuild."; return; }

    local role
    role="$(wt_menu "TUN · role" "Set up this host as:" \
        "client" "Edge/near-user side (captures traffic)" \
        "server" "Exit side (routes to the internet)")" || return

    local psk cipher obfs
    psk="$(ask_psk)" || return
    cipher="$(choose_cipher)" || return
    if wt_yesno "Obfuscation" "Enable extra whole-frame XOR obfuscation?\n(Must match on both sides. Adds no crypto strength.)"; then obfs=true; else obfs=false; fi

    if [[ "$role" == "client" ]]; then
        local sip sport tip tpip
        sip="$(wt_input "Server address" "Enter the CopyTunnel SERVER public IP:" )" || return
        sport="$(ask_port "Server UDP port" "Enter the server's TUN/UDP port:" "51822")" || return
        tip="$(wt_input "Local TUN IP" "Local TUN address (swap with server):" "10.66.0.2")" || return
        tpip="$(wt_input "Peer TUN IP" "Server's TUN address:" "10.66.0.1")" || return
        cat > "$TUN_CONF" <<EOF
role = "client"
mode = "tun"
server_addr = "${sip}:${sport}"
pre_shared_key = "${psk}"
encryption = "${cipher}"
obfuscate = ${obfs}
tun_name = "copy0"
tun_ip = "${tip}"
tun_peer_ip = "${tpip}"
mtu = 1380
keepalive_secs = 15
log_level = "info"
EOF
    else
        local lport iface tip tpip nat
        lport="$(ask_port "Listen UDP port" "Port to listen on for TUN clients:" "51822")" || return
        iface="$(wt_input "Network interface" "Physical NIC for NAT (MASQUERADE):" "$(default_iface)")" || return
        tip="$(wt_input "Local TUN IP" "Server's TUN address:" "10.66.0.1")" || return
        tpip="$(wt_input "Peer TUN IP" "Client's TUN address:" "10.66.0.2")" || return
        if wt_yesno "NAT" "Auto-enable IP forwarding + MASQUERADE on ${iface}?"; then nat=true; else nat=false; fi
        cat > "$TUN_CONF" <<EOF
role = "server"
mode = "tun"
listen_addr = "0.0.0.0:${lport}"
proxy_listen = ""
pre_shared_key = "${psk}"
encryption = "${cipher}"
obfuscate = ${obfs}
tun_name = "copy0"
tun_ip = "${tip}"
tun_peer_ip = "${tpip}"
tun_netmask = "255.255.255.252"
mtu = 1380
interface = "${iface}"
auto_nat = ${nat}
log_level = "info"
EOF
    fi

    write_unit "$TUN_SVC" "CopyTunnel TUN tunnel" "$BIN --config $TUN_CONF"
    enable_start "$TUN_SVC"
    wt_msg "TUN installed" "TUN tunnel configured and started as '${role}'.\n\nConfig: $TUN_CONF\nService: ${TUN_SVC}\n\nKey (keep it safe, must match peer):\n${psk}"
}

tun_status() {
    local out
    out="Service ${TUN_SVC}: $(svc_active "$TUN_SVC")\n\n"
    out+="$(ip -brief addr show copy0 2>/dev/null || echo 'copy0: not present')\n\n"
    out+="Listening sockets:\n$(lsof -nP -iUDP -a -c copytunnel 2>/dev/null | tail -n +1 | head -8 || echo 'n/a')"
    wt_msg "TUN status" "$out"
}

tun_uninstall() {
    wt_yesno "Uninstall TUN" "Stop and remove the TUN tunnel service and its config?" || return
    stop_disable "$TUN_SVC"
    rm -f "$TUN_CONF"
    wt_msg "TUN removed" "TUN tunnel service and config removed."
}

tun_menu() {
    while true; do
        local c; c="$(wt_menu "TUN tunnel" "Encrypted layer-3 TUN tunnel" \
            "Install"   "Configure & start" \
            "Status"    "Service + interface status" \
            "Uninstall" "Stop & remove" \
            "Back"      "Return to main menu")" || return
        case "$c" in
            Install)   tun_install ;;
            Status)    tun_status ;;
            Uninstall) tun_uninstall ;;
            Back|"")   return ;;
        esac
    done
}

# ═════════════════════════════════════════════════════════════════════════════
#  METHOD 2 — TRANSPARENT PROXY (sing-box + iptables)
# ═════════════════════════════════════════════════════════════════════════════
write_tproxy_scripts() { # server_ip  tproxy_port
    local sip="$1" tport="$2"
    cat > "$CONF_DIR/tproxy-up.sh" <<EOF
#!/usr/bin/env bash
set -e
MARK=1; TABLE=100; TPORT=${tport}; SERVER_IP="${sip}"
ip rule add fwmark \$MARK lookup \$TABLE 2>/dev/null || true
ip route add local default dev lo table \$TABLE 2>/dev/null || true
iptables -t mangle -N CT_PRE 2>/dev/null || iptables -t mangle -F CT_PRE
iptables -t mangle -N CT_OUT 2>/dev/null || iptables -t mangle -F CT_OUT
for net in 127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 224.0.0.0/4 240.0.0.0/4 255.255.255.255/32; do
    iptables -t mangle -A CT_PRE -d \$net -j RETURN
    iptables -t mangle -A CT_OUT -d \$net -j RETURN
done
[ -n "\$SERVER_IP" ] && { iptables -t mangle -A CT_PRE -d "\$SERVER_IP" -j RETURN; iptables -t mangle -A CT_OUT -d "\$SERVER_IP" -j RETURN; }
if [ -f "${BYPASS_LIST}" ]; then
    while read -r cidr; do
        [ -n "\$cidr" ] || continue
        iptables -t mangle -A CT_PRE -d "\$cidr" -j RETURN
        iptables -t mangle -A CT_OUT -d "\$cidr" -j RETURN
    done < "${BYPASS_LIST}"
fi
iptables -t mangle -A CT_PRE -p tcp -j TPROXY --on-port \$TPORT --tproxy-mark \$MARK
iptables -t mangle -A CT_PRE -p udp -j TPROXY --on-port \$TPORT --tproxy-mark \$MARK
iptables -t mangle -C PREROUTING -j CT_PRE 2>/dev/null || iptables -t mangle -A PREROUTING -j CT_PRE
iptables -t mangle -A CT_OUT -p tcp -j MARK --set-mark \$MARK
iptables -t mangle -A CT_OUT -p udp -j MARK --set-mark \$MARK
iptables -t mangle -C OUTPUT -j CT_OUT 2>/dev/null || iptables -t mangle -A OUTPUT -j CT_OUT
EOF
    cat > "$CONF_DIR/tproxy-down.sh" <<EOF
#!/usr/bin/env bash
iptables -t mangle -D PREROUTING -j CT_PRE 2>/dev/null || true
iptables -t mangle -D OUTPUT -j CT_OUT 2>/dev/null || true
iptables -t mangle -F CT_PRE 2>/dev/null || true
iptables -t mangle -X CT_PRE 2>/dev/null || true
iptables -t mangle -F CT_OUT 2>/dev/null || true
iptables -t mangle -X CT_OUT 2>/dev/null || true
ip rule del fwmark 1 lookup 100 2>/dev/null || true
ip route flush table 100 2>/dev/null || true
EOF
    chmod +x "$CONF_DIR/tproxy-up.sh" "$CONF_DIR/tproxy-down.sh"
}

write_singbox_conf() { # socks_port  tproxy_port  server_ip
    local socks="$1" tport="$2" sip="$3"
    cat > "$SB_CONF" <<EOF
{
  "log": { "level": "warn", "timestamp": true },
  "inbounds": [
    {
      "type": "tproxy",
      "tag": "tproxy-in",
      "listen": "::",
      "listen_port": ${tport},
      "sniff": true
    }
  ],
  "outbounds": [
    { "type": "socks", "tag": "ct-out", "server": "127.0.0.1", "server_port": ${socks}, "version": "5" },
    { "type": "direct", "tag": "direct" }
  ],
  "route": {
    "rules": [
      { "ip_cidr": ["${sip}/32"], "outbound": "direct" },
      { "ip_is_private": true, "outbound": "direct" }
    ],
    "final": "ct-out",
    "auto_detect_interface": true
  }
}
EOF
}

proxy_install() {
    ensure_binary || { wt_msg "Binary missing" "Could not obtain the copytunnel binary. Try Options → Update."; return; }

    local role
    role="$(wt_menu "Proxy · role" "Set up this host as:" \
        "client" "Edge side: transparent proxy via sing-box" \
        "server" "Exit side: accepts encrypted streams")" || return

    local psk cipher obfs
    psk="$(ask_psk)" || return
    cipher="$(choose_cipher)" || return
    if wt_yesno "Obfuscation" "Enable extra whole-frame XOR obfuscation?\n(Must match on both sides.)"; then obfs=true; else obfs=false; fi

    if [[ "$role" == "server" ]]; then
        local pport
        pport="$(ask_port "Proxy TCP port" "Port to listen on for proxy clients:" "51823")" || return
        cat > "$PROXY_CONF" <<EOF
role = "server"
listen_addr = ""
proxy_listen = "0.0.0.0:${pport}"
pre_shared_key = "${psk}"
encryption = "${cipher}"
obfuscate = ${obfs}
log_level = "info"
EOF
        write_unit "$PROXY_SVC" "CopyTunnel proxy server" "$BIN --config $PROXY_CONF"
        enable_start "$PROXY_SVC"
        wt_msg "Proxy server installed" "Proxy server listening on TCP ${pport}.\n\nKey (must match clients):\n${psk}"
        return
    fi

    # ── client ──
    local sip sport socks tport
    sip="$(wt_input "Server address" "CopyTunnel SERVER public IP:")" || return
    sport="$(ask_port "Server TCP port" "Server's proxy TCP port:" "51823")" || return
    socks="$(ask_port "Local SOCKS port" "Local SOCKS5 port (sing-box dials this):" "1080")" || return
    tport="$(ask_port "tproxy port" "sing-box transparent (tproxy) port:" "12345")" || return

    cat > "$PROXY_CONF" <<EOF
role = "client"
mode = "proxy"
proxy_server = "${sip}:${sport}"
socks_listen = "127.0.0.1:${socks}"
pre_shared_key = "${psk}"
encryption = "${cipher}"
obfuscate = ${obfs}
log_level = "info"
EOF

    # sing-box
    if ! install_singbox; then
        wt_msg "sing-box missing" "Could not download sing-box automatically.\nInstall it to ${SB_BIN} and re-run Install."
        return
    fi
    write_singbox_conf "$socks" "$tport" "$sip"
    write_tproxy_scripts "$sip" "$tport"
    touch "$BYPASS_LIST"

    # services (order: copytunnel socks → sing-box → iptables rules)
    write_unit "$PROXY_SVC" "CopyTunnel proxy client (SOCKS5)" "$BIN --config $PROXY_CONF"
    write_unit "$SB_SVC" "sing-box (transparent proxy ingress)" "$SB_BIN run -c $SB_CONF" "network-online.target $PROXY_SVC.service"
    cat > "/etc/systemd/system/${TPROXY_SVC}.service" <<EOF
[Unit]
Description=CopyTunnel transparent-proxy iptables rules
After=network-online.target ${PROXY_SVC}.service ${SB_SVC}.service
Requires=${SB_SVC}.service
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=${CONF_DIR}/tproxy-up.sh
ExecStop=${CONF_DIR}/tproxy-down.sh

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    enable_start "$PROXY_SVC"
    enable_start "$SB_SVC"
    enable_start "$TPROXY_SVC"

    wt_msg "Proxy client installed" "Transparent proxy is up.\n\n• CopyTunnel SOCKS5: 127.0.0.1:${socks}\n• sing-box tproxy:   ${tport}\n• Server:            ${sip}:${sport}\n\nAll TCP/UDP (except local & server) is now redirected through the encrypted tunnel.\n\nKey (must match server):\n${psk}"
}

proxy_status() {
    local out
    out="Services:\n"
    out+="  ${PROXY_SVC}: $(svc_active "$PROXY_SVC")\n"
    out+="  ${SB_SVC}:    $(svc_active "$SB_SVC")\n"
    out+="  ${TPROXY_SVC}: $(svc_active "$TPROXY_SVC")\n\n"
    out+="SOCKS/listen sockets:\n$(lsof -nP -iTCP -sTCP:LISTEN -a -c copytunnel 2>/dev/null | head -6 || echo 'n/a')\n\n"
    out+="Active mangle rules:\n$(iptables -t mangle -S 2>/dev/null | grep -E 'CT_(PRE|OUT)' | head -6 || echo 'none')"
    wt_msg "Proxy status" "$out"
}

proxy_add_bypass() {
    local cidr
    cidr="$(wt_input "Add bypass" "IP or CIDR to exclude from the tunnel (sent direct):\ne.g. 1.2.3.4 or 5.6.0.0/16")" || return
    [[ -n "$cidr" ]] || return
    [[ "$cidr" == */* ]] || cidr="$cidr/32"
    echo "$cidr" >> "$BYPASS_LIST"
    systemctl restart "$TPROXY_SVC" >/dev/null 2>&1 || true
    wt_msg "Bypass added" "Added ${cidr} to the direct-route bypass list and reloaded rules."
}

proxy_remove_bypass() {
    [[ -s "$BYPASS_LIST" ]] || { wt_msg "No bypasses" "The bypass list is empty."; return; }
    local args=() line
    while read -r line; do [[ -n "$line" ]] && args+=("$line" "bypass"); done < "$BYPASS_LIST"
    local pick; pick="$(wt_menu "Remove bypass" "Select an entry to remove:" "${args[@]}")" || return
    grep -vxF "$pick" "$BYPASS_LIST" > "$BYPASS_LIST.tmp" && mv "$BYPASS_LIST.tmp" "$BYPASS_LIST"
    systemctl restart "$TPROXY_SVC" >/dev/null 2>&1 || true
    wt_msg "Bypass removed" "Removed ${pick} and reloaded rules."
}

proxy_uninstall() {
    wt_yesno "Uninstall proxy" "Stop and remove the proxy services, sing-box config, and iptables rules?" || return
    systemctl stop "$TPROXY_SVC" >/dev/null 2>&1 || true   # runs tproxy-down.sh
    stop_disable "$TPROXY_SVC"
    stop_disable "$SB_SVC"
    stop_disable "$PROXY_SVC"
    [[ -x "$CONF_DIR/tproxy-down.sh" ]] && bash "$CONF_DIR/tproxy-down.sh" 2>/dev/null || true
    rm -f "$PROXY_CONF" "$SB_CONF" "$CONF_DIR/tproxy-up.sh" "$CONF_DIR/tproxy-down.sh"
    wt_msg "Proxy removed" "Proxy services, sing-box config, and iptables rules removed.\n(The bypass list was kept at ${BYPASS_LIST}.)"
}

proxy_menu() {
    while true; do
        local c; c="$(wt_menu "Transparent Proxy" "sing-box tproxy + iptables → CopyTunnel SOCKS5" \
            "Install"      "Configure & start" \
            "Status"       "Service + rules status" \
            "Add"          "Add a direct-route bypass (client)" \
            "Remove"       "Remove a bypass (client)" \
            "Uninstall"    "Stop & remove" \
            "Back"         "Return to main menu")" || return
        case "$c" in
            Install)   proxy_install ;;
            Status)    proxy_status ;;
            Add)       proxy_add_bypass ;;
            Remove)    proxy_remove_bypass ;;
            Uninstall) proxy_uninstall ;;
            Back|"")   return ;;
        esac
    done
}

# ═════════════════════════════════════════════════════════════════════════════
#  OPTIONS
# ═════════════════════════════════════════════════════════════════════════════
opt_dns() {
    local d1 d2
    d1="$(wt_input "DNS 1" "Primary DNS server:" "8.8.8.8")" || return
    d2="$(wt_input "DNS 2" "Secondary DNS server:" "1.1.1.1")" || return
    cp -f /etc/resolv.conf /etc/resolv.conf.copytunnel.bak 2>/dev/null || true
    printf "nameserver %s\nnameserver %s\n" "$d1" "$d2" > /etc/resolv.conf
    wt_msg "DNS set" "Resolvers set to ${d1}, ${d2}.\n(Backup: /etc/resolv.conf.copytunnel.bak)"
}

opt_update() {
    rm -f "$BIN"
    if ensure_binary; then
        for s in "$TUN_SVC" "$PROXY_SVC"; do systemctl is-enabled --quiet "$s" 2>/dev/null && systemctl restart "$s"; done
        wt_msg "Updated" "Binary updated and running services restarted."
    else
        wt_msg "Update failed" "Could not obtain a new binary (no release and no cargo build)."
    fi
}

opt_genkey() {
    local k; k="$(gen_key)"
    wt_msg "Generated key" "Random 32-byte key (use as pre_shared_key or key_hex):\n\n${k}"
}

opt_test() {
    local out="Connectivity test:\n\n"
    for h in github.com google.com cloudflare.com; do
        if ping -c1 -W2 "$h" >/dev/null 2>&1; then out+="  $h  OK\n"; else out+="  $h  FAIL\n"; fi
    done
    out+="\nSOCKS test (proxy client, if running):\n"
    local socks; socks="$(grep -oP 'socks_listen *= *"[^"]*' "$PROXY_CONF" 2>/dev/null | grep -oP '[0-9.]+:[0-9]+' || true)"
    if [[ -n "$socks" ]]; then
        if curl -s --max-time 6 --socks5-hostname "$socks" https://api.ipify.org >/dev/null 2>&1; then
            out+="  via tunnel exit IP: $(curl -s --max-time 6 --socks5-hostname "$socks" https://api.ipify.org)\n"
        else
            out+="  SOCKS ${socks} not reachable\n"
        fi
    else
        out+="  (no proxy client configured)\n"
    fi
    wt_msg "Test" "$out"
}

opt_uninstall_all() {
    wt_yesno "Uninstall everything" "Remove ALL CopyTunnel services, configs, sing-box config, iptables rules, and the installed command?\n\nThis cannot be undone." || return
    systemctl stop "$TPROXY_SVC" >/dev/null 2>&1 || true
    [[ -x "$CONF_DIR/tproxy-down.sh" ]] && bash "$CONF_DIR/tproxy-down.sh" 2>/dev/null || true
    for s in "$TPROXY_SVC" "$SB_SVC" "$PROXY_SVC" "$TUN_SVC"; do stop_disable "$s"; done
    rm -rf "$CONF_DIR"
    rm -f /usr/local/bin/copytunnel-menu /usr/local/bin/ct "$BIN"
    wt_msg "Removed" "CopyTunnel fully removed.\n(The /opt/copytunnel source tree was left in place; delete it manually if desired.)"
    exit 0
}

options_menu() {
    while true; do
        local c; c="$(wt_menu "Options" "Additional configuration" \
            "DNS"          "Set system resolvers" \
            "Update"       "Update binary & restart services" \
            "GenKey"       "Generate a random key" \
            "Test"         "Connectivity & tunnel test" \
            "UninstallAll" "Remove everything" \
            "Back"         "Return to main menu")" || return
        case "$c" in
            DNS)          opt_dns ;;
            Update)       opt_update ;;
            GenKey)       opt_genkey ;;
            Test)         opt_test ;;
            UninstallAll) opt_uninstall_all ;;
            Back|"")      return ;;
        esac
    done
}

# ═════════════════════════════════════════════════════════════════════════════
#  MAIN MENU
# ═════════════════════════════════════════════════════════════════════════════
main_menu() {
    while true; do
        local c; c="$(wt_menu "CopyTunnel — choose method" \
            "Encrypted tunnel manager · pick a forwarding method" \
            "TUN"     "Layer-3 encrypted tunnel (TUN + UDP)" \
            "Proxy"   "Transparent proxy (sing-box + iptables)" \
            "Options" "DNS · update · keygen · test · uninstall" \
            "Quit"    "Exit")" || exit 0
        case "$c" in
            TUN)     tun_menu ;;
            Proxy)   proxy_menu ;;
            Options) options_menu ;;
            Quit|"") exit 0 ;;
        esac
    done
}

main_menu
