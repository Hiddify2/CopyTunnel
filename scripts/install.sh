#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# CopyTunnel bootstrap installer
#
# One-liner:
#   bash -c "$(curl -fsSL https://raw.githubusercontent.com/Hiddify2/CopyTunnel/main/scripts/install.sh)"
#
# Detects the OS/package manager, installs dependencies, places CopyTunnel under
# /opt/copytunnel, obtains the binary (prebuilt release or local cargo build),
# registers a `copytunnel` command, and launches the interactive manager.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

REPO="Hiddify2/CopyTunnel"
RAW_BASE="https://raw.githubusercontent.com/${REPO}/main"
CT_DIR="/opt/copytunnel"
CONF_DIR="/etc/copytunnel"
BIN="/usr/local/bin/copytunnel"

c_green=$'\e[1;32m'; c_red=$'\e[1;31m'; c_yellow=$'\e[1;33m'; c_reset=$'\e[0m'
say()  { echo "${c_green}==>${c_reset} $*"; }
warn() { echo "${c_yellow}warning:${c_reset} $*" >&2; }
die()  { echo "${c_red}error:${c_reset} $*" >&2; exit 1; }

# ── Re-exec as root if needed ────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    if command -v sudo >/dev/null 2>&1; then
        say "re-running as root via sudo"
        exec sudo -E bash "$0" "$@"
    fi
    die "please run as root (sudo)."
fi

# ── Detect package manager ───────────────────────────────────────────────────
detect_pkg() {
    if   command -v apt-get >/dev/null 2>&1; then PKG=apt
    elif command -v dnf      >/dev/null 2>&1; then PKG=dnf
    elif command -v yum      >/dev/null 2>&1; then PKG=yum
    else die "unsupported distro (need apt, dnf, or yum)."
    fi
    say "package manager: ${PKG}"
}

pkg_update() {
    case "$PKG" in
        apt) apt-get update -qq ;;
        dnf|yum) "$PKG" -y makecache >/dev/null 2>&1 || true ;;
    esac
}

pkg_install() {
    case "$PKG" in
        apt) DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" ;;
        dnf|yum) "$PKG" install -y "$@" ;;
    esac
}

# Map a logical dependency to its package name per distro.
install_deps() {
    say "installing dependencies"
    local common=(curl wget tar jq lsof git openssl)
    pkg_install "${common[@]}" || warn "some common packages failed to install"

    # whiptail: 'whiptail' on Debian/Ubuntu (newt), 'newt' on RHEL family.
    if [[ "$PKG" == "apt" ]]; then
        pkg_install whiptail dialog iproute2 iptables || warn "menu/net deps partial"
    else
        pkg_install newt dialog iproute iptables || warn "menu/net deps partial"
    fi
    command -v whiptail >/dev/null 2>&1 || die "whiptail is required but could not be installed."
}

# ── Obtain the binary ────────────────────────────────────────────────────────
detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64)  ARCH=x86_64-unknown-linux-gnu ;;
        aarch64|arm64) ARCH=aarch64-unknown-linux-gnu ;;
        *) ARCH="" ;;
    esac
}

download_binary() {
    detect_arch
    [[ -n "$ARCH" ]] || { warn "unknown CPU arch $(uname -m); will try source build"; return 1; }
    local url="https://github.com/${REPO}/releases/latest/download/copytunnel-${ARCH}"
    say "downloading prebuilt binary (${ARCH})"
    if curl -fsSL "$url" -o "$BIN.tmp"; then
        chmod +x "$BIN.tmp" && mv "$BIN.tmp" "$BIN"
        return 0
    fi
    rm -f "$BIN.tmp"
    warn "no prebuilt release found"
    return 1
}

build_binary() {
    if ! command -v cargo >/dev/null 2>&1; then
        warn "cargo not found; cannot build from source"
        return 1
    fi
    say "building from source (this can take a few minutes)"
    ( cd "$CT_DIR" && cargo build --release ) || return 1
    install -m 0755 "$CT_DIR/target/release/copytunnel" "$BIN"
    setcap cap_net_admin+ep "$BIN" 2>/dev/null || true
}

# ── Place the project ────────────────────────────────────────────────────────
fetch_project() {
    mkdir -p "$CT_DIR" "$CONF_DIR"
    # If the script is run from inside a checkout, copy it; else clone.
    local here; here="$(cd "$(dirname "$0")/.." 2>/dev/null && pwd || true)"
    if [[ -n "$here" && -f "$here/Cargo.toml" ]]; then
        say "copying project from ${here}"
        cp -r "$here"/{src,config,scripts,Cargo.toml,Cargo.lock} "$CT_DIR"/ 2>/dev/null || true
    elif command -v git >/dev/null 2>&1; then
        say "cloning ${REPO}"
        rm -rf "$CT_DIR.git.tmp"
        git clone --depth 1 "https://github.com/${REPO}" "$CT_DIR.git.tmp" >/dev/null 2>&1 \
            && cp -r "$CT_DIR.git.tmp"/* "$CT_DIR"/ && rm -rf "$CT_DIR.git.tmp"
    fi
    [[ -f "$CT_DIR/scripts/menu.sh" ]] || {
        say "fetching manager script"
        curl -fsSL "$RAW_BASE/scripts/menu.sh" -o "$CT_DIR/scripts/menu.sh" \
            || die "could not obtain menu.sh"
        mkdir -p "$CT_DIR/scripts"
    }
    chmod +x "$CT_DIR/scripts/"*.sh 2>/dev/null || true
}

register_command() {
    cat > /usr/local/bin/copytunnel-menu <<EOF
#!/usr/bin/env bash
exec bash ${CT_DIR}/scripts/menu.sh "\$@"
EOF
    chmod +x /usr/local/bin/copytunnel-menu
    # Friendly alias: typing 'ct' or 'copytunnel-menu' opens the manager.
    ln -sf /usr/local/bin/copytunnel-menu /usr/local/bin/ct 2>/dev/null || true
}

main() {
    detect_pkg
    pkg_update
    install_deps
    fetch_project
    download_binary || build_binary || warn "binary not installed yet — use the menu's Options → Update, or build manually"
    register_command
    say "done. Launching the manager (re-open later with: ${c_green}copytunnel-menu${c_reset} or ${c_green}ct${c_reset})"
    exec bash "$CT_DIR/scripts/menu.sh"
}

main "$@"
