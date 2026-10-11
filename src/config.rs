//! Configuration model for CopyTunnel.
//!
//! Both the client and the server read the **same** TOML schema; the `role`
//! field decides which half of the tunnel runs. Fields that only matter for one
//! side are documented inline and ignored (with a sensible default) on the
//! other side.

use std::net::SocketAddr;

use anyhow::{bail, Context, Result};
use serde::Deserialize;

use crate::crypto::CipherKind;

/// Which end of the tunnel this process is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Captures local traffic through a TUN device and relays it to the server.
    Client,
    /// Receives relayed packets, decrypts them, and lets the kernel route them
    /// to their real destination.
    Server,
}

/// IP-layer protocols CopyTunnel is willing to forward.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum L4Protocol {
    Tcp,
    Udp,
}

impl L4Protocol {
    /// The IANA protocol number as it appears in the IPv4 header.
    pub fn ip_number(self) -> u8 {
        match self {
            L4Protocol::Tcp => 6,
            L4Protocol::Udp => 17,
        }
    }
}

/// Fully parsed, validated configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    // ── Role ────────────────────────────────────────────────────────────────
    pub role: Role,

    // ── Transport (UDP data channel) ─────────────────────────────────────────
    /// Client: `IP:PORT` of the remote server. Server: ignored.
    #[serde(default)]
    pub server_addr: String,

    /// Server: local `IP:PORT` to bind the UDP listener on. Client: ignored,
    /// though it may be set to pin a local source port.
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,

    // ── Security ─────────────────────────────────────────────────────────────
    /// Pre-shared secret. Used to derive the symmetric key for every cipher.
    /// Must be identical on both sides. Minimum 16 characters.
    pub pre_shared_key: String,

    /// Optional explicit 32-byte key as a 64-char hex string. When present it
    /// overrides key derivation from `pre_shared_key` (the PSK is then used only
    /// for the lightweight connection handshake). Must match on both sides.
    #[serde(default)]
    pub key_hex: Option<String>,

    /// Which AEAD / obfuscation cipher protects each frame on the wire.
    /// See `crypto::CipherKind` and the README for the trade-offs.
    #[serde(default = "default_cipher")]
    pub encryption: CipherKind,

    /// Extra XOR obfuscation pass applied to the *entire* wire frame after
    /// encryption. Pure traffic-shaping; adds no cryptographic strength but
    /// changes the byte distribution so the frame does not look like a fixed
    /// AEAD structure to shallow DPI. Must match on both sides.
    #[serde(default)]
    pub obfuscate: bool,

    // ── Packet selection ─────────────────────────────────────────────────────
    /// IP protocols to tunnel. Packets of any other protocol read from the TUN
    /// are dropped. Defaults to TCP + UDP.
    #[serde(default = "default_protocols")]
    pub forward_protocols: Vec<L4Protocol>,

    /// Port filter. Empty = forward every port. When non-empty, a packet is
    /// tunnelled only if its source *or* destination port is in this list.
    #[serde(default)]
    pub forward_ports: Vec<u16>,

    // ── TUN interface ────────────────────────────────────────────────────────
    #[serde(default = "default_tun_name")]
    pub tun_name: String,
    /// Local address assigned to the TUN interface.
    pub tun_ip: String,
    /// Peer address of the point-to-point TUN link (swap between the two sides).
    pub tun_peer_ip: String,
    #[serde(default = "default_netmask")]
    pub tun_netmask: String,
    #[serde(default = "default_mtu")]
    pub mtu: u32,

    // ── Networking helpers ───────────────────────────────────────────────────
    /// Physical NIC used for the server-side NAT MASQUERADE rule, e.g. `eth0`.
    #[serde(default = "default_interface")]
    pub interface: String,

    /// Server: automatically enable IPv4 forwarding and install an iptables
    /// MASQUERADE rule so decrypted packets reach the internet and replies come
    /// back. Removed again on shutdown.
    #[serde(default = "default_true")]
    pub auto_nat: bool,

    /// Seconds between keepalive frames (client → server) so the server always
    /// knows the client's current UDP address and NAT mappings stay open.
    /// 0 disables keepalives.
    #[serde(default = "default_keepalive")]
    pub keepalive_secs: u64,

    // ── Runtime ──────────────────────────────────────────────────────────────
    /// Tokio worker threads. 0 = one per CPU core.
    #[serde(default)]
    pub worker_threads: usize,

    #[serde(default = "default_log_level")]
    pub log_level: String,
}

fn default_listen_addr() -> String {
    "0.0.0.0:51822".to_string()
}
fn default_cipher() -> CipherKind {
    CipherKind::ChaCha20Poly1305
}
fn default_protocols() -> Vec<L4Protocol> {
    vec![L4Protocol::Tcp, L4Protocol::Udp]
}
fn default_tun_name() -> String {
    "copy0".to_string()
}
fn default_netmask() -> String {
    "255.255.255.252".to_string()
}
fn default_mtu() -> u32 {
    1380
}
fn default_interface() -> String {
    "eth0".to_string()
}
fn default_true() -> bool {
    true
}
fn default_keepalive() -> u64 {
    15
}
fn default_log_level() -> String {
    "info".to_string()
}

impl Config {
    /// Load and validate a configuration file.
    pub fn from_file(path: &str) -> Result<Config> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config file `{path}`"))?;
        let cfg: Config =
            toml::from_str(&text).with_context(|| format!("failed to parse config file `{path}`"))?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<()> {
        if self.pre_shared_key.len() < 16 {
            bail!("pre_shared_key must be at least 16 characters");
        }
        if let Some(h) = &self.key_hex {
            let raw = hex::decode(h.trim())
                .context("key_hex is not valid hexadecimal")?;
            if raw.len() != 32 {
                bail!("key_hex must decode to exactly 32 bytes (64 hex chars)");
            }
        }
        if self.role == Role::Client {
            self.parsed_server_addr()
                .context("client requires a valid `server_addr` (IP:PORT)")?;
        } else {
            self.parsed_listen_addr()
                .context("server requires a valid `listen_addr` (IP:PORT)")?;
        }
        if self.mtu < 576 || self.mtu > 9000 {
            bail!("mtu must be between 576 and 9000");
        }
        self.tun_ip
            .parse::<std::net::Ipv4Addr>()
            .context("tun_ip is not a valid IPv4 address")?;
        self.tun_peer_ip
            .parse::<std::net::Ipv4Addr>()
            .context("tun_peer_ip is not a valid IPv4 address")?;
        self.tun_netmask
            .parse::<std::net::Ipv4Addr>()
            .context("tun_netmask is not a valid IPv4 address")?;
        if self.forward_protocols.is_empty() {
            bail!("forward_protocols must list at least one of \"tcp\", \"udp\"");
        }
        Ok(())
    }

    pub fn parsed_server_addr(&self) -> Result<SocketAddr> {
        Ok(self.server_addr.parse()?)
    }

    pub fn parsed_listen_addr(&self) -> Result<SocketAddr> {
        Ok(self.listen_addr.parse()?)
    }

    /// True when the given IPv4 protocol number is one we forward.
    pub fn forwards_protocol(&self, ip_proto: u8) -> bool {
        self.forward_protocols
            .iter()
            .any(|p| p.ip_number() == ip_proto)
    }
}
