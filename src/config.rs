//! Configuration model for CopyTunnel.
//!
//! Both the client and the server read the **same** TOML schema; the `role`
//! field decides which half of the tunnel runs, and (on the client) `mode`
//! decides *how* traffic is captured:
//!
//! * `tun` — a layer-3 TUN device captures IP packets (connectionless, UDP
//!   transport). Best for forwarding everything, including UDP.
//! * `proxy` — a local SOCKS5 server captures TCP streams (reliable, TCP
//!   transport). Fed by sing-box's transparent `tproxy` inbound plus iptables
//!   rules. CopyTunnel still does all the encryption.
//!
//! A server can serve **both** kinds of client at once: it opens a UDP listener
//! (`listen_addr`) for TUN clients and a TCP listener (`proxy_listen`) for proxy
//! clients, using the same pre-shared key and cipher for both.

use std::net::SocketAddr;

use anyhow::{bail, Context, Result};
use serde::Deserialize;

use crate::crypto::CipherKind;

/// Which end of the tunnel this process is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Client,
    Server,
}

/// How a *client* captures the traffic it tunnels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Layer-3 TUN device + UDP transport.
    Tun,
    /// Local SOCKS5 server (fed by sing-box tproxy) + TCP transport.
    Proxy,
}

/// IP-layer protocols CopyTunnel is willing to forward in TUN mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum L4Protocol {
    Tcp,
    Udp,
}

impl L4Protocol {
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
    // ── Role & mode ──────────────────────────────────────────────────────────
    pub role: Role,
    /// Client only. `tun` (default) or `proxy`. Ignored on the server.
    #[serde(default = "default_mode")]
    pub mode: Mode,

    // ── TUN-mode transport (UDP) ─────────────────────────────────────────────
    /// Client/TUN: `IP:PORT` of the server's UDP listener.
    #[serde(default)]
    pub server_addr: String,
    /// Server: local `IP:PORT` for the UDP (TUN) listener. Empty disables it.
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,

    // ── Proxy-mode transport (TCP) ───────────────────────────────────────────
    /// Client/proxy: `IP:PORT` of the server's TCP proxy listener.
    #[serde(default)]
    pub proxy_server: String,
    /// Server: local `IP:PORT` for the TCP proxy listener. Empty disables it.
    #[serde(default = "default_proxy_listen")]
    pub proxy_listen: String,
    /// Client/proxy: local address the SOCKS5 server binds on (sing-box dials it).
    #[serde(default = "default_socks_listen")]
    pub socks_listen: String,

    // ── Security ─────────────────────────────────────────────────────────────
    pub pre_shared_key: String,
    #[serde(default)]
    pub key_hex: Option<String>,
    #[serde(default = "default_cipher")]
    pub encryption: CipherKind,
    #[serde(default)]
    pub obfuscate: bool,

    // ── Packet selection (TUN mode) ──────────────────────────────────────────
    #[serde(default = "default_protocols")]
    pub forward_protocols: Vec<L4Protocol>,
    #[serde(default)]
    pub forward_ports: Vec<u16>,

    // ── TUN interface ────────────────────────────────────────────────────────
    #[serde(default = "default_tun_name")]
    pub tun_name: String,
    #[serde(default = "default_tun_ip")]
    pub tun_ip: String,
    #[serde(default = "default_tun_peer_ip")]
    pub tun_peer_ip: String,
    #[serde(default = "default_netmask")]
    pub tun_netmask: String,
    #[serde(default = "default_mtu")]
    pub mtu: u32,

    // ── Networking helpers ───────────────────────────────────────────────────
    #[serde(default = "default_interface")]
    pub interface: String,
    #[serde(default = "default_true")]
    pub auto_nat: bool,
    #[serde(default = "default_keepalive")]
    pub keepalive_secs: u64,

    // ── Runtime ──────────────────────────────────────────────────────────────
    #[serde(default)]
    pub worker_threads: usize,
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

fn default_mode() -> Mode {
    Mode::Tun
}
fn default_listen_addr() -> String {
    "0.0.0.0:51822".to_string()
}
fn default_proxy_listen() -> String {
    "0.0.0.0:51823".to_string()
}
fn default_socks_listen() -> String {
    "127.0.0.1:1080".to_string()
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
fn default_tun_ip() -> String {
    "10.66.0.2".to_string()
}
fn default_tun_peer_ip() -> String {
    "10.66.0.1".to_string()
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
    pub fn from_file(path: &str) -> Result<Config> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config file `{path}`"))?;
        let cfg: Config = toml::from_str(&text)
            .with_context(|| format!("failed to parse config file `{path}`"))?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<()> {
        if self.pre_shared_key.len() < 16 {
            bail!("pre_shared_key must be at least 16 characters");
        }
        if let Some(h) = &self.key_hex {
            let raw = hex::decode(h.trim()).context("key_hex is not valid hexadecimal")?;
            if raw.len() != 32 {
                bail!("key_hex must decode to exactly 32 bytes (64 hex chars)");
            }
        }

        match self.role {
            Role::Client => match self.mode {
                Mode::Tun => {
                    self.parsed_server_addr()
                        .context("TUN client requires a valid `server_addr` (IP:PORT)")?;
                    self.validate_tun_fields()?;
                }
                Mode::Proxy => {
                    self.parsed_proxy_server()
                        .context("proxy client requires a valid `proxy_server` (IP:PORT)")?;
                    self.parsed_socks_listen()
                        .context("proxy client requires a valid `socks_listen` (IP:PORT)")?;
                }
            },
            Role::Server => {
                let has_tun = !self.listen_addr.trim().is_empty();
                let has_proxy = !self.proxy_listen.trim().is_empty();
                if !has_tun && !has_proxy {
                    bail!("server must enable at least one of `listen_addr` (TUN/UDP) or `proxy_listen` (proxy/TCP)");
                }
                if has_tun {
                    self.parsed_listen_addr()
                        .context("invalid server `listen_addr` (IP:PORT)")?;
                    self.validate_tun_fields()?;
                }
                if has_proxy {
                    self.parsed_proxy_listen()
                        .context("invalid server `proxy_listen` (IP:PORT)")?;
                }
            }
        }

        if self.mtu < 576 || self.mtu > 9000 {
            bail!("mtu must be between 576 and 9000");
        }
        Ok(())
    }

    fn validate_tun_fields(&self) -> Result<()> {
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
    pub fn parsed_proxy_server(&self) -> Result<SocketAddr> {
        Ok(self.proxy_server.parse()?)
    }
    pub fn parsed_proxy_listen(&self) -> Result<SocketAddr> {
        Ok(self.proxy_listen.parse()?)
    }
    pub fn parsed_socks_listen(&self) -> Result<SocketAddr> {
        Ok(self.socks_listen.parse()?)
    }

    pub fn server_tun_enabled(&self) -> bool {
        !self.listen_addr.trim().is_empty()
    }
    pub fn server_proxy_enabled(&self) -> bool {
        !self.proxy_listen.trim().is_empty()
    }

    pub fn forwards_protocol(&self, ip_proto: u8) -> bool {
        self.forward_protocols
            .iter()
            .any(|p| p.ip_number() == ip_proto)
    }
}
