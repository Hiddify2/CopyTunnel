//! The two tunnel endpoints.
//!
//! ## Data path
//!
//! ```text
//!  client host                         server host                 internet
//!  ───────────                         ───────────                 ────────
//!  app ─▶ kernel ─▶ TUN(copy0) ─▶ read ─▶ encrypt ─▶ UDP ─────────────────▶
//!                                                              UDP ─▶ decrypt
//!                                                              ─▶ TUN(copy0)
//!                                                              ─▶ kernel NAT ─▶ dest
//!  ◀───────────────────────────────── UDP ◀─ encrypt ◀─ read ◀─ TUN ◀─ reply ◀─
//!  app ◀─ kernel ◀─ TUN(copy0) ◀─ write ◀─ decrypt ◀─ UDP
//! ```
//!
//! Every datagram carries exactly one tunnel frame. A frame's plaintext is one
//! type byte followed by the body:
//!   * `0x01` — a captured IPv4 packet
//!   * `0x02` — a keepalive (no body)
//!
//! The frame is then sealed by the configured cipher and, optionally, run
//! through the whole-frame XOR obfuscation layer.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use log::{debug, info, warn};
use tokio::net::UdpSocket;

use crate::config::Config;
use crate::crypto::{obfuscate_inplace, obfuscation_mask, Cipher};
use crate::packet::inspect_ipv4;
use crate::tun::Tun;

const FRAME_DATA: u8 = 0x01;
const FRAME_KEEPALIVE: u8 = 0x02;

/// Shared per-endpoint state.
struct Shared {
    cfg: Arc<Config>,
    cipher: Cipher,
    obfs_mask: Option<[u8; 64]>,
    tun: Tun,
    sock: UdpSocket,
}

impl Shared {
    fn build(cfg: Arc<Config>, sock: UdpSocket) -> Result<Arc<Shared>> {
        let cipher = Cipher::new(cfg.encryption, &cfg.pre_shared_key, &cfg.key_hex)
            .context("initialise cipher")?;
        let obfs_mask = if cfg.obfuscate {
            Some(obfuscation_mask(&cfg.pre_shared_key))
        } else {
            None
        };
        let tun = Tun::create(&cfg).context("create TUN device")?;
        info!("TUN interface `{}` is up (mtu {})", tun.name(), cfg.mtu);
        Ok(Arc::new(Shared {
            cfg,
            cipher,
            obfs_mask,
            tun,
            sock,
        }))
    }

    /// Wrap a frame body into a sealed (and optionally obfuscated) wire frame.
    fn encode(&self, kind: u8, body: &[u8]) -> Result<Vec<u8>> {
        let mut plain = Vec::with_capacity(1 + body.len());
        plain.push(kind);
        plain.extend_from_slice(body);
        let mut frame = self.cipher.seal(&plain)?;
        if let Some(mask) = &self.obfs_mask {
            obfuscate_inplace(&mut frame, mask);
        }
        Ok(frame)
    }

    /// Reverse of `encode`. Returns `(kind, body)` or an error for anything that
    /// fails to authenticate/parse (silently dropped by the caller).
    fn decode(&self, frame: &mut [u8]) -> Result<(u8, Vec<u8>)> {
        if let Some(mask) = &self.obfs_mask {
            obfuscate_inplace(frame, mask);
        }
        let plain = self.cipher.open(frame)?;
        if plain.is_empty() {
            anyhow::bail!("empty frame");
        }
        Ok((plain[0], plain[1..].to_vec()))
    }

    /// Should this captured packet be tunnelled, per the protocol/port filters?
    fn should_forward(&self, pkt: &[u8]) -> bool {
        let info = match inspect_ipv4(pkt) {
            Some(i) => i,
            None => return false, // non-IPv4 / truncated
        };
        if !self.cfg.forwards_protocol(info.protocol) {
            return false;
        }
        if self.cfg.forward_ports.is_empty() {
            return true;
        }
        let ports = &self.cfg.forward_ports;
        let hit = info
            .src_port
            .map(|p| ports.contains(&p))
            .unwrap_or(false)
            || info.dst_port.map(|p| ports.contains(&p)).unwrap_or(false);
        hit
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Client
// ─────────────────────────────────────────────────────────────────────────────

/// Run the client: capture local packets and relay them to the server.
pub async fn run_client(cfg: Arc<Config>) -> Result<()> {
    let server: SocketAddr = cfg.parsed_server_addr()?;
    // Bind an ephemeral local UDP port (or the configured one) and `connect` so
    // the kernel pins the 5-tuple and we can use plain send/recv.
    let bind = if cfg.listen_addr.is_empty() {
        "0.0.0.0:0".to_string()
    } else {
        // Reuse listen_addr's port locally if the user pinned one; else ephemeral.
        "0.0.0.0:0".to_string()
    };
    let sock = UdpSocket::bind(&bind).await.context("bind client UDP socket")?;
    sock.connect(server)
        .await
        .with_context(|| format!("connect to server {server}"))?;
    info!("relaying to server {server}");

    let shared = Shared::build(cfg.clone(), sock)?;

    let up = tokio::spawn(client_tun_to_net(shared.clone()));
    let down = tokio::spawn(client_net_to_tun(shared.clone()));
    let keep = tokio::spawn(client_keepalive(shared.clone()));

    tokio::select! {
        r = up => r.context("tun->net task panicked")?,
        r = down => r.context("net->tun task panicked")?,
        r = keep => r.context("keepalive task panicked")?,
        _ = tokio::signal::ctrl_c() => {
            info!("shutting down (signal)");
            Ok(())
        }
    }
}

async fn client_tun_to_net(s: Arc<Shared>) -> Result<()> {
    let mut buf = vec![0u8; s.cfg.mtu as usize + 128];
    loop {
        let n = s.tun.recv(&mut buf).await.context("read from TUN")?;
        let pkt = &buf[..n];
        if !s.should_forward(pkt) {
            debug!("dropping non-forwarded packet ({n} bytes)");
            continue;
        }
        let frame = match s.encode(FRAME_DATA, pkt) {
            Ok(f) => f,
            Err(e) => {
                warn!("encode failed: {e}");
                continue;
            }
        };
        if let Err(e) = s.sock.send(&frame).await {
            warn!("UDP send failed: {e}");
        }
    }
}

async fn client_net_to_tun(s: Arc<Shared>) -> Result<()> {
    let mut buf = vec![0u8; 65535];
    loop {
        let n = match s.sock.recv(&mut buf).await {
            Ok(n) => n,
            Err(e) => {
                warn!("UDP recv failed: {e}");
                continue;
            }
        };
        let (kind, body) = match s.decode(&mut buf[..n]) {
            Ok(v) => v,
            Err(_) => continue, // unauthenticated / junk
        };
        if kind != FRAME_DATA {
            continue;
        }
        if let Err(e) = s.tun.send(&body).await {
            warn!("TUN write failed: {e}");
        }
    }
}

async fn client_keepalive(s: Arc<Shared>) -> Result<()> {
    if s.cfg.keepalive_secs == 0 {
        // Never fire; park forever.
        futures_park().await;
        return Ok(());
    }
    let mut tick = tokio::time::interval(Duration::from_secs(s.cfg.keepalive_secs));
    loop {
        tick.tick().await;
        match s.encode(FRAME_KEEPALIVE, &[]) {
            Ok(frame) => {
                if let Err(e) = s.sock.send(&frame).await {
                    warn!("keepalive send failed: {e}");
                }
            }
            Err(e) => warn!("keepalive encode failed: {e}"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Server
// ─────────────────────────────────────────────────────────────────────────────

/// Run the server: decrypt relayed packets, deliver them to the kernel for
/// routing/NAT, and relay replies back to the last-seen client.
pub async fn run_server(cfg: Arc<Config>) -> Result<()> {
    let listen: SocketAddr = cfg.parsed_listen_addr()?;
    let sock = UdpSocket::bind(listen)
        .await
        .with_context(|| format!("bind server UDP socket on {listen}"))?;
    info!("listening for clients on {listen}");

    // Install NAT only on Linux and only when requested.
    #[cfg(target_os = "linux")]
    let _nat = if cfg.auto_nat {
        Some(crate::netsetup::NatGuard::install(&cfg))
    } else {
        None
    };

    let shared = Shared::build(cfg.clone(), sock)?;
    // The client's current UDP address, learned from authenticated frames.
    let peer: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));

    let up = tokio::spawn(server_net_to_tun(shared.clone(), peer.clone()));
    let down = tokio::spawn(server_tun_to_net(shared.clone(), peer.clone()));

    tokio::select! {
        r = up => r.context("net->tun task panicked")?,
        r = down => r.context("tun->net task panicked")?,
        _ = tokio::signal::ctrl_c() => {
            info!("shutting down (signal)");
            Ok(())
        }
    }
}

async fn server_net_to_tun(s: Arc<Shared>, peer: Arc<Mutex<Option<SocketAddr>>>) -> Result<()> {
    let mut buf = vec![0u8; 65535];
    loop {
        let (n, from) = match s.sock.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                warn!("UDP recv failed: {e}");
                continue;
            }
        };
        let (kind, body) = match s.decode(&mut buf[..n]) {
            Ok(v) => v,
            Err(_) => {
                debug!("dropped unauthenticated datagram from {from}");
                continue; // junk / wrong key / spoofed — never reaches the TUN
            }
        };

        // Authenticated: this is genuinely our client. Remember where it is.
        {
            let mut guard = peer.lock().unwrap();
            if guard.as_ref() != Some(&from) {
                info!("client address is now {from}");
                *guard = Some(from);
            }
        }

        match kind {
            FRAME_KEEPALIVE => { /* address already refreshed */ }
            FRAME_DATA => {
                if let Err(e) = s.tun.send(&body).await {
                    warn!("TUN write failed: {e}");
                }
            }
            other => debug!("unknown frame type {other}"),
        }
    }
}

async fn server_tun_to_net(s: Arc<Shared>, peer: Arc<Mutex<Option<SocketAddr>>>) -> Result<()> {
    let mut buf = vec![0u8; s.cfg.mtu as usize + 128];
    loop {
        let n = s.tun.recv(&mut buf).await.context("read from TUN")?;
        let pkt = &buf[..n];
        if !s.should_forward(pkt) {
            continue;
        }
        let dest = { *peer.lock().unwrap() };
        let dest = match dest {
            Some(d) => d,
            None => {
                debug!("reply packet but no client address yet; dropping");
                continue;
            }
        };
        let frame = match s.encode(FRAME_DATA, pkt) {
            Ok(f) => f,
            Err(e) => {
                warn!("encode failed: {e}");
                continue;
            }
        };
        if let Err(e) = s.sock.send_to(&frame, dest).await {
            warn!("UDP send_to {dest} failed: {e}");
        }
    }
}

/// A future that never resolves — used to park the keepalive task when disabled.
async fn futures_park() {
    let () = std::future::pending().await;
}
