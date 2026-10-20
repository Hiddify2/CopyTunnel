//! Transparent-proxy data path (SOCKS5 ingress + encrypted TCP relay).
//!
//! This is the layer-4 counterpart to the TUN data path. It is used by the
//! "transparent proxy" method, where sing-box captures outbound connections with
//! its `tproxy` inbound (via iptables rules) and forwards each one to the local
//! SOCKS5 server CopyTunnel runs here. CopyTunnel then relays the stream to the
//! server over an **AEAD-encrypted, length-framed TCP connection**, and the
//! server opens the real connection to the destination.
//!
//! ```text
//!  app ─▶ iptables TPROXY ─▶ sing-box (tproxy inbound) ─▶ SOCKS5 outbound
//!                                                              │
//!                                 127.0.0.1:socks_listen ◀─────┘
//!  CopyTunnel client (SOCKS5 server) ─ encrypt ─▶ TCP ─▶ CopyTunnel server
//!                                                             │ decrypt
//!                                                             ▼
//!                                                        real destination
//! ```
//!
//! ## Wire protocol (per relayed connection, one TCP connection to the server)
//!
//! Every message is `[u16 length][ sealed-frame ]`, where the sealed frame is
//! produced by the configured cipher (fresh nonce per frame, authenticated).
//!
//!   1. client → server: sealed **request** = `[atyp][addr][port:2]` (SOCKS atyp)
//!   2. server → client: sealed **reply**   = `[status]` (0 = ok)
//!   3. both ways: sealed **data** frames of raw bytes until the half closes.
//!
//! Closing is signalled by shutting the TCP write half (the peer's next
//! length read hits EOF). TCP already guarantees ordering, and each frame is
//! independently authenticated, so a tampered or injected frame is dropped and
//! the connection is torn down.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use log::{debug, error, info, warn};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::config::Config;
use crate::crypto::{obfuscate_inplace, obfuscation_mask, Cipher};

/// Max plaintext bytes carried per data frame.
const MAX_CHUNK: usize = 16 * 1024;

// ─────────────────────────────────────────────────────────────────────────────
// Target address (SOCKS atyp encoding, reused on our own wire)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
enum Target {
    V4(Ipv4Addr, u16),
    V6(Ipv6Addr, u16),
    Domain(String, u16),
}

impl Target {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Target::V4(ip, port) => {
                out.push(0x01);
                out.extend_from_slice(&ip.octets());
                out.extend_from_slice(&port.to_be_bytes());
            }
            Target::Domain(host, port) => {
                out.push(0x03);
                out.push(host.len() as u8);
                out.extend_from_slice(host.as_bytes());
                out.extend_from_slice(&port.to_be_bytes());
            }
            Target::V6(ip, port) => {
                out.push(0x04);
                out.extend_from_slice(&ip.octets());
                out.extend_from_slice(&port.to_be_bytes());
            }
        }
        out
    }

    fn decode(buf: &[u8]) -> Result<Target> {
        if buf.is_empty() {
            bail!("empty target");
        }
        match buf[0] {
            0x01 => {
                if buf.len() < 1 + 4 + 2 {
                    bail!("short ipv4 target");
                }
                let ip = Ipv4Addr::new(buf[1], buf[2], buf[3], buf[4]);
                let port = u16::from_be_bytes([buf[5], buf[6]]);
                Ok(Target::V4(ip, port))
            }
            0x03 => {
                let len = *buf.get(1).ok_or_else(|| anyhow!("short domain len"))? as usize;
                if buf.len() < 2 + len + 2 {
                    bail!("short domain target");
                }
                let host = String::from_utf8(buf[2..2 + len].to_vec())
                    .context("domain not utf8")?;
                let port = u16::from_be_bytes([buf[2 + len], buf[2 + len + 1]]);
                Ok(Target::Domain(host, port))
            }
            0x04 => {
                if buf.len() < 1 + 16 + 2 {
                    bail!("short ipv6 target");
                }
                let mut o = [0u8; 16];
                o.copy_from_slice(&buf[1..17]);
                let ip = Ipv6Addr::from(o);
                let port = u16::from_be_bytes([buf[17], buf[18]]);
                Ok(Target::V6(ip, port))
            }
            other => bail!("unknown atyp {other}"),
        }
    }

    async fn connect(&self) -> Result<TcpStream> {
        match self {
            Target::V4(ip, port) => Ok(TcpStream::connect(SocketAddr::from((*ip, *port))).await?),
            Target::V6(ip, port) => Ok(TcpStream::connect(SocketAddr::from((*ip, *port))).await?),
            Target::Domain(host, port) => Ok(TcpStream::connect((host.as_str(), *port)).await?),
        }
    }

    fn describe(&self) -> String {
        match self {
            Target::V4(ip, port) => format!("{ip}:{port}"),
            Target::V6(ip, port) => format!("[{ip}]:{port}"),
            Target::Domain(host, port) => format!("{host}:{port}"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AEAD TCP framing
// ─────────────────────────────────────────────────────────────────────────────

/// Encodes/decodes framed, sealed messages on a TCP half. Holds the cipher and
/// the optional obfuscation mask (both derived once and shared).
#[derive(Clone)]
struct Framer {
    cipher: Arc<Cipher>,
    mask: Option<Arc<[u8; 64]>>,
}

impl Framer {
    fn new(cfg: &Config) -> Result<Framer> {
        let cipher = Cipher::new(cfg.encryption, &cfg.pre_shared_key, &cfg.key_hex)?;
        let mask = if cfg.obfuscate {
            Some(Arc::new(obfuscation_mask(&cfg.pre_shared_key)))
        } else {
            None
        };
        Ok(Framer {
            cipher: Arc::new(cipher),
            mask,
        })
    }

    async fn write<W: AsyncWriteExt + Unpin>(&self, w: &mut W, plaintext: &[u8]) -> Result<()> {
        let mut frame = self.cipher.seal(plaintext)?;
        if let Some(mask) = &self.mask {
            obfuscate_inplace(&mut frame, mask);
        }
        if frame.len() > u16::MAX as usize {
            bail!("frame too large");
        }
        w.write_all(&(frame.len() as u16).to_be_bytes()).await?;
        w.write_all(&frame).await?;
        Ok(())
    }

    /// Returns `Ok(None)` on clean EOF before a frame starts.
    async fn read<R: AsyncReadExt + Unpin>(&self, r: &mut R) -> Result<Option<Vec<u8>>> {
        let mut len_buf = [0u8; 2];
        match r.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e.into()),
        }
        let len = u16::from_be_bytes(len_buf) as usize;
        if len == 0 {
            bail!("zero-length frame");
        }
        let mut frame = vec![0u8; len];
        r.read_exact(&mut frame).await?;
        if let Some(mask) = &self.mask {
            obfuscate_inplace(&mut frame, mask);
        }
        let plain = self.cipher.open(&frame)?;
        Ok(Some(plain))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Client: SOCKS5 server → encrypted relay to the CopyTunnel server
// ─────────────────────────────────────────────────────────────────────────────

/// Run the proxy client: a local SOCKS5 server that tunnels every CONNECT to the
/// CopyTunnel server.
pub async fn run_client_proxy(cfg: Arc<Config>) -> Result<()> {
    let bind: SocketAddr = cfg.parsed_socks_listen()?;
    let server: SocketAddr = cfg.parsed_proxy_server()?;
    let framer = Framer::new(&cfg)?;

    let listener = TcpListener::bind(bind)
        .await
        .with_context(|| format!("bind SOCKS5 listener on {bind}"))?;
    info!("SOCKS5 server on {bind} → CopyTunnel server {server}");

    loop {
        tokio::select! {
            accept = listener.accept() => {
                let (sock, peer) = match accept {
                    Ok(v) => v,
                    Err(e) => { warn!("accept failed: {e}"); continue; }
                };
                let framer = framer.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_socks_client(sock, server, framer).await {
                        debug!("socks session from {peer} ended: {e}");
                    }
                });
            }
            _ = tokio::signal::ctrl_c() => {
                info!("shutting down (signal)");
                return Ok(());
            }
        }
    }
}

async fn handle_socks_client(
    mut local: TcpStream,
    server: SocketAddr,
    framer: Framer,
) -> Result<()> {
    // ── SOCKS5 greeting ──
    let mut head = [0u8; 2];
    local.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        bail!("not SOCKS5");
    }
    let nmethods = head[1] as usize;
    let mut methods = vec![0u8; nmethods];
    local.read_exact(&mut methods).await?;
    // Reply: version 5, "no authentication required".
    local.write_all(&[0x05, 0x00]).await?;

    // ── SOCKS5 request ──
    let mut req = [0u8; 4];
    local.read_exact(&mut req).await?;
    if req[0] != 0x05 {
        bail!("bad request version");
    }
    let cmd = req[1];
    let atyp = req[3];
    let target = read_socks_target(&mut local, atyp).await?;

    if cmd != 0x01 {
        // Only CONNECT is supported; reply "command not supported".
        socks_reply(&mut local, 0x07).await?;
        bail!("unsupported SOCKS command {cmd} (only CONNECT)");
    }

    // ── Dial the CopyTunnel server and perform the tunnel handshake ──
    let mut up = TcpStream::connect(server)
        .await
        .with_context(|| format!("connect to CopyTunnel server {server}"))?;
    up.set_nodelay(true).ok();
    framer.write(&mut up, &target.encode()).await?;

    let reply = framer
        .read(&mut up)
        .await?
        .ok_or_else(|| anyhow!("server closed before reply"))?;
    let status = *reply.first().unwrap_or(&0xff);
    if status != 0x00 {
        socks_reply(&mut local, 0x05).await?; // connection refused
        bail!("server could not reach {} (status {status})", target.describe());
    }

    // Tell the SOCKS client we're connected (BND.ADDR 0.0.0.0:0).
    socks_reply(&mut local, 0x00).await?;
    debug!("proxying → {}", target.describe());

    relay(local, up, framer).await
}

async fn read_socks_target(local: &mut TcpStream, atyp: u8) -> Result<Target> {
    match atyp {
        0x01 => {
            let mut b = [0u8; 6];
            local.read_exact(&mut b).await?;
            Ok(Target::V4(
                Ipv4Addr::new(b[0], b[1], b[2], b[3]),
                u16::from_be_bytes([b[4], b[5]]),
            ))
        }
        0x03 => {
            let mut l = [0u8; 1];
            local.read_exact(&mut l).await?;
            let mut host = vec![0u8; l[0] as usize];
            local.read_exact(&mut host).await?;
            let mut p = [0u8; 2];
            local.read_exact(&mut p).await?;
            Ok(Target::Domain(
                String::from_utf8(host).context("domain not utf8")?,
                u16::from_be_bytes(p),
            ))
        }
        0x04 => {
            let mut b = [0u8; 18];
            local.read_exact(&mut b).await?;
            let mut o = [0u8; 16];
            o.copy_from_slice(&b[..16]);
            Ok(Target::V6(
                Ipv6Addr::from(o),
                u16::from_be_bytes([b[16], b[17]]),
            ))
        }
        other => bail!("unknown SOCKS atyp {other}"),
    }
}

async fn socks_reply(local: &mut TcpStream, code: u8) -> Result<()> {
    // VER REP RSV ATYP(IPv4) BND.ADDR(0.0.0.0) BND.PORT(0)
    local
        .write_all(&[0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Server: accept encrypted sessions → connect to the real destination
// ─────────────────────────────────────────────────────────────────────────────

/// Run the proxy server: accept encrypted TCP sessions and bridge them to their
/// real destinations.
pub async fn run_server_proxy(cfg: Arc<Config>) -> Result<()> {
    let bind: SocketAddr = cfg.parsed_proxy_listen()?;
    let framer = Framer::new(&cfg)?;
    let listener = TcpListener::bind(bind)
        .await
        .with_context(|| format!("bind proxy listener on {bind}"))?;
    info!("proxy (SOCKS stream) listener on {bind}");

    loop {
        tokio::select! {
            accept = listener.accept() => {
                let (sock, peer) = match accept {
                    Ok(v) => v,
                    Err(e) => { warn!("accept failed: {e}"); continue; }
                };
                let framer = framer.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_server_session(sock, framer).await {
                        debug!("session from {peer} ended: {e}");
                    }
                });
            }
            _ = tokio::signal::ctrl_c() => {
                info!("proxy listener shutting down (signal)");
                return Ok(());
            }
        }
    }
}

async fn handle_server_session(mut down: TcpStream, framer: Framer) -> Result<()> {
    down.set_nodelay(true).ok();
    // First frame = request. If it fails to authenticate we just drop the
    // connection (this shields the server from random internet scanners).
    let req = framer
        .read(&mut down)
        .await?
        .ok_or_else(|| anyhow!("client closed before request"))?;
    let target = Target::decode(&req)?;

    match target.connect().await {
        Ok(up) => {
            up.set_nodelay(true).ok();
            framer.write(&mut down, &[0x00]).await?; // ok
            debug!("connected → {}", target.describe());
            relay(up, down, framer).await
        }
        Err(e) => {
            let _ = framer.write(&mut down, &[0x01]).await; // failure
            bail!("connect to {} failed: {e}", target.describe());
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Bidirectional relay: raw `plain` side ⇄ framed `tunnel` side
// ─────────────────────────────────────────────────────────────────────────────

/// Pump bytes in both directions between a plaintext stream (`plain`: the local
/// SOCKS client, or the server-side destination) and the encrypted tunnel
/// stream (`tunnel`). Returns when either side closes.
async fn relay(plain: TcpStream, tunnel: TcpStream, framer: Framer) -> Result<()> {
    let (mut plain_r, mut plain_w) = plain.into_split();
    let (mut tun_r, mut tun_w) = tunnel.into_split();

    let f1 = framer.clone();
    // plain → tunnel (seal)
    let up = tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_CHUNK];
        loop {
            let n = match plain_r.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if f1.write(&mut tun_w, &buf[..n]).await.is_err() {
                break;
            }
        }
        let _ = tun_w.shutdown().await;
    });

    let f2 = framer;
    // tunnel → plain (open)
    let down = tokio::spawn(async move {
        while let Ok(Some(data)) = f2.read(&mut tun_r).await {
            if plain_w.write_all(&data).await.is_err() {
                break;
            }
        }
        let _ = plain_w.shutdown().await;
    });

    let _ = tokio::join!(up, down);
    Ok(())
}

/// Entry point used by `main` for the server: run the proxy listener, logging a
/// fatal error if it dies.
pub async fn serve(cfg: Arc<Config>) {
    if let Err(e) = run_server_proxy(cfg).await {
        error!("proxy server stopped: {e:#}");
    }
}
