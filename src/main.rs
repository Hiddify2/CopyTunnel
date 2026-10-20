//! CopyTunnel — encrypted packet/stream relay.
//!
//! One binary, two roles and (on the client) two capture modes:
//!
//!   * `role = "client"`, `mode = "tun"`   — capture IP packets via a TUN device
//!     and relay them over UDP (layer 3).
//!   * `role = "client"`, `mode = "proxy"` — run a local SOCKS5 server (fed by
//!     sing-box's transparent tproxy inbound) and relay TCP streams over an
//!     encrypted TCP connection (layer 4).
//!   * `role = "server"` — serve both kinds of client at once: a UDP listener for
//!     TUN clients and a TCP listener for proxy clients, sharing one key/cipher.

mod config;
mod crypto;
mod logging;
mod packet;
mod proxy;

#[cfg(target_os = "linux")]
mod netsetup;
#[cfg(target_os = "linux")]
mod tun;
#[cfg(target_os = "linux")]
mod tunnel;

use std::sync::Arc;

use anyhow::Result;
use clap::Parser;

use crate::config::{Config, Mode, Role};

#[derive(Parser, Debug)]
#[command(
    name = "copytunnel",
    version,
    about = "Encrypted tunnel that relays TCP/UDP traffic to a remote peer (TUN or transparent-proxy mode)"
)]
struct Args {
    /// Path to the TOML configuration file.
    #[arg(short, long, default_value = "config/client.toml")]
    config: String,

    /// Override the log level (trace|debug|info|warn|error).
    #[arg(short, long)]
    log_level: Option<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let cfg = Config::from_file(&args.config)?;

    let level = args.log_level.clone().unwrap_or_else(|| cfg.log_level.clone());
    logging::init(&level);

    let role = match cfg.role {
        Role::Client => "client",
        Role::Server => "server",
    };
    logging::banner(role, env!("CARGO_PKG_VERSION"));
    log::info!("cipher: {}", cfg.encryption.human_name());
    if cfg.obfuscate {
        log::info!("whole-frame XOR obfuscation: enabled");
    }

    let threads = if cfg.worker_threads == 0 {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(2)
    } else {
        cfg.worker_threads
    };
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(threads)
        .enable_all()
        .build()?;

    let cfg = Arc::new(cfg);
    rt.block_on(dispatch(cfg))
}

async fn dispatch(cfg: Arc<Config>) -> Result<()> {
    match cfg.role {
        Role::Client => match cfg.mode {
            Mode::Proxy => {
                log::info!("client mode: transparent proxy (SOCKS5 + TCP transport)");
                proxy::run_client_proxy(cfg).await
            }
            Mode::Tun => run_tun_client(cfg).await,
        },
        Role::Server => run_server(cfg).await,
    }
}

// ── Server: run the proxy and/or TUN listeners together ─────────────────────

#[cfg(target_os = "linux")]
async fn run_server(cfg: Arc<Config>) -> Result<()> {
    let tun = cfg.server_tun_enabled();
    let proxy = cfg.server_proxy_enabled();

    if proxy {
        let c = cfg.clone();
        tokio::spawn(async move { proxy::serve(c).await });
    }

    if tun {
        // Foreground: owns the Ctrl-C handler and NAT-teardown guard.
        tunnel::run_server(cfg).await
    } else {
        // Proxy only: park until signalled.
        tokio::signal::ctrl_c().await?;
        log::info!("shutting down (signal)");
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
async fn run_server(cfg: Arc<Config>) -> Result<()> {
    // Only the proxy path is available off Linux (TUN needs Linux).
    if cfg.server_proxy_enabled() {
        proxy::run_server_proxy(cfg).await
    } else {
        anyhow::bail!(
            "this server config only enables the TUN listener, which is Linux-only. \
             Set `proxy_listen` to run the transparent-proxy server here, or deploy on Linux."
        )
    }
}

// ── Client TUN mode ─────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
async fn run_tun_client(cfg: Arc<Config>) -> Result<()> {
    log::info!("client mode: TUN (layer-3 packet capture, UDP transport)");
    tunnel::run_client(cfg).await
}

#[cfg(not(target_os = "linux"))]
async fn run_tun_client(_cfg: Arc<Config>) -> Result<()> {
    anyhow::bail!(
        "TUN mode is Linux-only. Use `mode = \"proxy\"` on this platform, or deploy on Linux."
    )
}
