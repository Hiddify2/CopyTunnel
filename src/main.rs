//! CopyTunnel — encrypted layer-3 packet relay.
//!
//! A single binary that runs as either the `client` (captures local TCP/UDP
//! traffic through a TUN device and relays every packet to the server, encrypted)
//! or the `server` (decrypts the relayed packets and lets the kernel route them
//! to their real destination, then relays the replies back).
//!
//! The role, cipher, addresses, and interface settings all come from one TOML
//! config file shared by both sides.

mod config;
mod crypto;
mod logging;
mod packet;

#[cfg(target_os = "linux")]
mod netsetup;
#[cfg(target_os = "linux")]
mod tun;
#[cfg(target_os = "linux")]
mod tunnel;

use anyhow::Result;
use clap::Parser;

use crate::config::{Config, Role};

#[derive(Parser, Debug)]
#[command(
    name = "copytunnel",
    version,
    about = "Encrypted layer-3 tunnel that copies TCP/UDP packets to a remote peer"
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

    run(cfg)
}

#[cfg(target_os = "linux")]
fn run(cfg: Config) -> Result<()> {
    use std::sync::Arc;

    let threads = if cfg.worker_threads == 0 {
        std::thread::available_parallelism().map(|n| n.get()).unwrap_or(2)
    } else {
        cfg.worker_threads
    };

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(threads)
        .enable_all()
        .build()?;

    let cfg = Arc::new(cfg);
    rt.block_on(async move {
        match cfg.role {
            Role::Client => tunnel::run_client(cfg).await,
            Role::Server => tunnel::run_server(cfg).await,
        }
    })
}

#[cfg(not(target_os = "linux"))]
fn run(_cfg: Config) -> Result<()> {
    anyhow::bail!(
        "CopyTunnel's TUN data path is Linux-only. Build and run it on a Linux host \
         (the config parser and crypto still compile elsewhere for development)."
    )
}
