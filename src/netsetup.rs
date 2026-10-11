//! Server-side kernel plumbing: IPv4 forwarding + NAT so decrypted packets can
//! actually reach the internet and their replies find their way back.
//!
//! When `auto_nat = true` the server:
//!   1. enables `net.ipv4.ip_forward`,
//!   2. installs a MASQUERADE rule on the physical interface,
//!   3. allows forwarding to/from the TUN device,
//!
//! and tears all of that down again on shutdown. All operations are best-effort:
//! a failure is logged as a warning rather than aborting the tunnel, because
//! some deployments manage NAT externally.

#![cfg(target_os = "linux")]

use std::process::Command;

use log::{info, warn};

use crate::config::Config;

/// Guard that installs NAT rules on construction and removes them on drop.
pub struct NatGuard {
    tun: String,
    iface: String,
    installed: bool,
    prev_ip_forward: Option<String>,
}

impl NatGuard {
    pub fn install(cfg: &Config) -> NatGuard {
        let mut guard = NatGuard {
            tun: cfg.tun_name.clone(),
            iface: cfg.interface.clone(),
            installed: false,
            prev_ip_forward: read_ip_forward(),
        };

        // Enable IPv4 forwarding.
        if set_ip_forward("1") {
            info!("enabled net.ipv4.ip_forward");
        } else {
            warn!("could not enable net.ipv4.ip_forward — forwarding may not work");
        }

        // MASQUERADE outbound traffic leaving the physical NIC.
        let ok_masq = iptables(&[
            "-t", "nat", "-A", "POSTROUTING",
            "-o", &guard.iface, "-j", "MASQUERADE",
        ]);
        // Allow forwarding between the TUN and the NIC in both directions.
        let ok_fwd_in = iptables(&[
            "-A", "FORWARD", "-i", &guard.tun, "-o", &guard.iface, "-j", "ACCEPT",
        ]);
        let ok_fwd_out = iptables(&[
            "-A", "FORWARD", "-i", &guard.iface, "-o", &guard.tun,
            "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT",
        ]);

        if ok_masq && ok_fwd_in && ok_fwd_out {
            guard.installed = true;
            info!("installed NAT (MASQUERADE on {}) + FORWARD rules", guard.iface);
        } else {
            warn!("one or more iptables rules failed to install; check `iptables -t nat -L`");
        }

        guard
    }
}

impl Drop for NatGuard {
    fn drop(&mut self) {
        if self.installed {
            let _ = iptables(&[
                "-t", "nat", "-D", "POSTROUTING",
                "-o", &self.iface, "-j", "MASQUERADE",
            ]);
            let _ = iptables(&[
                "-D", "FORWARD", "-i", &self.tun, "-o", &self.iface, "-j", "ACCEPT",
            ]);
            let _ = iptables(&[
                "-D", "FORWARD", "-i", &self.iface, "-o", &self.tun,
                "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT",
            ]);
            info!("removed NAT / FORWARD rules");
        }
        if let Some(prev) = &self.prev_ip_forward {
            let _ = set_ip_forward(prev.trim());
        }
    }
}

fn iptables(args: &[&str]) -> bool {
    match Command::new("iptables").args(args).status() {
        Ok(s) => s.success(),
        Err(e) => {
            warn!("failed to execute iptables: {e}");
            false
        }
    }
}

fn read_ip_forward() -> Option<String> {
    std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward").ok()
}

fn set_ip_forward(val: &str) -> bool {
    std::fs::write("/proc/sys/net/ipv4/ip_forward", val).is_ok()
}
