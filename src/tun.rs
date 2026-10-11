//! Linux TUN device: creation, address configuration, and async I/O.
//!
//! A TUN device is a virtual interface the kernel treats like a NIC: packets the
//! kernel routes into it appear as reads on a file descriptor, and bytes written
//! to that descriptor are injected into the network stack as if they had arrived
//! on a wire. CopyTunnel reads raw IPv4 packets here on the client, and writes
//! decrypted packets here on the server so the kernel can route/NAT them onward.
//!
//! Linux only. TUN support on Windows/macOS uses entirely different APIs and is
//! out of scope (matching the reference project, which is Linux-only).

#![cfg(target_os = "linux")]

use std::io;
use std::os::unix::io::{AsRawFd, RawFd};
use std::process::Command;

use anyhow::{bail, Context, Result};
use tokio::io::unix::AsyncFd;

use crate::config::Config;

const TUN_DEV: &str = "/dev/net/tun";
const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;
// _IOW('T', 202, int) on Linux.
const TUNSETIFF: libc::c_ulong = 0x4004_54ca;

/// Owns the raw TUN file descriptor and closes it on drop.
struct TunFd(RawFd);

impl AsRawFd for TunFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

impl Drop for TunFd {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.0);
        }
    }
}

impl TunFd {
    fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let n = unsafe { libc::read(self.0, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }

    fn write(&self, buf: &[u8]) -> io::Result<usize> {
        let n = unsafe { libc::write(self.0, buf.as_ptr() as *const libc::c_void, buf.len()) };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }
}

/// An async-capable TUN interface.
pub struct Tun {
    fd: AsyncFd<TunFd>,
    name: String,
}

impl Tun {
    /// Create the TUN device, assign its address, bring it up, and set the MTU.
    ///
    /// Requires `CAP_NET_ADMIN` (run as root, or grant the capability to the
    /// binary with `setcap`).
    pub fn create(cfg: &Config) -> Result<Tun> {
        // Open the clone device.
        let fd = unsafe { libc::open(c_path(TUN_DEV).as_ptr(), libc::O_RDWR) };
        if fd < 0 {
            return Err(io::Error::last_os_error())
                .context("open /dev/net/tun (is the tun module loaded? are you root?)");
        }
        let tunfd = TunFd(fd);

        // Build the ifreq structure: 16-byte name followed by the flags union.
        // We lay it out manually to avoid depending on libc's ifreq, whose
        // padding differs between platforms.
        let mut ifr = [0u8; 40];
        let name_bytes = cfg.tun_name.as_bytes();
        if name_bytes.len() >= 16 {
            bail!("tun_name must be shorter than 16 characters");
        }
        ifr[..name_bytes.len()].copy_from_slice(name_bytes);
        let flags = (IFF_TUN | IFF_NO_PI) as u16;
        ifr[16..18].copy_from_slice(&flags.to_ne_bytes());

        let rc = unsafe { libc::ioctl(fd, TUNSETIFF, ifr.as_mut_ptr()) };
        if rc < 0 {
            return Err(io::Error::last_os_error()).context("ioctl(TUNSETIFF)");
        }

        // Switch the fd to non-blocking so AsyncFd can drive it.
        set_nonblocking(fd)?;

        // Configure addressing through the `ip` command — robust and matches how
        // most tunnel tooling sets interfaces up.
        configure_interface(cfg)?;

        Ok(Tun {
            fd: AsyncFd::new(tunfd).context("register TUN fd with tokio")?,
            name: cfg.tun_name.clone(),
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Read one IP packet from the kernel.
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.fd.readable().await?;
            match guard.try_io(|inner| inner.get_ref().read(buf)) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }

    /// Inject one IP packet into the kernel.
    pub async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.fd.writable().await?;
            match guard.try_io(|inner| inner.get_ref().write(buf)) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }
}

fn set_nonblocking(fd: RawFd) -> Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error()).context("fcntl(F_GETFL) on TUN");
    }
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if rc < 0 {
        return Err(io::Error::last_os_error()).context("fcntl(F_SETFL, O_NONBLOCK) on TUN");
    }
    Ok(())
}

fn configure_interface(cfg: &Config) -> Result<()> {
    let prefix = netmask_to_prefix(&cfg.tun_netmask)?;
    // Point-to-point addressing: local tun_ip, peer tun_peer_ip.
    run_ip(&[
        "addr", "add",
        &format!("{}/{}", cfg.tun_ip, prefix),
        "peer", &cfg.tun_peer_ip,
        "dev", &cfg.tun_name,
    ])?;
    run_ip(&["link", "set", "dev", &cfg.tun_name, "mtu", &cfg.mtu.to_string()])?;
    run_ip(&["link", "set", "dev", &cfg.tun_name, "up"])?;
    Ok(())
}

fn run_ip(args: &[&str]) -> Result<()> {
    let status = Command::new("ip")
        .args(args)
        .status()
        .with_context(|| format!("failed to run `ip {}`", args.join(" ")))?;
    if !status.success() {
        bail!("`ip {}` exited with {}", args.join(" "), status);
    }
    Ok(())
}

fn netmask_to_prefix(mask: &str) -> Result<u32> {
    let m: std::net::Ipv4Addr = mask.parse().context("invalid netmask")?;
    Ok(u32::from(m).count_ones())
}

fn c_path(p: &str) -> Vec<libc::c_char> {
    let mut v: Vec<libc::c_char> = p.bytes().map(|b| b as libc::c_char).collect();
    v.push(0);
    v
}
