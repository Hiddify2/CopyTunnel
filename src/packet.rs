//! Minimal IPv4 packet inspection.
//!
//! CopyTunnel operates at layer 3: it never rewrites packets, it only *decides*
//! whether to tunnel a given packet based on its IP protocol and L4 ports. This
//! module provides just enough parsing for that decision and nothing more.

/// Protocol/port facts extracted from an IPv4 packet header.
#[derive(Debug, Clone, Copy)]
pub struct PacketInfo {
    pub protocol: u8,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
}

/// Parse the fixed parts of an IPv4 header (and the first four bytes of the L4
/// header for TCP/UDP ports). Returns `None` for non-IPv4 or truncated packets.
pub fn inspect_ipv4(pkt: &[u8]) -> Option<PacketInfo> {
    if pkt.len() < 20 {
        return None;
    }
    let version = pkt[0] >> 4;
    if version != 4 {
        return None; // IPv6 or garbage — caller decides what to do.
    }
    let ihl = (pkt[0] & 0x0f) as usize * 4;
    if ihl < 20 || pkt.len() < ihl {
        return None;
    }
    let protocol = pkt[9];

    let (src_port, dst_port) = match protocol {
        6 | 17 => {
            // TCP and UDP both begin with [src_port:2][dst_port:2].
            if pkt.len() >= ihl + 4 {
                let sp = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
                let dp = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
                (Some(sp), Some(dp))
            } else {
                (None, None)
            }
        }
        _ => (None, None),
    };

    Some(PacketInfo {
        protocol,
        src_port,
        dst_port,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_udp_ports() {
        // IHL=5 (20 bytes), proto=17 (UDP), ports 53 -> 1024.
        let mut pkt = vec![0u8; 28];
        pkt[0] = 0x45;
        pkt[9] = 17;
        pkt[20..22].copy_from_slice(&53u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&1024u16.to_be_bytes());
        let info = inspect_ipv4(&pkt).unwrap();
        assert_eq!(info.protocol, 17);
        assert_eq!(info.src_port, Some(53));
        assert_eq!(info.dst_port, Some(1024));
    }

    #[test]
    fn rejects_ipv6() {
        let pkt = [0x60u8; 40];
        assert!(inspect_ipv4(&pkt).is_none());
    }
}
