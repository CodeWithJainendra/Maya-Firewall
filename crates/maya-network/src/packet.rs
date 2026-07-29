//! Raw packet structures and parsing.
//! Zero-copy packet parsing for maximum throughput at kernel-boundary.

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Raw captured packet with metadata.
#[derive(Debug, Clone)]
pub struct RawPacket {
    /// Raw packet bytes
    pub data: Bytes,
    /// Capture timestamp (nanoseconds since epoch)
    pub timestamp_ns: u64,
    /// Interface index where captured
    pub ifindex: u32,
    /// Packet direction
    pub direction: PacketDirection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketDirection {
    Ingress,
    Egress,
}

/// Parsed Ethernet header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EthernetHeader {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ethertype: u16,
}

/// Parsed IPv4 header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ipv4Header {
    pub version: u8,
    pub ihl: u8,
    pub tos: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub src_addr: std::net::Ipv4Addr,
    pub dst_addr: std::net::Ipv4Addr,
}

/// Parsed TCP header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq_num: u32,
    pub ack_num: u32,
    pub data_offset: u8,
    pub flags: TcpFlags,
    pub window_size: u16,
    pub checksum: u16,
    pub urgent_pointer: u16,
}

/// TCP flags for scan detection.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct TcpFlags {
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
    pub urg: bool,
    pub ece: bool,
    pub cwr: bool,
}

impl TcpFlags {
    /// Parse TCP flags from a byte.
    pub fn from_byte(byte: u8) -> Self {
        Self {
            fin: byte & 0x01 != 0,
            syn: byte & 0x02 != 0,
            rst: byte & 0x04 != 0,
            psh: byte & 0x08 != 0,
            ack: byte & 0x10 != 0,
            urg: byte & 0x20 != 0,
            ece: byte & 0x40 != 0,
            cwr: byte & 0x80 != 0,
        }
    }

    /// Detect scan type from TCP flags.
    pub fn scan_type(&self) -> Option<maya_core::types::ScanType> {
        use maya_core::types::ScanType;
        if self.syn && !self.ack && !self.fin && !self.rst {
            Some(ScanType::SynScan)
        } else if self.ack && !self.syn {
            Some(ScanType::AckScan)
        } else if self.fin && !self.syn && !self.ack {
            Some(ScanType::FinScan)
        } else if self.fin && self.psh && self.urg {
            Some(ScanType::XmasScan)
        } else if !self.fin && !self.syn && !self.rst && !self.psh && !self.ack && !self.urg {
            Some(ScanType::NullScan)
        } else {
            None
        }
    }
}

/// A fully parsed packet ready for analysis.
#[derive(Debug, Clone)]
pub struct ParsedPacket {
    pub ethernet: EthernetHeader,
    pub ip: Option<Ipv4Header>,
    pub tcp: Option<TcpHeader>,
    pub payload: Bytes,
    pub source_ip: Option<IpAddr>,
    pub dest_ip: Option<IpAddr>,
    pub source_port: Option<u16>,
    pub dest_port: Option<u16>,
}

impl ParsedPacket {
    /// Zero-copy parse from raw bytes.
    pub fn parse(raw: &RawPacket) -> Option<Self> {
        let data = &raw.data;
        if data.len() < 14 {
            return None; // Too small for ethernet
        }

        // Parse Ethernet header
        let ethernet = EthernetHeader {
            dst_mac: [data[0], data[1], data[2], data[3], data[4], data[5]],
            src_mac: [data[6], data[7], data[8], data[9], data[10], data[11]],
            ethertype: u16::from_be_bytes([data[12], data[13]]),
        };

        // Only process IPv4 (0x0800)
        if ethernet.ethertype != 0x0800 {
            return Some(Self {
                ethernet,
                ip: None,
                tcp: None,
                payload: Bytes::new(),
                source_ip: None,
                dest_ip: None,
                source_port: None,
                dest_port: None,
            });
        }

        if data.len() < 34 {
            return None; // Too small for IPv4 + TCP
        }

        // Parse IPv4 header
        let ip_start = 14;
        let ihl = (data[ip_start] & 0x0F) as usize * 4;
        let ip = Ipv4Header {
            version: (data[ip_start] >> 4) & 0x0F,
            ihl: (data[ip_start] & 0x0F),
            tos: data[ip_start + 1],
            total_length: u16::from_be_bytes([data[ip_start + 2], data[ip_start + 3]]),
            identification: u16::from_be_bytes([data[ip_start + 4], data[ip_start + 5]]),
            flags: (data[ip_start + 6] >> 5) & 0x07,
            fragment_offset: u16::from_be_bytes([data[ip_start + 6] & 0x1F, data[ip_start + 7]]),
            ttl: data[ip_start + 8],
            protocol: data[ip_start + 9],
            checksum: u16::from_be_bytes([data[ip_start + 10], data[ip_start + 11]]),
            src_addr: std::net::Ipv4Addr::new(
                data[ip_start + 12],
                data[ip_start + 13],
                data[ip_start + 14],
                data[ip_start + 15],
            ),
            dst_addr: std::net::Ipv4Addr::new(
                data[ip_start + 16],
                data[ip_start + 17],
                data[ip_start + 18],
                data[ip_start + 19],
            ),
        };

        let source_ip = Some(IpAddr::V4(ip.src_addr));
        let dest_ip = Some(IpAddr::V4(ip.dst_addr));

        // Parse TCP header (protocol 6).
        //
        // Require a well-formed IPv4 header length (IHL >= 5, i.e. >= 20 bytes).
        // A crafted packet with IHL < 5 would otherwise place `tcp_start` inside
        // the IPv4/Ethernet header, so garbage bytes would be parsed as the
        // TCP ports/flags and fed into scan detection as attacker-chosen values.
        let tcp = if ip.protocol == 6 && ihl >= 20 && data.len() >= ip_start + ihl + 20 {
            let tcp_start = ip_start + ihl;
            let flags_byte = data[tcp_start + 13];
            Some(TcpHeader {
                src_port: u16::from_be_bytes([data[tcp_start], data[tcp_start + 1]]),
                dst_port: u16::from_be_bytes([data[tcp_start + 2], data[tcp_start + 3]]),
                seq_num: u32::from_be_bytes([
                    data[tcp_start + 4],
                    data[tcp_start + 5],
                    data[tcp_start + 6],
                    data[tcp_start + 7],
                ]),
                ack_num: u32::from_be_bytes([
                    data[tcp_start + 8],
                    data[tcp_start + 9],
                    data[tcp_start + 10],
                    data[tcp_start + 11],
                ]),
                data_offset: (data[tcp_start + 12] >> 4) & 0x0F,
                flags: TcpFlags::from_byte(flags_byte),
                window_size: u16::from_be_bytes([data[tcp_start + 14], data[tcp_start + 15]]),
                checksum: u16::from_be_bytes([data[tcp_start + 16], data[tcp_start + 17]]),
                urgent_pointer: u16::from_be_bytes([data[tcp_start + 18], data[tcp_start + 19]]),
            })
        } else {
            None
        };

        let source_port = tcp.as_ref().map(|t| t.src_port);
        let dest_port = tcp.as_ref().map(|t| t.dst_port);

        let payload_start = if let Some(ref tcp_hdr) = tcp {
            ip_start + ihl + (tcp_hdr.data_offset as usize * 4)
        } else {
            ip_start + ihl
        };

        let payload = if payload_start < data.len() {
            raw.data.slice(payload_start..)
        } else {
            Bytes::new()
        };

        Some(Self {
            ethernet,
            ip: Some(ip),
            tcp,
            payload,
            source_ip,
            dest_ip,
            source_port,
            dest_port,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(data: Vec<u8>) -> RawPacket {
        RawPacket {
            data: Bytes::from(data),
            timestamp_ns: 0,
            ifindex: 0,
            direction: PacketDirection::Ingress,
        }
    }

    /// Build an Ethernet+IPv4(+TCP) frame with the given IPv4 IHL nibble.
    fn frame_with_ihl(ihl_nibble: u8) -> Vec<u8> {
        let mut d = vec![0u8; 54];
        // Ethernet ethertype = IPv4
        d[12] = 0x08;
        d[13] = 0x00;
        // IPv4 version (4) + IHL nibble
        d[14] = (4 << 4) | (ihl_nibble & 0x0F);
        // protocol = TCP (6) at ip_start + 9
        d[23] = 6;
        // TCP header assuming a well-formed 20-byte IPv4 header (tcp_start = 34)
        d[34] = 0x12; // src_port high
        d[35] = 0x34; // src_port low  => 0x1234
        d[36] = 0x00; // dst_port high
        d[37] = 0x50; // dst_port low  => 80
        d[46] = 0x50; // data_offset = 5 (<<4)
        d[47] = 0x02; // flags = SYN
        d
    }

    #[test]
    fn well_formed_tcp_packet_parses_ports() {
        let packet = ParsedPacket::parse(&raw(frame_with_ihl(5))).expect("should parse");
        let tcp = packet.tcp.expect("TCP header expected");
        assert_eq!(tcp.src_port, 0x1234);
        assert_eq!(tcp.dst_port, 80);
        assert!(tcp.flags.syn);
    }

    #[test]
    fn malformed_ihl_does_not_parse_tcp_from_ip_header() {
        // IHL = 4 (16 bytes) is below the 20-byte minimum. The TCP header must
        // not be parsed, otherwise bytes inside the IPv4 header would be read as
        // attacker-chosen ports/flags and fed to scan detection.
        for bad_ihl in [0u8, 1, 4] {
            let packet = ParsedPacket::parse(&raw(frame_with_ihl(bad_ihl)))
                .expect("IP header should still parse");
            assert!(
                packet.tcp.is_none(),
                "TCP must not parse for IHL={bad_ihl}"
            );
            assert!(packet.source_port.is_none());
            assert!(packet.dest_port.is_none());
        }
    }
}
