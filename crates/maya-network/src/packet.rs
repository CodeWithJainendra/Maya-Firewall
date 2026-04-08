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

        // Parse TCP header (protocol 6)
        let tcp = if ip.protocol == 6 && data.len() >= ip_start + ihl + 20 {
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
