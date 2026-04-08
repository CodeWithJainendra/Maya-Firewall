//! Utility functions for Project MAYA.
//!
//! Cryptographic hashing, fake data generation, network helpers, and more.

use rand::Rng;
use sha2::{Digest, Sha256};
use std::net::IpAddr;

/// Generate SHA-256 hash of bytes, returned as hex string.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Generate a random IP address within a given CIDR range.
pub fn random_ip_in_subnet(cidr: &str) -> Option<IpAddr> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return None;
    }

    let base_ip: std::net::Ipv4Addr = parts[0].parse().ok()?;
    let prefix_len: u32 = parts[1].parse().ok()?;

    if prefix_len > 32 {
        return None;
    }

    if prefix_len == 32 {
        return Some(IpAddr::V4(base_ip));
    }

    let base_u32 = u32::from(base_ip);
    let host_bits = 32 - prefix_len;
    let host_space = 1u64 << host_bits;

    if host_space <= 2 {
        return None;
    }

    let mut rng = rand::rng();
    // /0 requires a special path because shifting by 32 in u32 is invalid.
    if host_bits == 32 {
        let host_part: u32 = rng.random_range(1..u32::MAX);
        return Some(IpAddr::V4(std::net::Ipv4Addr::from(host_part)));
    }

    // Avoid network address (0) and broadcast (all 1s)
    let host_part: u32 = rng.random_range(1..(host_space as u32 - 1));
    let mask = !((1u32 << host_bits) - 1);
    let ip_u32 = (base_u32 & mask) | host_part;

    Some(IpAddr::V4(std::net::Ipv4Addr::from(ip_u32)))
}

/// Generate a realistic hostname.
pub fn generate_hostname(decoy_type: &str) -> String {
    let mut rng = rand::rng();
    let prefixes = match decoy_type {
        "linux" => &["srv", "web", "db", "app", "mail", "dev", "staging", "prod"][..],
        "windows" => &["WIN", "DC", "EXCH", "SQL", "WEB", "FILE", "PRINT", "RDP"][..],
        "scada" => &["PLC", "RTU", "HMI", "DCS", "SCADA", "OPC"][..],
        "network" => &["fw", "sw", "rt", "lb", "vpn", "proxy"][..],
        _ => &["host", "node", "system"][..],
    };

    let prefix = prefixes[rng.random_range(0..prefixes.len())];
    let suffix: u16 = rng.random_range(1..999);
    let domains = ["corp.local", "internal.net", "prod.lan", "infra.local"];
    let domain = domains[rng.random_range(0..domains.len())];

    format!("{prefix}-{suffix:03}.{domain}")
}

/// Generate a realistic service version banner.
pub fn generate_banner(service: &str) -> String {
    let mut rng = rand::rng();
    match service {
        "ssh" => {
            let versions = [
                "OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
                "OpenSSH_7.4 CentOS-7",
                "OpenSSH_8.2p1 Ubuntu-4ubuntu0.11",
                "OpenSSH_9.3p1 Debian-1",
            ];
            format!("SSH-2.0-{}", versions[rng.random_range(0..versions.len())])
        }
        "http" => {
            let servers = [
                "Apache/2.4.41 (Ubuntu)",
                "nginx/1.18.0",
                "Microsoft-IIS/10.0",
                "Apache/2.4.52 (Debian)",
            ];
            servers[rng.random_range(0..servers.len())].to_string()
        }
        "mysql" => {
            let versions = ["5.7.42", "8.0.33", "5.6.51", "8.0.36"];
            format!(
                "{}-0ubuntu0.18.04.1",
                versions[rng.random_range(0..versions.len())]
            )
        }
        "ftp" => {
            let versions = ["vsFTPd 3.0.3", "ProFTPD 1.3.5", "Pure-FTPd 1.0.49"];
            versions[rng.random_range(0..versions.len())].to_string()
        }
        "smb" => "Samba 4.15.13-Ubuntu".to_string(),
        "rdp" => "Microsoft Terminal Services".to_string(),
        _ => format!(
            "Unknown Service/{}.{}",
            rng.random_range(1..10u32),
            rng.random_range(0..99u32)
        ),
    }
}

/// Generate fake but valid-looking Aadhaar number (passes Verhoeff checksum).
pub fn generate_fake_aadhaar() -> String {
    let mut rng = rand::rng();
    // Generate 11 random digits, then compute check digit
    let mut digits: Vec<u8> = (0..11).map(|_| rng.random_range(0..10u8)).collect();
    // Ensure first digit is 2-9 (valid Aadhaar)
    digits[0] = rng.random_range(2..10u8);

    let check = verhoeff_checksum(&digits);
    digits.push(check);

    digits
        .iter()
        .map(|d| d.to_string())
        .collect::<Vec<_>>()
        .join("")
}

/// Verhoeff checksum computation.
fn verhoeff_checksum(digits: &[u8]) -> u8 {
    let d: [[u8; 10]; 10] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
        [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
        [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
        [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
        [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
        [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
        [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
        [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
        [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
    ];

    let p: [[u8; 10]; 8] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
        [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
        [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
        [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
        [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
        [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
        [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
    ];

    let inv: [u8; 10] = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9];

    let mut c: u8 = 0;
    for (i, &digit) in digits.iter().rev().enumerate() {
        c = d[c as usize][p[(i + 1) % 8][digit as usize] as usize];
    }

    inv[c as usize]
}

/// Generate realistic fake PAN number.
pub fn generate_fake_pan() -> String {
    let mut rng = rand::rng();
    let chars: Vec<char> = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".chars().collect();
    let types = ['C', 'P', 'H', 'F', 'A', 'T', 'B', 'L', 'J', 'G'];

    let mut pan = String::new();
    for _ in 0..3 {
        pan.push(chars[rng.random_range(0..chars.len())]);
    }
    pan.push(types[rng.random_range(0..types.len())]);
    pan.push(chars[rng.random_range(0..chars.len())]);
    for _ in 0..4 {
        pan.push(char::from(b'0' + rng.random_range(0..10u8)));
    }
    pan.push(chars[rng.random_range(0..chars.len())]);

    pan
}

/// Generate realistic fake Indian phone number.
pub fn generate_fake_phone() -> String {
    let mut rng = rand::rng();
    let prefixes = ["6", "7", "8", "9"];
    let prefix = prefixes[rng.random_range(0..prefixes.len())];
    let rest: String = (0..9)
        .map(|_| char::from(b'0' + rng.random_range(0..10u8)))
        .collect();
    format!("+91{prefix}{rest}")
}

/// Calculate Shannon entropy of a byte slice (0.0 - 8.0).
/// High entropy indicates encrypted/compressed/packed data.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut freq = [0u64; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }

    let len = data.len() as f64;
    freq.iter()
        .filter(|&&f| f > 0)
        .map(|&f| {
            let p = f as f64 / len;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        let hash = sha256_hex(b"test");
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_random_ip() {
        let ip = random_ip_in_subnet("10.13.37.0/24");
        assert!(ip.is_some());
        if let Some(IpAddr::V4(v4)) = ip {
            assert_eq!(v4.octets()[0], 10);
            assert_eq!(v4.octets()[1], 13);
            assert_eq!(v4.octets()[2], 37);
        }
    }

    #[test]
    fn test_random_ip_edge_prefixes() {
        assert_eq!(
            random_ip_in_subnet("10.13.37.42/32"),
            Some(IpAddr::V4(std::net::Ipv4Addr::new(10, 13, 37, 42)))
        );
        assert!(random_ip_in_subnet("10.13.37.0/31").is_none());
    }

    #[test]
    fn test_hostname_gen() {
        let host = generate_hostname("linux");
        assert!(host.contains('.'));
    }

    #[test]
    fn test_aadhaar_gen() {
        let aadhaar = generate_fake_aadhaar();
        assert_eq!(aadhaar.len(), 12);
    }

    #[test]
    fn test_pan_gen() {
        let pan = generate_fake_pan();
        assert_eq!(pan.len(), 10);
    }

    #[test]
    fn test_entropy() {
        let low_entropy = vec![0u8; 1000];
        let high_entropy: Vec<u8> = (0..=255).cycle().take(1000).collect();
        assert!(shannon_entropy(&low_entropy) < 1.0);
        assert!(shannon_entropy(&high_entropy) > 7.0);
    }
}
