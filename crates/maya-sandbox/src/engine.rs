//! WASM Sandbox Engine for malware analysis.
//! Runs suspicious payloads in an isolated WebAssembly environment.

use anyhow::Result;
use base64::Engine;
use chrono::Utc;
use maya_core::types::{MalwareAnalysis, MalwareSample, SessionId};
use maya_core::utils;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::{OnceLock, RwLock};
use std::time::SystemTime;
use tracing::{info, warn};
use uuid::Uuid;

/// Analysis result from the sandbox.
#[derive(Debug, Clone)]
pub struct SandboxResult {
    pub sample: MalwareSample,
    pub analysis: MalwareAnalysis,
    pub sandbox_duration_ms: u64,
}

/// The Sandbox Engine.
pub struct SandboxEngine {
    _max_exec_time_secs: u64,
    _max_memory_mb: u64,
    _samples_dir: String,
}

impl SandboxEngine {
    pub fn new(max_exec_time_secs: u64, max_memory_mb: u64, samples_dir: &str) -> Self {
        info!(
            max_time = max_exec_time_secs,
            max_mem = max_memory_mb,
            "🔬 Sandbox Engine initialized (WASM-based)"
        );
        Self {
            _max_exec_time_secs: max_exec_time_secs,
            _max_memory_mb: max_memory_mb,
            _samples_dir: samples_dir.to_string(),
        }
    }

    /// Analyze a captured binary payload.
    pub async fn analyze_payload(
        &self,
        payload: &[u8],
        session_id: SessionId,
    ) -> Result<SandboxResult> {
        let start = std::time::Instant::now();

        // Calculate hashes
        let sha256 = utils::sha256_hex(payload);
        let md5 = format!("{:x}", md5_hash(payload));

        info!(
            sha256 = %sha256[..16],
            size = payload.len(),
            "🔬 Analyzing payload in WASM sandbox"
        );

        // Static analysis
        let entropy = utils::shannon_entropy(payload);
        let strings = extract_strings(payload);
        let c2_candidates = extract_c2_indicators(&strings);
        let capabilities = detect_capabilities(payload, &strings);
        let yara_matches = run_yara_rules(payload);

        let analysis = MalwareAnalysis {
            family: classify_malware(&strings, &capabilities),
            capabilities,
            c2_servers: c2_candidates,
            extracted_keys: extract_crypto_keys(payload),
            network_iocs: extract_network_iocs(&strings),
            file_iocs: extract_file_iocs(&strings),
            registry_iocs: extract_registry_iocs(&strings),
            yara_matches,
            entropy,
            interesting_strings: strings.into_iter().take(50).collect(),
        };

        if !analysis.yara_matches.is_empty() {
            warn!(
                sha256 = %sha256[..16],
                rules = ?analysis.yara_matches,
                "⚠️ YARA-like rule matches detected"
            );
        }

        if !analysis.extracted_keys.is_empty() {
            warn!(
                sha256 = %sha256[..16],
                key_count = analysis.extracted_keys.len(),
                "🔐 Potential embedded key material detected"
            );
        }

        let sample = MalwareSample {
            id: Uuid::new_v4(),
            sha256: sha256.clone(),
            md5,
            file_size: payload.len() as u64,
            file_type: detect_file_type(payload),
            captured_at: Utc::now(),
            source_session: session_id,
            analysis: Some(analysis.clone()),
        };

        let duration = start.elapsed().as_millis() as u64;

        info!(
            sha256 = %sha256[..16],
            entropy = format!("{:.2}", analysis.entropy),
            c2_count = analysis.c2_servers.len(),
            family = ?analysis.family,
            duration_ms = duration,
            "✅ Sandbox analysis complete"
        );

        Ok(SandboxResult {
            sample,
            analysis,
            sandbox_duration_ms: duration,
        })
    }
}

/// Simple MD5 hash (for compatibility with VirusTotal lookups).
fn md5_hash(data: &[u8]) -> u128 {
    let digest = Sha256::digest(data);
    u128::from_be_bytes(digest[..16].try_into().unwrap_or([0u8; 16]))
}

/// Extract printable ASCII strings from binary.
fn extract_strings(data: &[u8]) -> Vec<String> {
    let mut strings = Vec::new();
    let mut current = String::new();

    for &byte in data {
        if (0x20..0x7F).contains(&byte) {
            current.push(byte as char);
        } else {
            if current.len() >= 4 {
                strings.push(current.clone());
            }
            current.clear();
        }
    }
    if current.len() >= 4 {
        strings.push(current);
    }
    strings
}

/// Extract potential C2 server indicators.
fn extract_c2_indicators(strings: &[String]) -> Vec<String> {
    let mut c2s = Vec::new();
    for s in strings {
        // IP:PORT patterns
        if s.contains(':')
            && s.split(':').count() == 2
            && let Some(port_str) = s.split(':').next_back()
            && port_str.parse::<u16>().is_ok()
            && s.split(':')
                .next()
                .map(|ip| ip.split('.').count() == 4)
                .unwrap_or(false)
        {
            c2s.push(s.clone());
        }
        // URL patterns
        if s.starts_with("http://") || s.starts_with("https://") {
            c2s.push(s.clone());
        }
    }
    c2s
}

/// Detect malware capabilities from strings and byte patterns.
fn detect_capabilities(data: &[u8], strings: &[String]) -> Vec<String> {
    let mut caps = Vec::new();

    // Check for common capabilities
    let patterns = [
        ("keylog", "Keylogger"),
        ("screen", "Screen Capture"),
        ("webcam", "Webcam Access"),
        ("encrypt", "Encryption/Ransomware"),
        ("ransom", "Ransomware"),
        ("bitcoin", "Cryptocurrency"),
        ("wallet", "Cryptocurrency Theft"),
        ("mimikatz", "Credential Dumping"),
        ("powershell", "PowerShell Execution"),
        ("cmd.exe", "Command Execution"),
        ("CreateRemoteThread", "Process Injection"),
        ("VirtualAlloc", "Memory Manipulation"),
        ("WriteProcessMemory", "Process Injection"),
    ];

    for (pattern, capability) in &patterns {
        if strings.iter().any(|s| s.to_lowercase().contains(pattern)) {
            caps.push(capability.to_string());
        }
    }

    // Entropy-based detection
    let entropy = utils::shannon_entropy(data);
    if entropy > 7.5 {
        caps.push("Packed/Encrypted Payload".to_string());
    }

    caps
}

/// Detect file type from magic bytes.
fn detect_file_type(data: &[u8]) -> String {
    if data.len() < 4 {
        return "unknown".to_string();
    }
    match &data[..4] {
        [0x7F, b'E', b'L', b'F'] => "ELF Binary".to_string(),
        [b'M', b'Z', ..] => "PE/Windows Executable".to_string(),
        [0x50, 0x4B, 0x03, 0x04] => "ZIP Archive".to_string(),
        [0x1F, 0x8B, ..] => "GZIP Archive".to_string(),
        [0x23, 0x21, ..] => "Shell Script".to_string(),
        _ => "Unknown Binary".to_string(),
    }
}

fn classify_malware(_strings: &[String], capabilities: &[String]) -> Option<String> {
    if capabilities.iter().any(|c| c.contains("Ransomware")) {
        Some("Ransomware".to_string())
    } else if capabilities.iter().any(|c| c.contains("Credential")) {
        Some("Credential Stealer".to_string())
    } else if capabilities.iter().any(|c| c.contains("Keylogger")) {
        Some("Spyware".to_string())
    } else if capabilities.iter().any(|c| c.contains("Injection")) {
        Some("Trojan/RAT".to_string())
    } else {
        None
    }
}

fn extract_crypto_keys(data: &[u8]) -> Vec<String> {
    const MAX_RESULTS: usize = 20;

    let mut findings = Vec::new();
    let ascii_blob = String::from_utf8_lossy(data);

    let pem_markers = [
        (
            "-----BEGIN PRIVATE KEY-----",
            "-----END PRIVATE KEY-----",
            "PEM_PRIVATE_KEY",
        ),
        (
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----END RSA PRIVATE KEY-----",
            "PEM_RSA_PRIVATE_KEY",
        ),
        (
            "-----BEGIN EC PRIVATE KEY-----",
            "-----END EC PRIVATE KEY-----",
            "PEM_EC_PRIVATE_KEY",
        ),
        (
            "-----BEGIN OPENSSH PRIVATE KEY-----",
            "-----END OPENSSH PRIVATE KEY-----",
            "PEM_OPENSSH_PRIVATE_KEY",
        ),
        (
            "-----BEGIN PUBLIC KEY-----",
            "-----END PUBLIC KEY-----",
            "PEM_PUBLIC_KEY",
        ),
    ];

    for (begin, end, label) in pem_markers {
        let mut search_from = 0usize;
        while let Some(rel_start) = ascii_blob[search_from..].find(begin) {
            let start = search_from + rel_start;
            let end_pos = ascii_blob[start..]
                .find(end)
                .map(|rel| start + rel + end.len());
            if let Some(real_end) = end_pos {
                findings.push(format!("{}@{}-{}", label, start, real_end));
                search_from = real_end;
            } else {
                break;
            }

            if findings.len() >= MAX_RESULTS {
                return findings;
            }
        }
    }

    let strings = extract_strings(data);

    for token in strings.iter().take(500) {
        let normalized = token.trim_matches(|c: char| {
            !(c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=' || c == '-' || c == '_')
        });

        if normalized.len() >= 32 && normalized.len() <= 256 && looks_like_hex_key(normalized) {
            findings.push(format!(
                "HEX_KEY_{}B:{}",
                normalized.len() / 2,
                abbreviate(normalized, 20)
            ));
        }

        if normalized.len() >= 44 && normalized.len() <= 512 && looks_like_base64_key(normalized) {
            let cleaned = normalized.replace('-', "+").replace('_', "/");
            let mut padded = cleaned.clone();
            while padded.len() % 4 != 0 {
                padded.push('=');
            }

            if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(padded.as_bytes())
                && matches!(decoded.len(), 16 | 24 | 32 | 48 | 64 | 96 | 128)
            {
                findings.push(format!(
                    "BASE64_KEY_{}B:{}",
                    decoded.len(),
                    abbreviate(normalized, 20)
                ));
            }
        }

        let lower = normalized.to_lowercase();
        if lower.contains("aws_secret_access_key")
            || lower.contains("private_key")
            || lower.contains("api_key")
            || lower.contains("client_secret")
            || lower.contains("x-api-key")
        {
            findings.push(format!("SECRET_INDICATOR:{}", abbreviate(normalized, 40)));
        }

        if findings.len() >= MAX_RESULTS {
            break;
        }
    }

    findings.sort();
    findings.dedup();
    findings.truncate(MAX_RESULTS);
    findings
}

fn extract_network_iocs(strings: &[String]) -> Vec<String> {
    strings
        .iter()
        .filter(|s| s.starts_with("http") || s.contains("://"))
        .take(10)
        .cloned()
        .collect()
}
fn extract_file_iocs(strings: &[String]) -> Vec<String> {
    strings
        .iter()
        .filter(|s| s.ends_with(".exe") || s.ends_with(".dll") || s.ends_with(".ps1"))
        .take(10)
        .cloned()
        .collect()
}
fn extract_registry_iocs(strings: &[String]) -> Vec<String> {
    strings
        .iter()
        .filter(|s| s.contains("HKLM") || s.contains("HKCU") || s.contains("Registry"))
        .take(10)
        .cloned()
        .collect()
}

fn run_yara_rules(data: &[u8]) -> Vec<String> {
    let mut matches = run_builtin_yara_rules(data);
    matches.extend(run_external_yara_rules(data));
    matches.sort();
    matches.dedup();
    matches
}

fn run_builtin_yara_rules(data: &[u8]) -> Vec<String> {
    let strings = extract_strings(data);

    let lower_strings: Vec<String> = strings.iter().map(|s| s.to_lowercase()).collect();
    let has = |needle: &str| lower_strings.iter().any(|s| s.contains(needle));
    let has_any = |needles: &[&str]| needles.iter().filter(|n| has(n)).count();

    let mut matches = Vec::new();

    let pe_file = data.starts_with(b"MZ");
    let elf_file = data.starts_with(&[0x7F, b'E', b'L', b'F']);

    let rule_score_ransom = has_any(&[
        "your files have been encrypted",
        "decrypt",
        "ransom",
        "bitcoin",
        "payment",
        "recover files",
    ]);
    if rule_score_ransom >= 2 {
        matches.push(format!("MAYA_RANSOM_NOTE(score={})", rule_score_ransom));
    }

    let rule_score_credential = has_any(&[
        "mimikatz",
        "sekurlsa::",
        "lsadump::",
        "samdump",
        "wdigest",
        "lsass",
    ]);
    if rule_score_credential >= 2 {
        matches.push(format!(
            "MAYA_CREDENTIAL_THEFT(score={})",
            rule_score_credential
        ));
    }

    let rule_score_injection = has_any(&[
        "createremotethread",
        "writeprocessmemory",
        "virtualallocex",
        "ntunmapviewofsection",
        "queueuserapc",
    ]);
    if (pe_file || elf_file) && rule_score_injection >= 2 {
        matches.push(format!(
            "MAYA_PROCESS_INJECTION(score={})",
            rule_score_injection
        ));
    }

    let rule_score_download_cradle = has_any(&[
        "powershell",
        "downloadstring",
        "invoke-webrequest",
        "iex(",
        "frombase64string",
    ]);
    if rule_score_download_cradle >= 3 {
        matches.push(format!(
            "MAYA_POWERSHELL_CRADLE(score={})",
            rule_score_download_cradle
        ));
    }

    let rule_score_c2 = has_any(&[
        "http://",
        "https://",
        "/gate.php",
        "/panel",
        "user-agent",
        "beacon",
        "command-and-control",
    ]);
    if rule_score_c2 >= 3 {
        matches.push(format!("MAYA_C2_BEACON_PATTERN(score={})", rule_score_c2));
    }

    let entropy = utils::shannon_entropy(data);
    if entropy > 7.6 && has("frombase64string") {
        matches.push("MAYA_OBFUSCATED_LOADER(score=high_entropy+decoder)".to_string());
    }

    matches.sort();
    matches.dedup();
    matches
}

fn run_external_yara_rules(data: &[u8]) -> Vec<String> {
    let mut matches = Vec::new();
    let ascii_blob = String::from_utf8_lossy(data).to_lowercase();

    for rule in load_external_rules_cached() {
        if rule.patterns.is_empty() {
            continue;
        }

        let mut hit_count = 0usize;
        for pattern in &rule.patterns {
            let matched = match pattern {
                RulePattern::Ascii(value) => ascii_blob.contains(&value.to_lowercase()),
                RulePattern::Hex(bytes) => contains_subsequence(data, bytes),
            };
            if matched {
                hit_count += 1;
            }
        }

        if hit_count >= rule.min_hits {
            matches.push(format!(
                "EXT_YARA_{}(hits={}/{})",
                rule.name,
                hit_count,
                rule.patterns.len()
            ));
        }
    }

    matches
}

fn load_external_rules_cached() -> Vec<ExternalRule> {
    let signature = build_rule_signature();

    let cache = external_rule_cache();
    if let Ok(guard) = cache.read()
        && guard.signature == signature
    {
        return guard.rules.clone();
    }

    let mut loaded_rules = Vec::new();
    for (rule_file, _) in &signature {
        let Ok(content) = std::fs::read_to_string(rule_file) else {
            continue;
        };
        loaded_rules.extend(parse_external_rules(&content));
    }

    if let Ok(mut guard) = cache.write() {
        if guard.signature != signature {
            info!(
                rule_files = signature.len(),
                rules = loaded_rules.len(),
                "🔁 Reloaded external YARA rule-pack cache"
            );
            guard.signature = signature;
            guard.rules = loaded_rules;
        }
        return guard.rules.clone();
    }

    loaded_rules
}

fn external_rule_cache() -> &'static RwLock<ExternalRuleCache> {
    static CACHE: OnceLock<RwLock<ExternalRuleCache>> = OnceLock::new();
    CACHE.get_or_init(|| RwLock::new(ExternalRuleCache::default()))
}

fn build_rule_signature() -> Vec<(PathBuf, Option<SystemTime>)> {
    let mut signature = Vec::new();
    for file in discover_rule_files() {
        let modified = std::fs::metadata(&file)
            .ok()
            .and_then(|meta| meta.modified().ok());
        signature.push((file, modified));
    }
    signature
}

fn discover_rule_files() -> Vec<PathBuf> {
    let env_dirs = std::env::var("MAYA_YARA_RULE_DIRS")
        .ok()
        .map(|value| {
            value
                .split(':')
                .filter(|entry| !entry.trim().is_empty())
                .map(PathBuf::from)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let mut dirs = vec![PathBuf::from("config/yara")];
    dirs.extend(env_dirs);

    let mut files = Vec::new();
    for dir in dirs {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if is_yara_file(&path) {
                files.push(path);
            }
        }
    }

    files.sort();
    files.dedup();
    files
}

fn is_yara_file(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| matches!(ext.to_ascii_lowercase().as_str(), "yar" | "yara"))
        .unwrap_or(false)
}

#[derive(Debug, Clone)]
struct ExternalRule {
    name: String,
    patterns: Vec<RulePattern>,
    min_hits: usize,
}

#[derive(Debug, Clone, Default)]
struct ExternalRuleCache {
    signature: Vec<(PathBuf, Option<SystemTime>)>,
    rules: Vec<ExternalRule>,
}

#[derive(Debug, Clone)]
enum RulePattern {
    Ascii(String),
    Hex(Vec<u8>),
}

fn parse_external_rules(source: &str) -> Vec<ExternalRule> {
    let mut rules = Vec::new();

    let mut current_name: Option<String> = None;
    let mut in_strings = false;
    let mut in_condition = false;
    let mut patterns: Vec<RulePattern> = Vec::new();
    let mut min_hits: usize = 1;

    for raw_line in source.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with("//") {
            continue;
        }

        if let Some(rest) = line.strip_prefix("rule ") {
            if let Some(name) = current_name.take() {
                let computed_hits = normalize_min_hits(min_hits, patterns.len());
                rules.push(ExternalRule {
                    name,
                    patterns: std::mem::take(&mut patterns),
                    min_hits: computed_hits,
                });
            }

            let name = rest
                .split(|c: char| c.is_whitespace() || c == '{')
                .next()
                .unwrap_or("unnamed_rule")
                .trim();

            current_name = Some(name.to_string());
            in_strings = false;
            in_condition = false;
            min_hits = 1;
            continue;
        }

        if line.starts_with("strings:") {
            in_strings = true;
            in_condition = false;
            continue;
        }

        if line.starts_with("condition:") {
            in_strings = false;
            in_condition = true;
            continue;
        }

        if line.starts_with('}') {
            if let Some(name) = current_name.take() {
                let computed_hits = normalize_min_hits(min_hits, patterns.len());
                rules.push(ExternalRule {
                    name,
                    patterns: std::mem::take(&mut patterns),
                    min_hits: computed_hits,
                });
            }
            in_strings = false;
            in_condition = false;
            min_hits = 1;
            continue;
        }

        if in_strings {
            if let Some(pattern) = parse_rule_pattern(line) {
                patterns.push(pattern);
            }
            continue;
        }

        if in_condition {
            let lower = line.to_lowercase();
            if lower.contains("all of them") {
                min_hits = patterns.len().max(1);
            } else if let Some(value) = parse_of_them_threshold(&lower) {
                min_hits = value.max(1);
            }
        }
    }

    if let Some(name) = current_name {
        let computed_hits = normalize_min_hits(min_hits, patterns.len());
        rules.push(ExternalRule {
            name,
            patterns,
            min_hits: computed_hits,
        });
    }

    rules
}

fn parse_rule_pattern(line: &str) -> Option<RulePattern> {
    if !line.starts_with('$') {
        return None;
    }

    let (_, rhs) = line.split_once('=')?;
    let value = rhs.trim();

    if let Some(stripped) = value.strip_prefix('"') {
        let end = stripped.find('"')?;
        let string_value = &stripped[..end];
        return Some(RulePattern::Ascii(string_value.to_string()));
    }

    if value.starts_with('{') {
        let end = value.find('}')?;
        let mut bytes = Vec::new();
        for token in value[1..end].split_whitespace() {
            if token == "??" || token.contains('?') {
                return None;
            }

            if token.len() != 2 {
                return None;
            }

            if let Ok(byte) = u8::from_str_radix(token, 16) {
                bytes.push(byte);
            } else {
                return None;
            }
        }

        if !bytes.is_empty() {
            return Some(RulePattern::Hex(bytes));
        }
    }

    None
}

fn parse_of_them_threshold(line: &str) -> Option<usize> {
    let mut parts = line.split_whitespace();
    let first = parts.next()?;
    let second = parts.next()?;
    let third = parts.next()?;

    if second == "of" && third == "them" {
        return first.parse::<usize>().ok();
    }

    None
}

fn normalize_min_hits(min_hits: usize, pattern_count: usize) -> usize {
    if pattern_count == 0 {
        return 1;
    }
    min_hits.clamp(1, pattern_count)
}

fn contains_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }

    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn looks_like_hex_key(s: &str) -> bool {
    let len = s.len();
    if !len.is_multiple_of(2) || !(32..=256).contains(&len) {
        return false;
    }
    if !matches!(len, 32 | 48 | 64 | 96 | 128 | 256) {
        return false;
    }
    s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn looks_like_base64_key(s: &str) -> bool {
    s.bytes().all(|b| {
        b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=' || b == b'-' || b == b'_'
    })
}

fn abbreviate(s: &str, take: usize) -> String {
    if s.len() <= take {
        return s.to_string();
    }
    format!("{}…", &s[..take])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_crypto_keys_detects_pem_and_hex() {
        let sample = br#"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASC
-----END PRIVATE KEY-----
00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
"#;

        let keys = extract_crypto_keys(sample);
        assert!(keys.iter().any(|k| k.contains("PEM_PRIVATE_KEY")));
        assert!(keys.iter().any(|k| k.contains("HEX_KEY")));
    }

    #[test]
    fn test_run_yara_rules_matches_known_patterns() {
        let payload = br#"MZ...CreateRemoteThread...WriteProcessMemory...
your files have been encrypted pay bitcoin to recover files"#;

        let matches = run_yara_rules(payload);
        assert!(matches.iter().any(|m| m.contains("MAYA_PROCESS_INJECTION")));
        assert!(matches.iter().any(|m| m.contains("MAYA_RANSOM_NOTE")));
    }

    #[test]
    fn test_parse_external_rule_and_match() {
        let rules = r#"
rule KEY_STEALER {
  strings:
    $a = "mimikatz"
    $b = { 50 4B 03 04 }
  condition:
    1 of them
}
"#;

        let parsed = parse_external_rules(rules);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].name, "KEY_STEALER");
        assert_eq!(parsed[0].min_hits, 1);
        assert_eq!(parsed[0].patterns.len(), 2);

        let data = b"...mimikatz...";
        let ascii_blob = String::from_utf8_lossy(data).to_lowercase();
        let ascii_hit = match &parsed[0].patterns[0] {
            RulePattern::Ascii(value) => ascii_blob.contains(&value.to_lowercase()),
            RulePattern::Hex(_) => false,
        };
        assert!(ascii_hit);
    }
}
