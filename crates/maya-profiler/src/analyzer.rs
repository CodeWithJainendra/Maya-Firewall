//! Adversary Behavior Analyzer.
//! Tracks keystroke dynamics, command patterns, and maps to MITRE ATT&CK TTPs.

use chrono::Utc;
use dashmap::DashMap;
use maya_core::types::*;
use serde::{Deserialize, Serialize};
use tracing::info;

/// Known APT group behavioral signatures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AptSignature {
    pub group_name: String,
    pub origin_country: String,
    pub typical_tools: Vec<String>,
    pub typical_commands: Vec<String>,
    pub avg_keystroke_interval: (f64, f64), // min, max range
    pub active_hours_utc: Vec<u8>,
    pub language_indicators: Vec<String>,
}

/// The main behavior analyzer.
pub struct BehaviorAnalyzer {
    /// APT signature database
    apt_signatures: Vec<AptSignature>,
    /// Per-session keystroke data
    keystroke_data: DashMap<SessionId, Vec<KeystrokeEvent>>,
    /// Per-session command sequences
    command_sequences: DashMap<SessionId, Vec<String>>,
    /// Attribution threshold
    threshold: f64,
}

/// A single keystroke event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeystrokeEvent {
    pub timestamp_ms: u64,
    pub inter_key_delay_ms: Option<u64>,
    pub key_hold_ms: u64,
}

/// Attribution result with detailed evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributionResult {
    pub group_name: String,
    pub confidence: f64,
    pub evidence: Vec<String>,
    pub matching_ttps: Vec<String>,
    pub suspected_origin: String,
}

impl BehaviorAnalyzer {
    pub fn new(threshold: f64) -> Self {
        let apt_signatures = vec![
            AptSignature {
                group_name: "APT41 (Winnti)".into(),
                origin_country: "China".into(),
                typical_tools: vec![
                    "cobalt_strike".into(),
                    "mimikatz".into(),
                    "shadow_pad".into(),
                ],
                typical_commands: vec![
                    "whoami".into(),
                    "net user".into(),
                    "tasklist".into(),
                    "systeminfo".into(),
                ],
                avg_keystroke_interval: (80.0, 150.0),
                active_hours_utc: vec![0, 1, 2, 3, 4, 5, 6, 7, 8], // UTC 0-8 = CST 8-16
                language_indicators: vec!["zh".into(), "gbk".into()],
            },
            AptSignature {
                group_name: "SideWinder".into(),
                origin_country: "India (suspected)".into(),
                typical_tools: vec!["custom_rat".into(), "hta_downloader".into()],
                typical_commands: vec!["dir".into(), "type".into(), "ipconfig".into()],
                avg_keystroke_interval: (100.0, 200.0),
                active_hours_utc: vec![3, 4, 5, 6, 7, 8, 9, 10, 11], // IST business hours
                language_indicators: vec!["hi".into(), "en-IN".into()],
            },
            AptSignature {
                group_name: "Lazarus Group".into(),
                origin_country: "North Korea".into(),
                typical_tools: vec![
                    "hidden_cobra".into(),
                    "hoplight".into(),
                    "electric_fish".into(),
                ],
                typical_commands: vec!["reg query".into(), "sc query".into(), "netsh".into()],
                avg_keystroke_interval: (120.0, 250.0),
                active_hours_utc: vec![0, 1, 2, 3, 4, 5, 6, 7], // KST 9-16
                language_indicators: vec!["ko".into(), "euc-kr".into()],
            },
            AptSignature {
                group_name: "APT28 (Fancy Bear)".into(),
                origin_country: "Russia".into(),
                typical_tools: vec!["x_agent".into(), "x_tunnel".into(), "gamefish".into()],
                typical_commands: vec!["certutil".into(), "wmic".into(), "powershell".into()],
                avg_keystroke_interval: (90.0, 180.0),
                active_hours_utc: vec![5, 6, 7, 8, 9, 10, 11, 12, 13], // MSK business hours
                language_indicators: vec!["ru".into(), "koi8-r".into()],
            },
        ];

        info!(
            signatures = apt_signatures.len(),
            threshold, "🔍 Behavior Analyzer initialized with APT signature database"
        );

        Self {
            apt_signatures,
            keystroke_data: DashMap::new(),
            command_sequences: DashMap::new(),
            threshold,
        }
    }

    /// Record a keystroke event for a session.
    pub fn record_keystroke(&self, session_id: &SessionId, event: KeystrokeEvent) {
        self.keystroke_data
            .entry(session_id.clone())
            .or_default()
            .push(event);
    }

    /// Record a command execution.
    pub fn record_command(&self, session_id: &SessionId, command: String) {
        self.command_sequences
            .entry(session_id.clone())
            .or_default()
            .push(command);
    }

    /// Attempt attribution based on collected behavioral data.
    pub fn attempt_attribution(&self, session_id: &SessionId) -> Option<AttributionResult> {
        let commands = self.command_sequences.get(session_id)?;
        let keystrokes = self.keystroke_data.get(session_id);

        let mut best_match: Option<AttributionResult> = None;
        let mut best_score = 0.0f64;

        for sig in &self.apt_signatures {
            let mut score = 0.0;
            let mut evidence = Vec::new();
            let mut matching_ttps = Vec::new();

            // Command pattern matching (40% weight).
            //
            // Score on the number of *distinct signature commands* observed, not
            // the raw number of attacker commands that matched. Counting raw
            // matches let an attacker repeat a single command (e.g. `whoami`)
            // to drive `cmd_score` above 1.0, which inflated the final
            // confidence past 100% (and produced nonsensical "N of M" evidence).
            let matched_commands: Vec<&String> = sig
                .typical_commands
                .iter()
                .filter(|tc| commands.iter().any(|cmd| cmd.contains(tc.as_str())))
                .collect();
            if !matched_commands.is_empty() {
                let cmd_score =
                    matched_commands.len() as f64 / sig.typical_commands.len().max(1) as f64;
                score += cmd_score * 0.4;
                evidence.push(format!(
                    "Command pattern match: {} of {} commands",
                    matched_commands.len(),
                    sig.typical_commands.len()
                ));
                for m in &matched_commands {
                    matching_ttps.push(format!("T1059: Command-Line Interface ({})", m));
                }
            }

            // Tool signature matching (30% weight)
            let tool_matches: Vec<_> = commands
                .iter()
                .filter(|cmd| sig.typical_tools.iter().any(|t| cmd.contains(t.as_str())))
                .collect();
            if !tool_matches.is_empty() {
                score += 0.3;
                evidence.push(format!("Tool signature match: {:?}", sig.typical_tools));
            }

            // Keystroke dynamics (20% weight)
            if let Some(ref ks) = keystrokes
                && ks.len() > 5
            {
                // Average only over keystrokes that actually carry an
                // inter-key delay. Dividing the sum of present delays by the
                // total keystroke count (which always includes at least the
                // first keystroke, whose delay is `None`) systematically
                // under-reported the rhythm and skewed the match.
                let delays: Vec<f64> = ks
                    .iter()
                    .filter_map(|k| k.inter_key_delay_ms)
                    .map(|d| d as f64)
                    .collect();
                let avg_delay = if delays.is_empty() {
                    0.0
                } else {
                    delays.iter().sum::<f64>() / delays.len() as f64
                };

                if !delays.is_empty()
                    && avg_delay >= sig.avg_keystroke_interval.0
                    && avg_delay <= sig.avg_keystroke_interval.1
                {
                    score += 0.2;
                    evidence.push(format!(
                        "Keystroke rhythm match: avg {}ms (range {}-{}ms)",
                        avg_delay as u64,
                        sig.avg_keystroke_interval.0 as u64,
                        sig.avg_keystroke_interval.1 as u64
                    ));
                }
            }

            // Activity hours (10% weight)
            let current_hour = Utc::now().hour() as u8;
            if sig.active_hours_utc.contains(&current_hour) {
                score += 0.1;
                evidence.push(format!(
                    "Active during {} timezone working hours",
                    sig.origin_country
                ));
            }

            if score > best_score {
                best_score = score;
                best_match = Some(AttributionResult {
                    group_name: sig.group_name.clone(),
                    confidence: score,
                    evidence,
                    matching_ttps,
                    suspected_origin: sig.origin_country.clone(),
                });
            }
        }

        if best_score >= self.threshold {
            if let Some(ref attr) = best_match {
                info!(
                    group = %attr.group_name,
                    confidence = %format!("{:.1}%", attr.confidence * 100.0),
                    origin = %attr.suspected_origin,
                    "🎯 APT ATTRIBUTION"
                );
            }
            best_match
        } else {
            None
        }
    }
}

use chrono::Timelike;

#[cfg(test)]
mod tests {
    use super::*;

    fn ks(delay: Option<u64>) -> KeystrokeEvent {
        KeystrokeEvent {
            timestamp_ms: 0,
            inter_key_delay_ms: delay,
            key_hold_ms: 10,
        }
    }

    #[test]
    fn confidence_never_exceeds_one_when_command_repeated() {
        // Regression: repeating a single matching command must not push the
        // confidence above 1.0 (100%). Threshold set low so attribution fires.
        let analyzer = BehaviorAnalyzer::new(0.1);
        let session = SessionId::new();

        // APT41 has 4 typical commands; run just one of them 100 times.
        for _ in 0..100 {
            analyzer.record_command(&session, "whoami".to_string());
        }

        let result = analyzer
            .attempt_attribution(&session)
            .expect("attribution should fire above threshold");

        assert!(
            result.confidence <= 1.0,
            "confidence must be <= 1.0 (100%), got {}",
            result.confidence
        );
        // 1 of 4 signature commands matched => command weight 0.25 * 0.4 = 0.1.
        assert!(result.confidence >= 0.1);
    }

    #[test]
    fn keystroke_average_uses_only_present_delays() {
        // Regression: the average must be taken over keystrokes that carry a
        // delay, not over the total keystroke count. Here 5 keystrokes have no
        // delay and 5 have a 100ms delay -> present-average is 100ms (inside
        // APT41's 80-150ms band). The old code divided by 10 -> 50ms, which is
        // outside the band, so the rhythm match was wrongly dropped.
        let analyzer = BehaviorAnalyzer::new(0.1);
        let session = SessionId::new();

        // Match all four APT41 commands so it is unambiguously the best match.
        for cmd in ["whoami", "net user", "tasklist", "systeminfo"] {
            analyzer.record_command(&session, cmd.to_string());
        }
        for _ in 0..5 {
            analyzer.record_keystroke(&session, ks(None));
        }
        for _ in 0..5 {
            analyzer.record_keystroke(&session, ks(Some(100)));
        }

        let result = analyzer
            .attempt_attribution(&session)
            .expect("attribution should fire");

        assert!(result.group_name.contains("APT41"));
        assert!(
            result
                .evidence
                .iter()
                .any(|e| e.contains("Keystroke rhythm match")),
            "expected keystroke rhythm match in evidence, got {:?}",
            result.evidence
        );
        assert!(result.confidence <= 1.0);
    }
}
