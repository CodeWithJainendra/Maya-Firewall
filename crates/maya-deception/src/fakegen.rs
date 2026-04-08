//! Fake data generator for MAYA honey-files and AI responses.
//! Generates logically consistent, realistic honey-data (Aadhaar, PAN, Bank records).

use rand::Rng;

pub struct FakeDataGenerator;

impl FakeDataGenerator {
    pub fn new() -> Self {
        Self
    }

    /// Generates a valid-looking Aadhaar number (12 digits, doesn't start with 0/1).
    pub fn generate_aadhaar(&self) -> String {
        let mut rng = rand::rng();
        let first = rng.random_range(2..10);
        let mut aadhaar = format!("{}", first);
        for _ in 0..11 {
            aadhaar.push_str(&rng.random_range(0..10).to_string());
        }
        aadhaar
    }

    /// Generates a valid-looking PAN number (ABCPX1234Y).
    pub fn generate_pan(&self) -> String {
        let mut rng = rand::rng();
        let mut pan = String::new();
        // First 3: Random letters
        for _ in 0..3 {
            pan.push(rng.random_range(b'A'..=b'Z') as char);
        }
        // 4th: Status P for Individual, C for Company, etc.
        let status = ["P", "C", "H", "A", "B", "G", "J", "L", "F", "T"];
        pan.push_str(status[rng.random_range(0..status.len())]);
        // 5th: First char of last name (randomized here)
        pan.push(rng.random_range(b'A'..=b'Z') as char);
        // Next 4: Random digits
        for _ in 0..4 {
            pan.push_str(&rng.random_range(0..10).to_string());
        }
        // Last: Random letter
        pan.push(rng.random_range(b'A'..=b'Z') as char);
        pan
    }

    /// Generates a realistic Indian name.
    pub fn generate_name(&self) -> String {
        let first_names = [
            "Aravind",
            "Deepika",
            "Rohan",
            "Siddharth",
            "Ananya",
            "Ishaan",
            "Kavya",
            "Madhav",
            "Nisha",
            "Pranav",
            "Riya",
            "Sahil",
            "Tanvi",
            "Varun",
            "Zoya",
        ];
        let last_names = [
            "Sharma",
            "Verma",
            "Gupta",
            "Malhotra",
            "Reddy",
            "Iyer",
            "Nair",
            "Patel",
            "Singh",
            "Joshi",
            "Kulkarni",
            "Chaudhary",
            "Das",
            "Banerjee",
            "Khan",
        ];

        let mut rng = rand::rng();
        format!(
            "{} {}",
            first_names[rng.random_range(0..first_names.len())],
            last_names[rng.random_range(0..last_names.len())]
        )
    }

    /// Generates a fake bank transaction record.
    pub fn generate_bank_record(&self) -> String {
        let mut rng = rand::rng();
        let name = self.generate_name();
        let pan = self.generate_pan();
        let account = format!("{:012}", rng.random_range(100000000000u64..999999999999u64));
        let amount = rng.random_range(500.0..500000.0);
        let date = chrono::Utc::now() - chrono::Duration::hours(rng.random_range(1..720));

        format!(
            "ID: TXN{:08} | Date: {} | From: {} (Acct: {}) | PAN: {} | Amount: ₹{:.2} | Status: COMPLETED",
            rng.random_range(1..99999999),
            date.format("%Y-%m-%d %H:%M:%S"),
            name,
            account,
            pan,
            amount
        )
    }

    /// Generates a realistic hospital patient record (AIIMS style).
    pub fn generate_patient_record(&self) -> String {
        let mut rng = rand::rng();
        let name = self.generate_name();
        let aadhaar = self.generate_aadhaar();
        let uhid = format!("UHID-{:08}", rng.random_range(1..99999999));
        let blood_groups = ["A+", "A-", "B+", "B-", "O+", "O-", "AB+", "AB-"];
        let vitals = format!(
            "BP: {}/{} mmHg | HR: {} bpm | Temp: {:.1} F",
            rng.random_range(110..140),
            rng.random_range(70..90),
            rng.random_range(60..100),
            rng.random_range(97.0..102.0)
        );

        format!(
            "--- PATIENT DISCHARGE SUMMARY ---\n\
             Name: {}\n\
             UHID: {}\n\
             Aadhaar: {}\n\
             Blood Group: {}\n\
             Vitals: {}\n\
             Diagnosis: Stage {} Hypertension / Diabetic Ketoacidosis\n\
             Prescription: Metformin 500mg, Telmisartan 40mg\n\
             --------------------------------",
            name,
            uhid,
            aadhaar,
            blood_groups[rng.random_range(0..blood_groups.len())],
            vitals,
            rng.random_range(1..3)
        )
    }

    /// Generates a realistic proprietary source code snippet (Honey-Code).
    pub fn generate_source_code(&self, language: &str) -> String {
        match language {
            "rust" => r#"// Private Corporate Transaction Engine v4.2
use crate::crypto::{Kyber768, Aes256Gcm};
use std::sync::Arc;

pub struct CoreVault {
    secret_key: [u8; 32],
    shard_id: String,
}

impl CoreVault {
    /// Internal: Signs a transaction using the hardware-backed key.
    /// DO NOT EXPOSE TO PUBLIC API
    pub fn sign_transaction(&self, tx_info: &TransactionData) -> Result<Signature> {
        let auth_token = std::env::var("CORE_SECRET_AUTH").unwrap();
        // ... internal logic ...
    }
}
"#
            .into(),
            "cpp" => r#"// SCADA Power Grid Control Module
#include <modbus.h>
#include <grid_types.h>

void adjust_voltage_parameters(float current_load) {
    // SECURITY_SENSITIVE: Physical override logic
    if (current_load > CRITICAL_THRESHOLD) {
        set_relay_state(RELAY_PRIMARY, STATE_TRIP);
        log_event("Grid Emergency Trip - Auto-engaged");
    }
}
"#
            .into(),
            _ => "// Confidential Information".into(),
        }
    }

    /// Creates a fake git structure in memory strings.
    pub fn generate_git_history(&self) -> String {
        "commit d09a12c823f4b5e67a8b9c0d1e2f3a4b5c6d7e8f\n\
         Author: Siddharth <sid@corp.local>\n\
         Date:   Wed Mar 25 14:02:11 2026 +0530\n\
         \n\
             Update core banking vault encryption keys (temp)\n\
         \n\
         commit 4e8f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f\n\
         Author: Ananya <ananya@corp.local>\n\
         Date:   Tue Mar 24 10:15:22 2026 +0530\n\
         \n\
             Add Modbus TCP support for Siemens PLCs\n"
            .to_string()
    }
}

impl Default for FakeDataGenerator {
    fn default() -> Self {
        Self::new()
    }
}
