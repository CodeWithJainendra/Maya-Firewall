# 🕸️ Project MAYA — Active Deception Grid

> **"Westworld" for Cyber-Attackers**  
> AI-powered Dynamic Deception Engine  
> CDIS, IIT Kanpur

```
 ███╗   ███╗ █████╗ ██╗   ██╗ █████╗ 
 ████╗ ████║██╔══██╗╚██╗ ██╔╝██╔══██╗
 ██╔████╔██║███████║ ╚████╔╝ ███████║
 ██║╚██╔╝██║██╔══██║  ╚██╔╝  ██╔══██║
 ██║ ╚═╝ ██║██║  ██║   ██║   ██║  ██║
 ╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝
```

## 🔥 What is MAYA?

MAYA is an **AI-powered Active Deception Grid** that doesn't just defend against hackers — it **traps them in a digital illusion**. When an attacker breaches your network, MAYA creates a dynamically generated fake environment (the "Maya"/Illusion) that evolves with every attacker action.

```
Attacker scans network → MAYA spawns 500 fake servers (milliseconds)
Attacker exploits a "vulnerable" server → MAYA lets them in (to a fake environment)
Attacker runs commands → AI generates hyper-realistic output
Attacker drops malware → MAYA silently extracts C2 servers, keys, signatures
Attacker attempts exfiltration → MAYA feeds fake data while alerting SOC
```

**You're not building a firewall. You're building The Matrix.**

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        PROJECT MAYA                             │
├──────────┬──────────┬──────────┬──────────┬──────────┬─────────┤
│ Network  │ Deception│ AI Brain │ Sandbox  │ Crypto   │ Consens.│
│ Engine   │ Engine   │ (LLM)   │ (WASM)   │ (PQ)     │ HotStuff│
│ (eBPF)   │ (gVisor) │          │          │ (Kyber)  │ (BFT)   │
├──────────┼──────────┼──────────┼──────────┼──────────┼─────────┤
│ Profiler │ Dashboard│ CLI      │          │          │         │
│ (APT)    │ (SOC)    │          │          │          │         │
└──────────┴──────────┴──────────┴──────────┴──────────┴─────────┘
```

## 🧠 GOD-TIER Technology Stack

| Component | Technology | Why |
|-----------|-----------|-----|
| **Core Language** | Rust 2024 Edition | Memory safety, zero-cost abstractions, no GC pauses |
| **Network Engine** | Linux XDP/eBPF | Kernel-level packet processing (microsecond latency) |
| **Virtualization** | gVisor + Kata Containers | Hardware-level isolation, root-inside-container safe |
| **Sandboxing** | WebAssembly (Wasmtime) | Sandboxed execution without full VM overhead |
| **Cryptography** | X25519 + Ed25519 + Kyber768 (PQ-ready) | Post-Quantum hybrid, future-proof |
| **Consensus** | HotStuff BFT | High-throughput consensus for distributed decoys |
| **Formal Verification** | TLA+ | Mathematical proof of consensus safety |
| **AI** | Llama-3 via Ollama | Real-time hyper-realistic system state generation |

## 🚀 Quick Start

```bash
# Build MAYA
cargo build --release

# Generate default config
./target/release/maya init

# Generate development config (unsafe for production)
./target/release/maya init --dev

# Validate config (production safety checks)
./target/release/maya validate-config

# Validate config in dev mode (syntax/parse only)
./target/release/maya validate-config --dev

# Start the grid (development mode)
./target/release/maya start --dev

# Interactive Ghost Shell (test the fake terminal)
./target/release/maya ghost-shell --hostname srv-001.corp.local

# Generate cryptographic keys
./target/release/maya gen-keys --node-id maya-node-001

# Analyze a malware sample
./target/release/maya analyze --file suspicious.bin

# Start SOC Dashboard
./target/release/maya dashboard --port 8900

# Start Taipy SOC view (standardized env launcher)
./scripts/run-taipy-dashboard.sh
```

### Taipy deployment environment standard

Use these env variables across local/dev/prod for the Taipy UI:

- `MAYA_TAIPY_API_BASE` (default `http://127.0.0.1:8900`)
- `MAYA_TAIPY_DASHBOARD_TOKEN` (optional dashboard token)
- `MAYA_TAIPY_REQUEST_TIMEOUT_SECS` (default `2.0`)
- `MAYA_TAIPY_HOST` (default `127.0.0.1`)
- `MAYA_TAIPY_PORT` (default `5000`)
- `MAYA_TAIPY_DARK_MODE` (default `true`)
- `MAYA_TAIPY_RELOADER` (default `true`)

Backward-compatible aliases are still accepted: `MAYA_API_BASE`, `MAYA_DASHBOARD_TOKEN`.

## 📁 Project Structure

```
Maya/
├── Cargo.toml                  # Workspace root
├── config/maya.toml            # Default configuration
├── tla/MayaConsensus.tla       # TLA+ formal verification
├── crates/
│   ├── maya-core/              # Core types, config, events, utilities
│   ├── maya-network/           # XDP/eBPF network engine
│   ├── maya-deception/         # Dynamic deception orchestrator
│   ├── maya-ai/                # LLM-powered generative deception
│   ├── maya-sandbox/           # WASM malware analysis sandbox
│   ├── maya-crypto/            # Post-quantum cryptography
│   ├── maya-consensus/         # HotStuff BFT consensus
│   ├── maya-profiler/          # Adversary behavior profiling
│   ├── maya-dashboard/         # SOC Dashboard API
│   └── maya-cli/               # CLI entry point
```

## 🎯 Key Features

### 1. Ghost Shell (AI-Powered Fake Terminal)
- 25+ Linux commands with hyper-realistic output
- `cat /etc/passwd` → realistic users
- `cat /var/log/auth.log` → AI-generated consistent logs
- SQL injection → fake but mathematically consistent data (Aadhaar passes Verhoeff checksum)

### 2. Network Deception Engine
- Zero-copy packet parsing
- TCP flag-based scan type detection (SYN, FIN, XMAS, NULL)
- APT-aware threat classification (slow+stealthy = high threat)
- Automatic decoy spawning on scan detection

### 3. Adversary Profiler
- Keystroke dynamics analysis
- MITRE ATT&CK TTP mapping
- APT group attribution (APT41, SideWinder, Lazarus, Fancy Bear)
- Evidence chain for CERT-In reporting

### 4. Malware Sandbox
- Static analysis (strings, entropy, magic bytes)
- C2 server extraction
- File type detection (ELF, PE, ZIP, GZIP)
- Capability detection (keylogger, ransomware, credential stealer)
- External rule-pack loading from `config/yara/*.yar|*.yara` (hot-tunable signatures)

#### Custom Rule Packs
- Drop custom YARA-like rules in `config/yara/` (example: `config/yara/starter_rules.yar`)
- Override rule directories with `MAYA_YARA_RULE_DIRS` (colon-separated paths)
- Rule-pack cache auto-refreshes on file mtime changes (no MAYA restart needed)

### 5. Post-Quantum Cryptography
- Ed25519 signatures + X25519 key exchange (classical)
- Kyber768 KEM ready (hybrid PQ mode)
- AES-256-GCM for inter-node encryption
- Automatic key rotation

### 6. HotStuff BFT Consensus
- Distributed decoy coordination
- Byzantine fault tolerance (tolerates f faults with 3f+1 nodes)
- TLA+ formally verified for safety

## 📊 Monetization

| Client | Use Case | Pricing |
|--------|----------|---------|
| Hospitals (AIIMS, Apollo) | Ransomware → patient data protection | ₹50L-1Cr/yr |
| Banks (HDFC, SBI) | Core banking → fake ledger traps | ₹1Cr-5Cr/yr |
| Defense (DRDO/ISRO) | Classified network threat intel | ₹5Cr-20Cr |
| CERT-In / NTRO | National deception grid | Govt contracts |
| Power Grids (SCADA) | ICS/OT protection | Multi-million |

## 📜 License

MIT License — CDIS, IIT Kanpur
