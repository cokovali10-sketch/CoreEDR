# CoreEDR

**Production-grade Endpoint Detection and Response (EDR) / Antivirus Engine**

A lightweight, high-performance EDR solution written in Rust with real-time process monitoring, heuristic analysis, YARA rule integration, ML-based threat classification, MITRE ATT&CK mapping, event correlation, and automated threat containment.

## Features

### Core Detection
- **Real-time Process Monitoring** — Native OS API integration with process chain tracking and tree visualization
- **Heuristic Analysis** — 6-vector risk scoring with composite severity assessment
- **Rule Engine** — JSON-defined custom rules with blacklist/whitelist support
- **Signature Detection** — YARA rule compilation and scanning

### Advanced Detection
- **Behavioral Analysis** — Multi-signal event correlation (process chains, file + network combos)
- **ML Classification** — Lightweight logistic regression model for threat scoring
- **Network Monitoring** — Connection tracking, suspicious port detection, C2 beacon detection
- **File System Monitoring** — Real-time file change detection with platform-native watchers

### Threat Intelligence
- **MITRE ATT&CK Mapping** — Automatic mapping of detections to ATT&CK techniques (40+ techniques)
- **Event Correlation Engine** — Links events across sources to build attack chains
- **Process Chain Analysis** — Visual process tree tracking with parent-child relationships
- **Kill Chain Reconstruction** — Automated attack timeline generation

### Response & Containment
- **Automated Kill** — Terminate malicious processes via native APIs
- **Encrypted Quarantine** — AES-256-GCM encryption with Argon2id key derivation
- **Alert Management** — Deduplication, cooldown, acknowledgment, severity filtering
- **Tamper Protection** — Self-integrity checks, anti-kill, watchdog, elevation detection

### Management
- **REST API** — Full HTTP API for management, queries, and control (Axum)
- **Web UI Dashboard** — Real-time monitoring dashboard with WebSocket updates
- **CLI Interface** — `clap`-based CLI with daemon, scan, status, quarantine commands
- **Auto-Update** — Automatic rule and model updates from remote sources

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        CoreEDR Engine                            │
├──────────┬──────────┬──────────┬──────────┬─────────────────────┤
│ Process  │  File    │ Network  │  YARA    │   Behavioral        │
│ Monitor  │ Monitor  │ Monitor  │ Scanner  │   Analyzer          │
│ (chains) │          │          │          │                     │
├──────────┴──────────┴──────────┴──────────┴─────────────────────┤
│              Heuristic Engine + Rule Engine                      │
├─────────────────────────────────────────────────────────────────┤
│            ML Threat Classifier (Logistic Reg)                  │
├─────────────────────────────────────────────────────────────────┤
│         MITRE ATT&CK Mapper (40+ techniques, 12 tactics)       │
├─────────────────────────────────────────────────────────────────┤
│         Event Correlation Engine (attack chains, timelines)     │
├─────────────────────────────────────────────────────────────────┤
│         Containment Engine + Alert Manager                       │
├─────────────────────────────────────────────────────────────────┤
│    Encrypted Quarantine (AES-256-GCM) + Logger                  │
├─────────────────────────────────────────────────────────────────┤
│         Tamper Guard + Integrity Checker                         │
├─────────────────────────────────────────────────────────────────┤
│     REST API (Axum) + Web UI + WebSocket                         │
└─────────────────────────────────────────────────────────────────┘
```

## Installation

### Prerequisites
- Rust 1.70+ (install via [rustup](https://rustup.rs/))

### Build

```bash
# Full build with all features
cargo build --release

# Minimal build (core features only)
cargo build --release --no-default-features

# Build with specific features
cargo build --release --features "api,yara,ml"
```

### Install

```bash
cargo install --path .
```

## Usage

### CLI Commands

```bash
# Run in daemon mode (continuous monitoring)
coreedr daemon

# Run a single scan
coreedr scan

# Show current status
coreedr status

# Generate default configuration
coreedr config > config.json

# List quarantined items
coreedr quarantine

# Start REST API server with Web UI
coreedr server --port 8080
```

### Configuration

```bash
# Generate default config
coreedr config > config.json

# Edit config
vim config.json

# Run with custom config
coreedr daemon --config /path/to/config.json
```

### REST API

```bash
# Health check
curl http://localhost:8080/api/health

# System status
curl http://localhost:8080/api/system/status

# Start a scan
curl -X POST http://localhost:8080/api/scan

# List quarantine entries
curl http://localhost:8080/api/quarantine

# List alerts
curl http://localhost:8080/api/alerts

# MITRE ATT&CK overview
curl http://localhost:8080/api/mitre/overview

# Map event to ATT&CK technique
curl -X POST http://localhost:8080/api/mitre/map \
  -H "Content-Type: application/json" \
  -d '{"event_type":"process_creation","details":{"CommandLine":"powershell -encodedcommand"}}'

# Event correlation overview
curl http://localhost:8080/api/correlation/overview

# Add correlated event
curl -X POST http://localhost:8080/api/correlation/events \
  -H "Content-Type: application/json" \
  -d '{"event_type":"process_creation","process_name":"malware.exe"}'
```

### Web UI

Open `http://localhost:8080` in your browser after starting the server.

## Feature Flags

| Feature | Description | Default |
|---------|-------------|---------|
| `api` | REST API server (Axum) | ✓ |
| `yara` | YARA rule integration | ✓ |
| `ml` | ML threat classification | ✓ |
| `quarantine-encrypt` | AES-256-GCM quarantine encryption | ✓ |
| `file-monitoring` | Real-time file system monitoring | ✓ |
| `network-monitoring` | Network connection monitoring | ✓ |
| `behavioral-analysis` | Behavioral analysis engine | ✓ |
| `config-watch` | Configuration hot-reload | ✓ |
| `auto-update` | Automatic rule/model updates | ✓ |
| `web-ui` | Embedded web dashboard | ✓ |
| `service` | Windows Service integration | ✓ |

## Platform Support

| Platform | Process Monitoring | Service Mode | File Monitoring | Network Monitoring |
|----------|-------------------|--------------|-----------------|-------------------|
| Windows  | Native APIs | Windows Service | ReadDirectoryChangesW | GetExtendedTcpTable |
| Linux    | /proc filesystem | systemd | inotify | /proc/net/* |
| macOS    | /proc + sysctl | launchd | FSEvents | sysctl |

## Testing

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture

# Run specific test
cargo test test_scanner_creation

# Run integration tests
cargo test --test integration
```

## Project Structure

```
CoreEDR/
├── src/
│   ├── main.rs              # CLI entry point
│   ├── lib.rs               # Module declarations
│   ├── error.rs             # Centralized error types
│   ├── logging.rs           # Tracing-based logging
│   ├── config.rs            # Configuration management
│   ├── scanner.rs           # Central scan orchestrator
│   ├── process_monitor.rs   # OS process enumeration + chain tracking
│   ├── heuristic_engine.rs  # Anomaly detection
│   ├── rule_engine.rs       # Signature-based detection
│   ├── hash_engine.rs       # SHA-256 hashing + entropy
│   ├── alert.rs             # Alert management
│   ├── containment.rs       # Threat response
│   ├── quarantine/          # Encrypted quarantine
│   │   ├── mod.rs
│   │   ├── encryption.rs    # AES-256-GCM
│   │   ├── store.rs         # JSON index
│   │   ├── restore.rs       # File restoration
│   │   └── cleanup.rs       # Retention cleanup
│   ├── logger.rs            # Security event logging
│   ├── platform/            # Native OS APIs
│   │   ├── windows/
│   │   ├── linux/
│   │   └── macos/
│   ├── monitoring/          # File system monitoring
│   ├── network/             # Network monitoring
│   ├── yara/                # YARA integration
│   ├── behavioral/          # Behavioral analysis
│   ├── ml/                  # ML classification
│   ├── tamper/              # Tamper protection
│   ├── mitre/               # MITRE ATT&CK mapping
│   │   ├── mod.rs
│   │   ├── techniques.rs    # 40+ ATT&CK techniques
│   │   ├── mapper.rs        # Event→technique mapper
│   │   └── matrix.rs        # Dashboard matrix data
│   ├── correlation/         # Event correlation engine
│   │   ├── mod.rs
│   │   ├── engine.rs        # Core correlation logic
│   │   ├── chain.rs         # Attack chain builder
│   │   └── timeline.rs      # Event timeline visualization
│   ├── api/                 # REST API
│   │   ├── routes/
│   │   │   ├── health.rs
│   │   │   ├── scan.rs
│   │   │   ├── quarantine.rs
│   │   │   ├── alerts.rs
│   │   │   ├── config.rs
│   │   │   ├── system.rs
│   │   │   ├── rules.rs
│   │   │   ├── mitre.rs
│   │   │   └── correlation.rs
│   │   └── middleware/
│   └── updater/             # Auto-update
├── rules/
│   ├── default.json         # Default detection rules
│   └── mitre_rules.json     # MITRE ATT&CK detection rules
├── ui/                      # Web dashboard
│   ├── index.html
│   ├── css/
│   └── js/
├── tests/                   # Integration tests
├── docs/                    # Documentation
├── Cargo.toml
└── README.md
```

## License

MIT License - Hermes Studio

## Benchmarks

Benchmarks are implemented with [Criterion](https://github.com/bheisler/criterion.rs) in enches/detection_benchmarks.rs.

Run:

`
cargo bench
`

Latest results (Windows, release, single-threaded):

| Benchmark | Time |
|-----------|------|
| heuristic_engine/analyze_single_process | ~2-5 us |
| mitre_mapper/map_event | ~1-3 us |
| correlation_engine/add_event | ~1-2 us |
| yara_scanner/scan_bytes | ~5-20 us |

Results vary by hardware and rule set. Run cargo bench to reproduce.
## Problem

Endpoint detection tools are often either too heavy (enterprise EDR with kernel drivers) or too shallow (signature-only AV). CoreEDR targets the middle ground: a lightweight, user-mode Rust engine combining heuristic analysis, YARA, ML scoring, MITRE ATT&CK mapping, and event correlation — without kernel dependencies.

## Architecture

- **Process monitor** (platform-specific: ToolHelp on Windows, /proc on Linux, ps on macOS) enumerates processes and builds process trees.
- **Heuristic engine** applies 6 detection vectors (suspicious name, memory anomaly, CPU anomaly, process chain, command line, hidden process) and produces a risk score + severity.
- **Rule engine** evaluates JSON-defined rules and blacklists/whitelists.
- **YARA scanner** compiles and runs YARA rules over bytes/files/process memory.
- **ML classifier** (logistic regression) scores feature vectors.
- **MITRE mapper** maps detections to ATT&CK techniques.
- **Correlation engine** links events into attack chains with incidents.
- **Containment** kills/quarantines/alerts based on recommended action.
- **Alert manager** deduplicates with cooldown.
- **REST API / WebSocket** (optional feature) for management.

## Trade-offs

- User-mode only: no kernel-level visibility, but portable and safe to deploy.
- Heuristic + ML are lightweight (no deep learning); lower accuracy than heavy models but runs on any host.
- Optional features gated behind Cargo features to keep the core small.
- Windows process enumeration uses ToolHelp (no wmic dependency) for compatibility.

## Benchmarks

Run `cargo bench`. See `benches/detection_benchmarks.rs`.

## Limitations

- No kernel driver: cannot detect kernel-level rootkits or hook syscalls.
- ML model is a simple logistic regression; not trained on large datasets in-tree.
- Behavioral analysis is rule-based, not ML-driven.
- API module (`api` feature) is currently not compiling (planned for next release).
- YARA process-memory scanning reads only up to 4 KB per region.
