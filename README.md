# CoreEDR

Lightweight Endpoint Detection and Response (EDR) / Antivirus engine written in Rust.

**Version:** 0.1.0 | **Language:** Rust | **License:** MIT

## Features

### Real-Time Process Monitoring
- Continuous scanning of running processes
- Process chain analysis (parent-child relationships)
- Memory and CPU usage anomaly detection
- New/terminated/modified process tracking

### Heuristic Analysis Engine
- **Name-based detection** — matches against known malware names
- **Memory anomaly detection** — detects unusual memory consumption
- **CPU spike detection** — identifies resource-intensive suspicious processes
- **Command-line analysis** — detects suspicious command patterns (PowerShell encoded, certutil, etc.)
- **Hidden process detection** — identifies process hollowing attempts
- **Entropy analysis** — flags high-entropy (packed/encrypted) executables

### Signature-Based Detection
- Blacklist/whitelist by hash (SHA-256)
- Blacklist/whitelist by process name
- Custom rule engine with JSON-defined rules
- Pattern matching with regex support

### Threat Containment
- **Auto-kill** — terminates malicious processes (SIGKILL/TaskKill)
- **Quarantine** — isolates suspicious processes with full audit trail
- **Alerting** — generates alerts for medium/high/critical threats
- **Cooldown** — prevents duplicate actions on the same process

### Logging & Alerts
- Structured JSON logging with timestamps
- Severity levels: DEBUG, INFO, WARNING, ERROR, CRITICAL
- Event categories: PROCESS, FILE, NETWORK, HEURISTIC, SIGNATURE, CONTAINMENT
- Alert deduplication and cooldown
- Alert acknowledgment system

### Rule Engine
- JSON-based custom rules
- Built-in rules for common attack patterns
- Rule conditions: NameContains, HashEquals, CommandLineContains, MemoryAbove, Combined
- Enable/disable rules dynamically

## Build & Run

```bash
# Build release
cargo build --release

# Run single scan
./target/release/coreedr scan

# Run daemon (continuous monitoring)
./target/release/coreedr daemon

# Generate default config
./target/release/coreedr config > config.json

# View quarantined items
./target/release/coreedr quarantine
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `daemon` | Start continuous monitoring |
| `scan` | Run single scan |
| `status` | Show current status |
| `config` | Generate default configuration |
| `quarantine` | List quarantined items |
| `help` | Show help |

## Configuration

Edit `config.json` to customize:

```json
{
  "general": {
    "scan_interval_ms": 5000,
    "quarantine_path": "./quarantine"
  },
  "detection": {
    "enable_heuristic": true,
    "enable_signature": true,
    "entropy_threshold": 7.5
  },
  "response": {
    "auto_kill_malicious": true,
    "auto_quarantine": true,
    "cooldown_seconds": 30
  }
}
```

## Detection Rules

### Built-in Rules
| Rule | Severity | Description |
|------|----------|-------------|
| `mimikatz_detected` | Critical | Mimikatz credential dumping tool |
| `suspicious_encoded_ps` | High | PowerShell with encoded command |
| `high_entropy_process` | High | Process with >100MB memory |

### Custom Rules

Create a JSON file with rules:

```json
[
  {
    "name": "my_custom_rule",
    "description": "Detects suspicious activity",
    "severity": "High",
    "condition": {
      "Combined": [
        {"CommandLineContains": "powershell"},
        {"CommandLineContains": "-enc"}
      ]
    },
    "enabled": true
  }
]
```

## Project Structure

```
CoreEDR/
├── src/
│   ├── main.rs              # CLI entry point
│   ├── lib.rs               # Module declarations
│   ├── config.rs            # Configuration management
│   ├── process_monitor.rs   # Real-time process scanning
│   ├── hash_engine.rs       # SHA-256 hashing & entropy
│   ├── heuristic_engine.rs  # Anomaly detection
│   ├── rule_engine.rs       # Signature-based rules
│   ├── logger.rs            # Security event logging
│   ├── alert.rs             # Alert management
│   ├── containment.rs       # Threat response
│   └── quarantine.rs        # Quarantine management
├── config.json              # Default configuration
├── Cargo.toml               # Rust dependencies
└── README.md
```

## Testing

```bash
cargo test
```

Runs 20+ unit tests covering:
- Hash computation and verification
- Process monitoring
- Heuristic analysis
- Rule engine
- Alert management
- Quarantine operations
- Logger functionality

## Security Notes

- **Read-only by default** — CoreEDR only monitors, does not modify system state unless configured
- **Cooldown protection** — prevents rapid repeated actions on the same process
- **Whitelist support** — protect system processes from accidental termination
- **Audit trail** — all actions are logged with full context
- **Quarantine** — suspicious items are isolated, not deleted

## License

MIT
