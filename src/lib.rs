pub mod alert;
pub mod config;
pub mod containment;
pub mod error;
pub mod hash_engine;
pub mod heuristic_engine;
pub mod logger;
pub mod process_monitor;
pub mod quarantine;
pub mod rule_engine;
pub mod scanner;

// Phase 2: Logging infrastructure
pub mod logging;

// Phase 3: Platform-specific modules
pub mod platform;

// Phase 4: File system monitoring
#[cfg(feature = "file-monitoring")]
pub mod monitoring;

// Phase 5: Network monitoring
#[cfg(feature = "network-monitoring")]
pub mod network;

// Phase 6: YARA integration
#[cfg(feature = "yara")]
pub mod yara;

// Phase 7: Encrypted quarantine (extends quarantine module)

// Phase 8: Behavioral analysis
#[cfg(feature = "behavioral-analysis")]
pub mod behavioral;

// Phase 9: ML threat classification
#[cfg(feature = "ml")]
pub mod ml;

// Phase 10: Tamper protection
#[cfg(feature = "tamper-protection")]
pub mod tamper;

// Phase 11: MITRE ATT&CK mapping
pub mod mitre;

// Phase 12: Event correlation
pub mod correlation;

// Phase 13: REST API
#[cfg(feature = "api")]
pub mod api;

// Phase 13: Auto-update
#[cfg(feature = "auto-update")]
pub mod updater;
