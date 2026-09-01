use coreedr::config::{Config, GeneralConfig, MonitoringConfig, DetectionConfig, ResponseConfig, LoggingConfig, RulesConfig};
use std::path::PathBuf;

pub const EICAR_TEST_STRING: &str = r#"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"#;

pub fn create_temp_dir(prefix: &str) -> PathBuf {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.into_path();
    std::fs::create_dir_all(&path).ok();
    path
}

pub fn make_test_config() -> Config {
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.into_path();

    Config {
        general: GeneralConfig {
            scan_interval_ms: 5000,
            daemon_mode: false,
            max_cpu_percent: 10.0,
            quarantine_path: base.join("quarantine"),
            config_version: "1.0.0".to_string(),
        },
        monitoring: MonitoringConfig {
            watch_processes: true,
            watch_file_system: false,
            watch_network: false,
            watch_registry: false,
            monitored_dirs: vec![],
            ignored_dirs: vec![],
            ignored_processes: vec!["coreedr".to_string()],
        },
        detection: DetectionConfig {
            enable_heuristic: true,
            enable_signature: true,
            enable_behavioral: false,
            entropy_threshold: 7.5,
            suspicious_api_threshold: 5,
            max_process_chain_depth: 10,
            yara_rules_path: base.join("rules"),
        },
        response: ResponseConfig {
            auto_kill_malicious: false,
            auto_quarantine: true,
            alert_on_critical: true,
            alert_command: None,
            cooldown_seconds: 60,
        },
        logging: LoggingConfig {
            log_path: base.join("logs").join("test.log"),
            log_level: "info".to_string(),
            max_log_size_mb: 10,
            retention_days: 7,
            json_format: true,
        },
        rules: RulesConfig {
            rules_dir: base.join("rules"),
            custom_signatures: vec![],
            blacklisted_hashes: vec![],
            blacklisted_names: vec!["mimikatz".to_string()],
            whitelisted_hashes: vec![],
            whitelisted_names: vec!["bash".to_string()],
        },
    }
}
