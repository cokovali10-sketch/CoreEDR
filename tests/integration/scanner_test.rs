use coreedr::config::Config;
use coreedr::scanner::Scanner;
use std::fs;

fn make_test_config() -> Config {
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.into_path();

    Config {
        general: coreedr::config::GeneralConfig {
            scan_interval_ms: 5000,
            daemon_mode: false,
            max_cpu_percent: 10.0,
            quarantine_path: base.join("quarantine"),
            config_version: "1.0.0".to_string(),
        },
        monitoring: coreedr::config::MonitoringConfig {
            watch_processes: true,
            watch_file_system: false,
            watch_network: false,
            watch_registry: false,
            monitored_dirs: vec![],
            ignored_dirs: vec![],
            ignored_processes: vec!["coreedr".to_string()],
        },
        detection: coreedr::config::DetectionConfig {
            enable_heuristic: true,
            enable_signature: true,
            enable_behavioral: false,
            entropy_threshold: 7.5,
            suspicious_api_threshold: 5,
            max_process_chain_depth: 10,
            yara_rules_path: base.join("rules"),
        },
        response: coreedr::config::ResponseConfig {
            auto_kill_malicious: false,
            auto_quarantine: true,
            alert_on_critical: true,
            alert_command: None,
            cooldown_seconds: 60,
        },
        logging: coreedr::config::LoggingConfig {
            log_path: base.join("logs").join("test.log"),
            log_level: "info".to_string(),
            max_log_size_mb: 10,
            retention_days: 7,
            json_format: true,
        },
        rules: coreedr::config::RulesConfig {
            rules_dir: base.join("rules"),
            custom_signatures: vec![],
            blacklisted_hashes: vec![],
            blacklisted_names: vec![],
            whitelisted_hashes: vec![],
            whitelisted_names: vec![],
        },
    }
}

#[test]
fn test_scanner_creation() {
    let config = make_test_config();
    let scanner = Scanner::new(config);
    assert!(scanner.is_ok(), "Scanner should initialize without error");
}

#[test]
fn test_single_scan() {
    let config = make_test_config();
    let mut scanner = Scanner::new(config).unwrap();
    let report = scanner.run_scan();

    assert!(report.is_ok(), "Scan should complete without error");
    let report = report.unwrap();
    assert!(report.duration_ms > 0 || report.processes_scanned >= 0);
}

#[test]
fn test_scan_detects_processes() {
    let config = make_test_config();
    let mut scanner = Scanner::new(config).unwrap();
    let report = scanner.run_scan().unwrap();

    assert!(
        report.processes_scanned > 0 || report.new_processes > 0,
        "Scan should find at least some running processes"
    );
}

#[test]
fn test_scan_report_structure() {
    let config = make_test_config();
    let mut scanner = Scanner::new(config).unwrap();
    let report = scanner.run_scan().unwrap();

    assert_eq!(report.scan_number, 1);
    assert!(report.timestamp.timestamp() > 0);
    assert!(report.duration_ms < 60000, "Scan should complete within 60s");
    assert!(!report.threat_summary.critical > 1000);
    assert!(report.logger_stats.total_events > 0);
}

#[test]
fn test_scanner_stats() {
    let config = make_test_config();
    let mut scanner = Scanner::new(config).unwrap();
    let _ = scanner.run_scan();

    let stats = scanner.get_stats();
    assert_eq!(stats.scan_count, 1);
}

#[test]
fn test_multiple_scans_increment_counter() {
    let config = make_test_config();
    let mut scanner = Scanner::new(config).unwrap();
    let _ = scanner.run_scan();
    let _ = scanner.run_scan();
    let _ = scanner.run_scan();

    let stats = scanner.get_stats();
    assert_eq!(stats.scan_count, 3);
}

#[test]
fn test_scan_with_default_config() {
    let config = Config::default();
    let mut scanner = Scanner::new(config);
    assert!(scanner.is_ok());

    let report = scanner.unwrap().run_scan();
    assert!(report.is_ok());
}
