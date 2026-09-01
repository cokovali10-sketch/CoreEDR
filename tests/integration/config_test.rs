use coreedr::config::Config;

#[test]
fn test_default_config() {
    let config = Config::default();

    assert_eq!(config.general.scan_interval_ms, 5000);
    assert!(config.general.daemon_mode);
    assert!(config.monitoring.watch_processes);
    assert!(config.detection.enable_heuristic);
    assert!(config.detection.enable_signature);
    assert!(config.response.auto_kill_malicious);
    assert!(config.response.auto_quarantine);
    assert!(config.logging.json_format);
    assert_eq!(config.logging.retention_days, 30);
    assert!(!config.rules.blacklisted_names.is_empty());
}

#[test]
fn test_config_save_load() {
    let tmp = tempfile::tempdir().unwrap();
    let config_path = tmp.path().join("test_config.json");

    let mut config = Config::default();
    config.general.scan_interval_ms = 10000;
    config.detection.entropy_threshold = 8.5;

    let save_result = config.save(config_path.to_str().unwrap());
    assert!(save_result.is_ok(), "Config save should succeed");

    let loaded = Config::load(config_path.to_str().unwrap());
    assert!(loaded.is_ok(), "Config load should succeed");

    let loaded = loaded.unwrap();
    assert_eq!(loaded.general.scan_interval_ms, 10000);
    assert_eq!(loaded.detection.entropy_threshold, 8.5);
}

#[test]
fn test_config_serialization() {
    let config = Config::default();

    let json = serde_json::to_string(&config);
    assert!(json.is_ok(), "Serialization should succeed");

    let json_str = json.unwrap();
    assert!(json_str.contains("scan_interval_ms"));
    assert!(json_str.contains("enable_heuristic"));

    let deserialized: Result<Config, _> = serde_json::from_str(&json_str);
    assert!(deserialized.is_ok(), "Deserialization should succeed");

    let deserialized = deserialized.unwrap();
    assert_eq!(deserialized.general.scan_interval_ms, config.general.scan_interval_ms);
    assert_eq!(deserialized.detection.enable_heuristic, config.detection.enable_heuristic);
}

#[test]
fn test_config_load_nonexistent() {
    let result = Config::load("C:\\nonexistent\\config.json");
    assert!(result.is_err(), "Loading nonexistent config should fail");
}

#[test]
fn test_config_custom_paths() {
    let tmp = tempfile::tempdir().unwrap();
    let mut config = Config::default();
    config.general.quarantine_path = tmp.path().join("custom_quarantine");
    config.logging.log_path = tmp.path().join("custom.log");

    let json = serde_json::to_string(&config).unwrap();
    let loaded: Config = serde_json::from_str(&json).unwrap();

    assert_eq!(loaded.general.quarantine_path, tmp.path().join("custom_quarantine"));
    assert_eq!(loaded.logging.log_path, tmp.path().join("custom.log"));
}

#[test]
fn test_config_default_config() {
    let config = Config::default_config();
    assert_eq!(config.general.config_version, "1.0.0");
    assert_eq!(config.detection.entropy_threshold, 7.5);
    assert_eq!(config.response.cooldown_seconds, 30);
}

#[test]
fn test_config_pretty_json() {
    let config = Config::default();
    let pretty = serde_json::to_string_pretty(&config).unwrap();

    assert!(pretty.contains('\n'), "Pretty JSON should contain newlines");
    assert!(pretty.contains("  "), "Pretty JSON should be indented");

    let parsed: Config = serde_json::from_str(&pretty).unwrap();
    assert_eq!(parsed.general.scan_interval_ms, 5000);
}
