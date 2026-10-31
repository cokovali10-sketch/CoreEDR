use crate::error::{CoreError, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub general: GeneralConfig,
    pub monitoring: MonitoringConfig,
    pub detection: DetectionConfig,
    pub response: ResponseConfig,
    pub logging: LoggingConfig,
    pub rules: RulesConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    pub scan_interval_ms: u64,
    pub daemon_mode: bool,
    pub max_cpu_percent: f64,
    pub quarantine_path: PathBuf,
    pub config_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringConfig {
    pub watch_processes: bool,
    pub watch_file_system: bool,
    pub watch_network: bool,
    pub watch_registry: bool,
    pub monitored_dirs: Vec<PathBuf>,
    pub ignored_dirs: Vec<PathBuf>,
    pub ignored_processes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionConfig {
    pub enable_heuristic: bool,
    pub enable_signature: bool,
    pub enable_behavioral: bool,
    pub entropy_threshold: f64,
    pub suspicious_api_threshold: u32,
    pub max_process_chain_depth: u32,
    pub yara_rules_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseConfig {
    pub auto_kill_malicious: bool,
    pub auto_quarantine: bool,
    pub alert_on_critical: bool,
    pub alert_command: Option<String>,
    pub cooldown_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub log_path: PathBuf,
    pub log_level: String,
    pub max_log_size_mb: u64,
    pub retention_days: u32,
    pub json_format: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulesConfig {
    pub rules_dir: PathBuf,
    pub custom_signatures: Vec<PathBuf>,
    pub blacklisted_hashes: Vec<String>,
    pub blacklisted_names: Vec<String>,
    pub whitelisted_hashes: Vec<String>,
    pub whitelisted_names: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            general: GeneralConfig {
                scan_interval_ms: 5000,
                daemon_mode: true,
                max_cpu_percent: 10.0,
                quarantine_path: PathBuf::from("./quarantine"),
                config_version: "1.0.0".to_string(),
            },
            monitoring: MonitoringConfig {
                watch_processes: true,
                watch_file_system: true,
                watch_network: true,
                watch_registry: false,
                monitored_dirs: vec![
                    PathBuf::from("/tmp"),
                    PathBuf::from("C:\\Users"),
                    PathBuf::from("/home"),
                ],
                ignored_dirs: vec![
                    PathBuf::from("/proc"),
                    PathBuf::from("/sys"),
                    PathBuf::from("C:\\Windows\\System32"),
                ],
                ignored_processes: vec![
                    "coreedr".to_string(),
                    "systemd".to_string(),
                    "launchd".to_string(),
                ],
            },
            detection: DetectionConfig {
                enable_heuristic: true,
                enable_signature: true,
                enable_behavioral: true,
                entropy_threshold: 7.5,
                suspicious_api_threshold: 5,
                max_process_chain_depth: 10,
                yara_rules_path: PathBuf::from("./rules"),
            },
            response: ResponseConfig {
                auto_kill_malicious: true,
                auto_quarantine: true,
                alert_on_critical: true,
                alert_command: None,
                cooldown_seconds: 30,
            },
            logging: LoggingConfig {
                log_path: PathBuf::from("./logs/coreedr.log"),
                log_level: "info".to_string(),
                max_log_size_mb: 100,
                retention_days: 30,
                json_format: true,
            },
            rules: RulesConfig {
                rules_dir: PathBuf::from("./rules"),
                custom_signatures: vec![],
                blacklisted_hashes: vec![
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
                ],
                blacklisted_names: vec![
                    "mimikatz".to_string(),
                    "lazagne".to_string(),
                    "bloodhound".to_string(),
                    "cobaltstrike".to_string(),
                    "meterpreter".to_string(),
                ],
                whitelisted_hashes: vec![],
                whitelisted_names: vec![
                    "svchost.exe".to_string(),
                    "csrss.exe".to_string(),
                    "lsass.exe".to_string(),
                    "explorer.exe".to_string(),
                    "kernel_task".to_string(),
                    "launchd".to_string(),
                    "systemd".to_string(),
                ],
            },
        }
    }
}

impl Config {
    pub fn load(path: &str) -> Result<Self> {
        let content = std::fs::read_to_string(path).map_err(|e| CoreError::ConfigNotFound {
            path: PathBuf::from(path),
        })?;
        let config: Config = serde_json::from_str(&content)?;
        Ok(config)
    }

    pub fn save(&self, path: &str) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    pub fn default_config() -> Self {
        Self::default()
    }
}
