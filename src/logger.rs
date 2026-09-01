use chrono::{DateTime, Utc, SecondsFormat};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{Write, BufWriter};
use std::path::Path;
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub timestamp: DateTime<Utc>,
    pub level: LogLevel,
    pub category: EventCategory,
    pub source: String,
    pub message: String,
    pub details: Option<String>,
    pub process_pid: Option<u32>,
    pub risk_score: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum LogLevel {
    Debug,
    Info,
    Warning,
    Error,
    Critical,
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogLevel::Debug => write!(f, "DEBUG"),
            LogLevel::Info => write!(f, "INFO"),
            LogLevel::Warning => write!(f, "WARNING"),
            LogLevel::Error => write!(f, "ERROR"),
            LogLevel::Critical => write!(f, "CRITICAL"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventCategory {
    ProcessMonitor,
    FileMonitor,
    NetworkMonitor,
    HeuristicAnalysis,
    SignatureDetection,
    Containment,
    System,
}

impl std::fmt::Display for EventCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EventCategory::ProcessMonitor => write!(f, "PROCESS"),
            EventCategory::FileMonitor => write!(f, "FILE"),
            EventCategory::NetworkMonitor => write!(f, "NETWORK"),
            EventCategory::HeuristicAnalysis => write!(f, "HEURISTIC"),
            EventCategory::SignatureDetection => write!(f, "SIGNATURE"),
            EventCategory::Containment => write!(f, "CONTAINMENT"),
            EventCategory::System => write!(f, "SYSTEM"),
        }
    }
}

pub struct SecurityLogger {
    writer: Mutex<BufWriter<File>>,
    json_format: bool,
    events: Mutex<Vec<SecurityEvent>>,
}

impl SecurityLogger {
    pub fn new(log_path: &Path, json_format: bool) -> Result<Self, Box<dyn std::error::Error>> {
        if let Some(parent) = log_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)?;

        Ok(Self {
            writer: Mutex::new(BufWriter::new(file)),
            json_format,
            events: Mutex::new(Vec::new()),
        })
    }

    pub fn log(
        &self,
        level: LogLevel,
        category: EventCategory,
        source: &str,
        message: &str,
        details: Option<String>,
        process_pid: Option<u32>,
        risk_score: Option<u32>,
    ) {
        let event = SecurityEvent {
            timestamp: Utc::now(),
            level,
            category,
            source: source.to_string(),
            message: message.to_string(),
            details,
            process_pid,
            risk_score,
        };

        if self.json_format {
            self.write_json(&event);
        } else {
            self.write_text(&event);
        }

        if let Ok(mut events) = self.events.lock() {
            events.push(event);
        }
    }

    fn write_json(&self, event: &SecurityEvent) {
        if let Ok(mut writer) = self.writer.lock() {
            if let Ok(json) = serde_json::to_string(event) {
                let _ = writeln!(writer, "{}", json);
            }
        }
    }

    fn write_text(&self, event: &SecurityEvent) {
        if let Ok(mut writer) = self.writer.lock() {
            let timestamp = event.timestamp.to_rfc3339_opts(SecondsFormat::Secs, true);
            let pid_str = event.process_pid
                .map(|p| format!(" [PID:{}]", p))
                .unwrap_or_default();
            let score_str = event.risk_score
                .map(|s| format!(" score={}", s))
                .unwrap_or_default();

            let _ = writeln!(
                writer,
                "[{}] {} {} {}:{}{}{}",
                timestamp,
                event.level,
                event.category,
                event.source,
                event.message,
                pid_str,
                score_str,
            );

            if let Some(ref details) = event.details {
                let _ = writeln!(writer, "  Details: {}", details);
            }
        }
    }

    pub fn info(&self, category: EventCategory, source: &str, message: &str) {
        self.log(LogLevel::Info, category, source, message, None, None, None);
    }

    pub fn warning(&self, category: EventCategory, source: &str, message: &str) {
        self.log(LogLevel::Warning, category, source, message, None, None, None);
    }

    pub fn error(&self, category: EventCategory, source: &str, message: &str) {
        self.log(LogLevel::Error, category, source, message, None, None, None);
    }

    pub fn critical(&self, category: EventCategory, source: &str, message: &str) {
        self.log(LogLevel::Critical, category, source, message, None, None, None);
    }

    pub fn get_recent_events(&self, count: usize) -> Vec<SecurityEvent> {
        if let Ok(events) = self.events.lock() {
            events.iter().rev().take(count).cloned().collect()
        } else {
            Vec::new()
        }
    }

    pub fn get_events_by_level(&self, level: LogLevel) -> Vec<SecurityEvent> {
        if let Ok(events) = self.events.lock() {
            events.iter().filter(|e| e.level == level).cloned().collect()
        } else {
            Vec::new()
        }
    }

    pub fn get_stats(&self) -> LoggerStats {
        if let Ok(events) = self.events.lock() {
            let mut stats = LoggerStats::default();
            stats.total_events = events.len() as u64;
            for event in events.iter() {
                match event.level {
                    LogLevel::Debug => stats.debug_count += 1,
                    LogLevel::Info => stats.info_count += 1,
                    LogLevel::Warning => stats.warning_count += 1,
                    LogLevel::Error => stats.error_count += 1,
                    LogLevel::Critical => stats.critical_count += 1,
                }
            }
            stats
        } else {
            LoggerStats::default()
        }
    }
}

#[derive(Debug, Default)]
pub struct LoggerStats {
    pub total_events: u64,
    pub debug_count: u64,
    pub info_count: u64,
    pub warning_count: u64,
    pub error_count: u64,
    pub critical_count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_logger_creation() {
        let tmp = env::temp_dir().join("test_coreedr.log");
        let logger = SecurityLogger::new(&tmp, false);
        assert!(logger.is_ok());
        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn test_log_write() {
        let tmp = env::temp_dir().join("test_coreedr_write.log");
        let logger = SecurityLogger::new(&tmp, false).unwrap();
        logger.info(EventCategory::System, "test", "Test message");
        logger.warning(EventCategory::ProcessMonitor, "test", "Warning message");
        logger.critical(EventCategory::Containment, "test", "Critical message");

        let stats = logger.get_stats();
        assert_eq!(stats.total_events, 3);
        assert_eq!(stats.info_count, 1);
        assert_eq!(stats.warning_count, 1);
        assert_eq!(stats.critical_count, 1);

        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn test_json_format() {
        let tmp = env::temp_dir().join("test_coreedr_json.log");
        let logger = SecurityLogger::new(&tmp, true).unwrap();
        logger.info(EventCategory::System, "test", "JSON test");

        let content = std::fs::read_to_string(&tmp).unwrap();
        assert!(content.contains("\"level\":\"Info\""));
        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn test_get_recent_events() {
        let tmp = env::temp_dir().join("test_coreedr_recent.log");
        let logger = SecurityLogger::new(&tmp, false).unwrap();
        for i in 0..5 {
            logger.info(EventCategory::System, "test", &format!("Event {}", i));
        }
        let recent = logger.get_recent_events(3);
        assert_eq!(recent.len(), 3);
        std::fs::remove_file(&tmp).ok();
    }
}
