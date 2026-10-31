use crate::heuristic_engine::{AnalysisResult, Severity};
use crate::logger::{EventCategory, SecurityLogger};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub process_name: String,
    pub process_pid: u32,
    pub risk_score: u32,
    pub indicators_count: u32,
    pub acknowledged: bool,
}

pub struct AlertManager {
    alerts: Vec<Alert>,
    max_alerts: usize,
    alert_cooldown: HashMap<u32, std::time::Instant>,
    cooldown_seconds: u64,
}

impl AlertManager {
    pub fn new(max_alerts: usize, cooldown_seconds: u64) -> Self {
        Self {
            alerts: Vec::new(),
            max_alerts,
            alert_cooldown: HashMap::new(),
            cooldown_seconds,
        }
    }

    pub fn process_analysis(
        &mut self,
        result: &AnalysisResult,
        logger: &SecurityLogger,
    ) -> Option<Alert> {
        if result.severity == Severity::Info || result.severity == Severity::Low {
            return None;
        }

        if let Some(last_alert) = self.alert_cooldown.get(&result.process.pid) {
            if last_alert.elapsed().as_secs() < self.cooldown_seconds {
                return None;
            }
        }

        let alert = Alert {
            id: format!(
                "ALERT-{}-{}",
                result.process.pid,
                chrono::Utc::now().timestamp()
            ),
            timestamp: chrono::Utc::now(),
            severity: result.severity.clone(),
            title: self.generate_title(result),
            description: self.generate_description(result),
            process_name: result.process.name.clone(),
            process_pid: result.process.pid,
            risk_score: result.risk_score,
            indicators_count: result.indicators.len() as u32,
            acknowledged: false,
        };

        self.alert_cooldown
            .insert(result.process.pid, std::time::Instant::now());

        logger.warning(
            EventCategory::HeuristicAnalysis,
            "alert",
            &format!("[{}] {}", alert.id, alert.title),
        );

        if self.alerts.len() >= self.max_alerts {
            self.alerts.remove(0);
        }
        self.alerts.push(alert.clone());

        Some(alert)
    }

    fn generate_title(&self, result: &AnalysisResult) -> String {
        match result.severity {
            Severity::Critical => format!(
                "CRITICAL: {} (PID: {})",
                result.process.name, result.process.pid
            ),
            Severity::High => format!(
                "HIGH RISK: {} (PID: {})",
                result.process.name, result.process.pid
            ),
            Severity::Medium => format!(
                "SUSPICIOUS: {} (PID: {})",
                result.process.name, result.process.pid
            ),
            _ => format!(
                "NOTICE: {} (PID: {})",
                result.process.name, result.process.pid
            ),
        }
    }

    fn generate_description(&self, result: &AnalysisResult) -> String {
        let indicators: Vec<String> = result
            .indicators
            .iter()
            .map(|i| format!("- {} ({})", i.description, i.indicator_type))
            .collect();

        format!(
            "Process '{}' with PID {} scored {}/100 risk.\nIndicators:\n{}",
            result.process.name,
            result.process.pid,
            result.risk_score,
            indicators.join("\n")
        )
    }

    pub fn acknowledge(&mut self, alert_id: &str) -> bool {
        if let Some(alert) = self.alerts.iter_mut().find(|a| a.id == alert_id) {
            alert.acknowledged = true;
            true
        } else {
            false
        }
    }

    pub fn get_active_alerts(&self) -> Vec<&Alert> {
        self.alerts.iter().filter(|a| !a.acknowledged).collect()
    }

    pub fn get_all_alerts(&self) -> &[Alert] {
        &self.alerts
    }

    pub fn get_alerts_by_severity(&self, severity: &Severity) -> Vec<&Alert> {
        self.alerts
            .iter()
            .filter(|a| &a.severity == severity)
            .collect()
    }

    pub fn get_stats(&self) -> AlertStats {
        let mut stats = AlertStats::default();
        stats.total = self.alerts.len() as u32;
        for alert in &self.alerts {
            match alert.severity {
                Severity::Critical => stats.critical += 1,
                Severity::High => stats.high += 1,
                Severity::Medium => stats.medium += 1,
                Severity::Low => stats.low += 1,
                Severity::Info => stats.info += 1,
            }
            if alert.acknowledged {
                stats.acknowledged += 1;
            }
        }
        stats
    }

    pub fn clear_acknowledged(&mut self) {
        self.alerts.retain(|a| !a.acknowledged);
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AlertStats {
    pub total: u32,
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    pub info: u32,
    pub acknowledged: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process_monitor::ProcessInfo;

    fn make_test_result(name: &str, pid: u32, score: u32) -> AnalysisResult {
        AnalysisResult {
            process: ProcessInfo {
                pid,
                name: name.to_string(),
                path: format!("/usr/bin/{}", name),
                command_line: String::new(),
                parent_pid: 1,
                user: "root".to_string(),
                memory_usage_kb: 10000,
                cpu_percent: 5.0,
                start_time: chrono::Utc::now(),
                hash: None,
                risk_score: score,
                chain_depth: 0,
                root_pid: 1,
            },
            risk_score: score,
            severity: Severity::from_score(score),
            indicators: Vec::new(),
            recommended_action: crate::heuristic_engine::Action::Alert,
            analysis_time_ms: 10,
        }
    }

    #[test]
    fn test_alert_manager_creation() {
        let manager = AlertManager::new(100, 60);
        assert!(manager.get_all_alerts().is_empty());
    }

    #[test]
    fn test_alert_generation() {
        let mut manager = AlertManager::new(100, 0);
        let result = make_test_result("mimikatz", 1234, 85);
        let tmp = std::env::temp_dir().join("test_alert.log");
        let logger = SecurityLogger::new(&tmp, false).unwrap();

        let alert = manager.process_analysis(&result, &logger);
        assert!(alert.is_some());
        assert_eq!(manager.get_all_alerts().len(), 1);
        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn test_acknowledge() {
        let mut manager = AlertManager::new(100, 0);
        let result = make_test_result("suspicious", 5678, 70);
        let tmp = std::env::temp_dir().join("test_ack.log");
        let logger = SecurityLogger::new(&tmp, false).unwrap();

        let alert = manager.process_analysis(&result, &logger).unwrap();
        assert!(!alert.acknowledged);

        manager.acknowledge(&alert.id);
        let alerts = manager.get_all_alerts();
        assert!(alerts[0].acknowledged);
        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn test_severity_filter() {
        let mut manager = AlertManager::new(100, 0);
        let result_high = make_test_result("bad1", 1, 80);
        let result_med = make_test_result("bad2", 2, 50);
        let tmp = std::env::temp_dir().join("test_sev.log");
        let logger = SecurityLogger::new(&tmp, false).unwrap();

        manager.process_analysis(&result_high, &logger);
        manager.process_analysis(&result_med, &logger);

        let critical = manager.get_alerts_by_severity(&Severity::High);
        assert_eq!(critical.len(), 1);
        std::fs::remove_file(&tmp).ok();
    }
}
