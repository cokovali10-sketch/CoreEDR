use crate::process_monitor::ProcessInfo;
use crate::hash_engine::HashEngine;
use crate::config::DetectionConfig;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIndicator {
    pub indicator_type: String,
    pub description: String,
    pub severity: Severity,
    pub confidence: f64,
    pub process_pid: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn from_score(score: u32) -> Self {
        match score {
            0..=20 => Severity::Info,
            21..=40 => Severity::Low,
            41..=60 => Severity::Medium,
            61..=80 => Severity::High,
            _ => Severity::Critical,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub process: ProcessInfo,
    pub risk_score: u32,
    pub severity: Severity,
    pub indicators: Vec<ThreatIndicator>,
    pub recommended_action: Action,
    pub analysis_time_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Action {
    Allow,
    Monitor,
    Alert,
    Quarantine,
    Kill,
}

pub struct HeuristicEngine {
    config: DetectionConfig,
    suspicious_names: Vec<String>,
    suspicious_extensions: Vec<String>,
    process_anomaly_baseline: HashMap<u32, ProcessAnomalyBaseline>,
}

#[derive(Debug, Clone)]
struct ProcessAnomalyBaseline {
    avg_memory: f64,
    avg_cpu: f64,
    sample_count: u32,
}

impl HeuristicEngine {
    pub fn new(config: DetectionConfig) -> Self {
        let suspicious_names = vec![
            "mimikatz".to_string(),
            "lazagne".to_string(),
            "bloodhound".to_string(),
            "cobaltstrike".to_string(),
            "meterpreter".to_string(),
            "empire".to_string(),
            "covenant".to_string(),
            "sliver".to_string(),
            "havoc".to_string(),
            "brute_ratel".to_string(),
            "inject".to_string(),
            "keylog".to_string(),
            "rat".to_string(),
            "backdoor".to_string(),
            "trojan".to_string(),
            "rootkit".to_string(),
        ];

        let suspicious_extensions = vec![
            ".exe".to_string(),
            ".dll".to_string(),
            ".scr".to_string(),
            ".pif".to_string(),
            ".vbs".to_string(),
            ".js".to_string(),
            ".wsf".to_string(),
            ".ps1".to_string(),
            ".bat".to_string(),
            ".cmd".to_string(),
        ];

        Self {
            config,
            suspicious_names,
            suspicious_extensions,
            process_anomaly_baseline: HashMap::new(),
        }
    }

    pub fn analyze(&mut self, process: &ProcessInfo) -> AnalysisResult {
        let start = std::time::Instant::now();
        let mut indicators = Vec::new();
        let mut risk_score: u32 = 0;

        risk_score += self.check_name_suspicious(process, &mut indicators);
        risk_score += self.check_memory_anomaly(process, &mut indicators);
        risk_score += self.check_cpu_anomaly(process, &mut indicators);
        risk_score += self.check_process_chain(process, &mut indicators);
        risk_score += self.check_command_line(process, &mut indicators);
        risk_score += self.check_hidden_process(process, &mut indicators);

        risk_score = risk_score.min(100);

        let severity = Severity::from_score(risk_score);
        let recommended_action = self.determine_action(risk_score, &severity);

        AnalysisResult {
            process: process.clone(),
            risk_score,
            severity,
            indicators,
            recommended_action,
            analysis_time_ms: start.elapsed().as_millis() as u64,
        }
    }

    fn check_name_suspicious(&self, process: &ProcessInfo, indicators: &mut Vec<ThreatIndicator>) -> u32 {
        let name_lower = process.name.to_lowercase();

        for suspicious in &self.suspicious_names {
            if name_lower.contains(suspicious.as_str()) {
                indicators.push(ThreatIndicator {
                    indicator_type: "suspicious_name".to_string(),
                    description: format!("Process name contains suspicious string: {}", suspicious),
                    severity: Severity::High,
                    confidence: 0.9,
                    process_pid: process.pid,
                });
                return 40;
            }
        }

        0
    }

    fn check_memory_anomaly(&mut self, process: &ProcessInfo, indicators: &mut Vec<ThreatIndicator>) -> u32 {
        let baseline = self.process_anomaly_baseline
            .entry(process.parent_pid)
            .or_insert(ProcessAnomalyBaseline {
                avg_memory: process.memory_usage_kb as f64,
                avg_cpu: process.cpu_percent,
                sample_count: 1,
            });

        if baseline.sample_count > 10 {
            let memory_ratio = process.memory_usage_kb as f64 / baseline.avg_memory.max(1.0);
            if memory_ratio > 5.0 {
                indicators.push(ThreatIndicator {
                    indicator_type: "memory_anomaly".to_string(),
                    description: format!("Memory usage {}x above normal", memory_ratio as u32),
                    severity: Severity::Medium,
                    confidence: 0.7,
                    process_pid: process.pid,
                });
                return 20;
            }
        }

        baseline.avg_memory = (baseline.avg_memory * baseline.sample_count as f64
            + process.memory_usage_kb as f64)
            / (baseline.sample_count as f64 + 1.0);
        baseline.sample_count += 1;

        0
    }

    fn check_cpu_anomaly(&self, process: &ProcessInfo, indicators: &mut Vec<ThreatIndicator>) -> u32 {
        if process.cpu_percent > 90.0 {
            indicators.push(ThreatIndicator {
                indicator_type: "cpu_spike".to_string(),
                description: format!("CPU usage at {}%", process.cpu_percent),
                severity: Severity::Medium,
                confidence: 0.6,
                process_pid: process.pid,
            });
            return 15;
        }
        0
    }

    fn check_process_chain(&self, process: &ProcessInfo, indicators: &mut Vec<ThreatIndicator>) -> u32 {
        if process.parent_pid == 0 && process.pid > 1 {
            return 0;
        }

        if process.command_line.is_empty() && process.path.is_empty() {
            indicators.push(ThreatIndicator {
                indicator_type: "hidden_process".to_string(),
                description: "Process has no command line or path (possible hollowing)".to_string(),
                severity: Severity::High,
                confidence: 0.8,
                process_pid: process.pid,
            });
            return 30;
        }

        0
    }

    fn check_command_line(&self, process: &ProcessInfo, indicators: &mut Vec<ThreatIndicator>) -> u32 {
        let cmd_lower = process.command_line.to_lowercase();
        let mut score = 0;

        let suspicious_patterns = [
            ("powershell", "encodedcommand", 25),
            ("cmd.exe", "/c echo", 20),
            ("wget", ".onion", 30),
            ("curl", "pastebin", 25),
            ("reg add", "run", 20),
            ("schtasks", "/create", 20),
            ("net user", "/add", 25),
            ("whoami", "/priv", 15),
            ("mimikatz", "sekurlsa", 40),
            ("certutil", "-urlcache", 30),
            ("mshta", "javascript", 35),
            ("wscript", "vbs", 20),
        ];

        for (pattern1, pattern2, pts) in &suspicious_patterns {
            if cmd_lower.contains(pattern1) && cmd_lower.contains(pattern2) {
                indicators.push(ThreatIndicator {
                    indicator_type: "suspicious_command".to_string(),
                    description: format!("Command contains {} + {}", pattern1, pattern2),
                    severity: Severity::High,
                    confidence: 0.85,
                    process_pid: process.pid,
                });
                score += pts;
            }
        }

        score.min(40)
    }

    fn check_hidden_process(&self, process: &ProcessInfo, indicators: &mut Vec<ThreatIndicator>) -> u32 {
        let name_lower = process.name.to_lowercase();

        if name_lower.starts_with('.') && process.parent_pid > 1 {
            indicators.push(ThreatIndicator {
                indicator_type: "hidden_name".to_string(),
                description: "Process name starts with dot (attempting to hide)".to_string(),
                severity: Severity::Medium,
                confidence: 0.7,
                process_pid: process.pid,
            });
            return 20;
        }

        0
    }

    fn determine_action(&self, risk_score: u32, severity: &Severity) -> Action {
        match severity {
            Severity::Critical => Action::Kill,
            Severity::High => {
                if self.config.enable_heuristic {
                    Action::Quarantine
                } else {
                    Action::Alert
                }
            }
            Severity::Medium => Action::Alert,
            Severity::Low => Action::Monitor,
            Severity::Info => Action::Allow,
        }
    }

    pub fn batch_analyze(&mut self, processes: &[ProcessInfo]) -> Vec<AnalysisResult> {
        processes.iter().map(|p| self.analyze(p)).collect()
    }

    pub fn get_threat_summary(&self, results: &[AnalysisResult]) -> ThreatSummary {
        let mut summary = ThreatSummary::default();
        for result in results {
            match result.severity {
                Severity::Critical => summary.critical += 1,
                Severity::High => summary.high += 1,
                Severity::Medium => summary.medium += 1,
                Severity::Low => summary.low += 1,
                Severity::Info => summary.info += 1,
            }
            summary.total_indicators += result.indicators.len() as u32;
        }
        summary.total = results.len() as u32;
        summary
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ThreatSummary {
    pub total: u32,
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    pub info: u32,
    pub total_indicators: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_process(name: &str, pid: u32, memory: u64, cpu: f64) -> ProcessInfo {
        ProcessInfo {
            pid,
            name: name.to_string(),
            path: format!("/usr/bin/{}", name),
            command_line: format!("{} --test", name),
            parent_pid: 1,
            user: "root".to_string(),
            memory_usage_kb: memory,
            cpu_percent: cpu,
            start_time: chrono::Utc::now(),
            hash: None,
            risk_score: 0,
        }
    }

    #[test]
    fn test_suspicious_name_detection() {
        let config = DetectionConfig {
            enable_heuristic: true,
            enable_signature: true,
            enable_behavioral: true,
            entropy_threshold: 7.5,
            suspicious_api_threshold: 5,
            max_process_chain_depth: 10,
            yara_rules_path: std::path::PathBuf::from("./rules"),
        };
        let mut engine = HeuristicEngine::new(config);
        let proc = make_test_process("mimikatz", 1234, 10000, 5.0);
        let result = engine.analyze(&proc);
        assert!(result.risk_score > 0);
        assert!(!result.indicators.is_empty());
    }

    #[test]
    fn test_clean_process() {
        let config = DetectionConfig {
            enable_heuristic: true,
            enable_signature: true,
            enable_behavioral: true,
            entropy_threshold: 7.5,
            suspicious_api_threshold: 5,
            max_process_chain_depth: 10,
            yara_rules_path: std::path::PathBuf::from("./rules"),
        };
        let mut engine = HeuristicEngine::new(config);
        let proc = make_test_process("bash", 100, 5000, 2.0);
        let result = engine.analyze(&proc);
        assert!(result.risk_score < 30);
    }

    #[test]
    fn test_severity_from_score() {
        assert_eq!(Severity::from_score(10), Severity::Info);
        assert_eq!(Severity::from_score(30), Severity::Low);
        assert_eq!(Severity::from_score(50), Severity::Medium);
        assert_eq!(Severity::from_score(70), Severity::High);
        assert_eq!(Severity::from_score(90), Severity::Critical);
    }
}
