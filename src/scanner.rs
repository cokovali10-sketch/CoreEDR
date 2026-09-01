use crate::config::Config;
use crate::containment::{ContainmentAction, ContainmentEngine};
use crate::error::{CoreError, Result};
use crate::heuristic_engine::{Action, HeuristicEngine};
use crate::hash_engine::HashEngine;
use crate::logger::{EventCategory, SecurityLogger};
use crate::process_monitor::{ProcessDelta, ProcessMonitor};
use crate::rule_engine::RuleEngine;

pub struct Scanner {
    config: Config,
    process_monitor: ProcessMonitor,
    heuristic_engine: HeuristicEngine,
    hash_engine: HashEngine,
    containment_engine: ContainmentEngine,
    alert_manager: crate::alert::AlertManager,
    rule_engine: RuleEngine,
    logger: SecurityLogger,
    scan_count: u64,
    threats_detected: u64,
    threats_contained: u64,
}

impl Scanner {
    pub fn new(config: Config) -> Result<Self> {
        let logger = SecurityLogger::new(&config.logging.log_path, config.logging.json_format)
            .map_err(|e| CoreError::Logger(e.to_string()))?;

        logger.info(EventCategory::System, "scanner", "CoreEDR Scanner initializing");

        let process_monitor = ProcessMonitor::new(config.general.scan_interval_ms);
        let heuristic_engine = HeuristicEngine::new(config.detection.clone());
        let hash_engine = HashEngine::new(config.detection.entropy_threshold);
        let containment_engine = ContainmentEngine::new(
            config.general.quarantine_path.clone(),
            config.response.auto_kill_malicious,
            config.response.auto_quarantine,
            config.response.cooldown_seconds,
        );
        let alert_manager = crate::alert::AlertManager::new(1000, config.response.cooldown_seconds);
        let rule_engine = RuleEngine::new(&config.rules)
            .map_err(|e| CoreError::RuleEngine(e.to_string()))?;

        logger.info(EventCategory::System, "scanner", "CoreEDR Scanner initialized");

        Ok(Self {
            config,
            process_monitor,
            heuristic_engine,
            hash_engine,
            containment_engine,
            alert_manager,
            rule_engine,
            logger,
            scan_count: 0,
            threats_detected: 0,
            threats_contained: 0,
        })
    }

    pub fn run_scan(&mut self) -> Result<ScanReport> {
        let start = std::time::Instant::now();
        self.scan_count += 1;

        self.logger.info(
            EventCategory::System,
            "scanner",
            &format!("Starting scan #{}", self.scan_count),
        );

        let delta = self.process_monitor.scan_processes()
            .map_err(|e| CoreError::ProcessMonitor(e.to_string()))?;

        self.logger.info(
            EventCategory::ProcessMonitor,
            "scanner",
            &format!(
                "Found {} new, {} terminated, {} modified processes",
                delta.new_processes.len(),
                delta.terminated_processes.len(),
                delta.modified_processes.len()
            ),
        );

        let mut analysis_results = Vec::new();
        let mut containment_actions = Vec::new();

        for process in &delta.new_processes {
            if self.is_process_ignored(&process.name) {
                continue;
            }

            let mut result = self.heuristic_engine.analyze(process);

            if self.config.detection.enable_signature {
                self.rule_engine.check_process(process, &mut result);
            }

            if result.risk_score > 0 {
                self.threats_detected += 1;

                if let Some(alert) = self.alert_manager.process_analysis(&result, &self.logger) {
                    self.logger.warning(
                        EventCategory::HeuristicAnalysis,
                        "scanner",
                        &format!("Alert generated: {}", alert.id),
                    );
                }

                match result.recommended_action {
                    Action::Kill | Action::Quarantine => {
                        let action = self.containment_engine.execute_action(
                            process.pid,
                            &process.name,
                            result.recommended_action.clone(),
                            &self.logger,
                        );
                        if matches!(action.result, crate::containment::ContainmentResult::Success) {
                            self.threats_contained += 1;
                        }
                        containment_actions.push(action);
                    }
                    _ => {}
                }
            }

            analysis_results.push(result);
        }

        let elapsed = start.elapsed().as_millis() as u64;

        let threat_summary = self.heuristic_engine.get_threat_summary(&analysis_results);
        let alert_stats = self.alert_manager.get_stats();
        let logger_stats = self.logger.get_stats();

        let report = ScanReport {
            scan_number: self.scan_count,
            timestamp: chrono::Utc::now(),
            duration_ms: elapsed,
            processes_scanned: delta.new_processes.len() as u32,
            new_processes: delta.new_processes.len() as u32,
            terminated_processes: delta.terminated_processes.len() as u32,
            modified_processes: delta.modified_processes.len() as u32,
            threats_detected: analysis_results.iter().filter(|r| r.risk_score > 40).count() as u32,
            threats_contained: containment_actions.iter()
                .filter(|a| matches!(a.result, crate::containment::ContainmentResult::Success))
                .count() as u32,
            threat_summary,
            alert_stats,
            logger_stats,
            containment_actions,
        };

        self.logger.info(
            EventCategory::System,
            "scanner",
            &format!(
                "Scan #{} complete: {} threats detected, {} contained, {}ms",
                self.scan_count, report.threats_detected, report.threats_contained, elapsed
            ),
        );

        Ok(report)
    }

    fn is_process_ignored(&self, name: &str) -> bool {
        self.config
            .monitoring
            .ignored_processes
            .iter()
            .any(|ignored| ignored.eq_ignore_ascii_case(name))
    }

    pub fn get_stats(&self) -> ScannerStats {
        ScannerStats {
            scan_count: self.scan_count,
            total_threats_detected: self.threats_detected,
            total_threats_contained: self.threats_contained,
        }
    }

    pub fn run_daemon(&mut self) -> Result<()> {
        self.logger.info(
            EventCategory::System,
            "scanner",
            "Starting EDR daemon mode",
        );

        loop {
            match self.run_scan() {
                Ok(report) => {
                    if report.threats_detected > 0 {
                        self.logger.warning(
                            EventCategory::System,
                            "daemon",
                            &format!("Scan found {} threats", report.threats_detected),
                        );
                    }
                }
                Err(e) => {
                    self.logger.error(
                        EventCategory::System,
                        "daemon",
                        &format!("Scan error: {}", e),
                    );
                }
            }

            std::thread::sleep(std::time::Duration::from_millis(
                self.config.general.scan_interval_ms,
            ));
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScanReport {
    pub scan_number: u64,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub duration_ms: u64,
    pub processes_scanned: u32,
    pub new_processes: u32,
    pub terminated_processes: u32,
    pub modified_processes: u32,
    pub threats_detected: u32,
    pub threats_contained: u32,
    pub threat_summary: crate::heuristic_engine::ThreatSummary,
    pub alert_stats: crate::alert::AlertStats,
    pub logger_stats: crate::logger::LoggerStats,
    pub containment_actions: Vec<ContainmentAction>,
}

#[derive(Debug)]
pub struct ScannerStats {
    pub scan_count: u64,
    pub total_threats_detected: u64,
    pub total_threats_contained: u64,
}
