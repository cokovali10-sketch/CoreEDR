use crate::logger::{SecurityLogger, EventCategory, LogLevel};
use crate::heuristic_engine::Action;
use std::process::Command;
use std::path::PathBuf;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainmentAction {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub pid: u32,
    pub process_name: String,
    pub action_type: ContainmentType,
    pub result: ContainmentResult,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ContainmentType {
    Kill,
    Quarantine,
    Block,
    Alert,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ContainmentResult {
    Success,
    Failed,
    Skipped,
    PermissionDenied,
}

pub struct ContainmentEngine {
    quarantine_path: PathBuf,
    auto_kill: bool,
    auto_quarantine: bool,
    cooldown_seconds: u64,
    last_action: std::collections::HashMap<u32, std::time::Instant>,
}

impl ContainmentEngine {
    pub fn new(
        quarantine_path: PathBuf,
        auto_kill: bool,
        auto_quarantine: bool,
        cooldown_seconds: u64,
    ) -> Self {
        std::fs::create_dir_all(&quarantine_path).ok();

        Self {
            quarantine_path,
            auto_kill,
            auto_quarantine,
            cooldown_seconds,
            last_action: std::collections::HashMap::new(),
        }
    }

    pub fn execute_action(
        &mut self,
        pid: u32,
        process_name: &str,
        action: Action,
        logger: &SecurityLogger,
    ) -> ContainmentAction {
        if let Some(last) = self.last_action.get(&pid) {
            if last.elapsed().as_secs() < self.cooldown_seconds {
                logger.info(
                    EventCategory::Containment,
                    "containment",
                    &format!("Cooldown active for PID {}, skipping", pid),
                );
                return ContainmentAction {
                    timestamp: chrono::Utc::now(),
                    pid,
                    process_name: process_name.to_string(),
                    action_type: ContainmentType::Alert,
                    result: ContainmentResult::Skipped,
                    details: "Cooldown active".to_string(),
                };
            }
        }

        let result = match action {
            Action::Kill => self.kill_process(pid, process_name, logger),
            Action::Quarantine => self.quarantine_process(pid, process_name, logger),
            Action::Alert => self.alert_process(pid, process_name, logger),
            Action::Monitor => {
                logger.info(
                    EventCategory::Containment,
                    "containment",
                    &format!("Monitoring PID {} ({})", pid, process_name),
                );
                ContainmentResult::Skipped
            }
            Action::Allow => ContainmentResult::Skipped,
        };

        self.last_action.insert(pid, std::time::Instant::now());

        ContainmentAction {
            timestamp: chrono::Utc::now(),
            pid,
            process_name: process_name.to_string(),
            action_type: match action {
                Action::Kill => ContainmentType::Kill,
                Action::Quarantine => ContainmentType::Quarantine,
                _ => ContainmentType::Alert,
            },
            result,
            details: format!("Action {:?} executed on PID {}", action, pid),
        }
    }

    fn kill_process(
        &self,
        pid: u32,
        process_name: &str,
        logger: &SecurityLogger,
    ) -> ContainmentResult {
        if !self.auto_kill {
            logger.warning(
                EventCategory::Containment,
                "containment",
                &format!("Auto-kill disabled, would kill PID {} ({})", pid, process_name),
            );
            return ContainmentResult::Skipped;
        }

        logger.critical(
            EventCategory::Containment,
            "containment",
            &format!("KILLING process PID {} ({})", pid, process_name),
        );

        #[cfg(target_os = "windows")]
        let result = Command::new("taskkill")
            .args(["/F", "/PID", &pid.to_string()])
            .output();

        #[cfg(target_os = "linux")]
        let result = Command::new("kill")
            .args(["-9", &pid.to_string()])
            .output();

        #[cfg(target_os = "macos")]
        let result = Command::new("kill")
            .args(["-9", &pid.to_string()])
            .output();

        match result {
            Ok(output) => {
                if output.status.success() {
                    logger.info(
                        EventCategory::Containment,
                        "containment",
                        &format!("Successfully killed PID {} ({})", pid, process_name),
                    );
                    ContainmentResult::Success
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    logger.error(
                        EventCategory::Containment,
                        "containment",
                        &format!("Failed to kill PID {}: {}", pid, stderr),
                    );
                    if stderr.contains("Access Denied") || stderr.contains("permission") {
                        ContainmentResult::PermissionDenied
                    } else {
                        ContainmentResult::Failed
                    }
                }
            }
            Err(e) => {
                logger.error(
                    EventCategory::Containment,
                    "containment",
                    &format!("Error killing PID {}: {}", pid, e),
                );
                ContainmentResult::Failed
            }
        }
    }

    fn quarantine_process(
        &self,
        pid: u32,
        process_name: &str,
        logger: &SecurityLogger,
    ) -> ContainmentResult {
        if !self.auto_quarantine {
            logger.warning(
                EventCategory::Containment,
                "containment",
                &format!("Auto-quarantine disabled, would quarantine PID {} ({})", pid, process_name),
            );
            return ContainmentResult::Skipped;
        }

        logger.warning(
            EventCategory::Containment,
            "containment",
            &format!("QUARANTINING PID {} ({})", pid, process_name),
        );

        let quarantine_entry = self.quarantine_path.join(format!(
            "{}_{}_{}.json",
            process_name,
            pid,
            chrono::Utc::now().timestamp()
        ));

        let quarantine_data = serde_json::json!({
            "pid": pid,
            "process_name": process_name,
            "quarantine_time": chrono::Utc::now().to_rfc3339(),
            "action": "quarantine",
            "status": "pending_review",
        });

        match std::fs::write(&quarantine_entry, quarantine_data.to_string()) {
            Ok(_) => {
                logger.info(
                    EventCategory::Containment,
                    "containment",
                    &format!("Quarantine record created: {:?}", quarantine_entry),
                );
                ContainmentResult::Success
            }
            Err(e) => {
                logger.error(
                    EventCategory::Containment,
                    "containment",
                    &format!("Failed to create quarantine record: {}", e),
                );
                ContainmentResult::Failed
            }
        }
    }

    fn alert_process(
        &self,
        pid: u32,
        process_name: &str,
        logger: &SecurityLogger,
    ) -> ContainmentResult {
        logger.warning(
            EventCategory::Containment,
            "containment",
            &format!("ALERT: Suspicious process PID {} ({}) detected", pid, process_name),
        );
        ContainmentResult::Success
    }

    pub fn get_quarantine_list(&self) -> Vec<String> {
        let mut list = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&self.quarantine_path) {
            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_str() {
                    list.push(name.to_string());
                }
            }
        }
        list
    }

    pub fn restore_from_quarantine(&self, filename: &str) -> Result<(), Box<dyn std::error::Error>> {
        let path = self.quarantine_path.join(filename);
        if path.exists() {
            std::fs::remove_file(&path)?;
            Ok(())
        } else {
            Err("Quarantine entry not found".into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_containment_engine_creation() {
        let tmp = env::temp_dir().join("test_quarantine");
        let engine = ContainmentEngine::new(tmp.clone(), true, true, 30);
        assert!(engine.get_quarantine_list().is_empty());
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn test_quarantine_list() {
        let tmp = env::temp_dir().join("test_quarantine_list");
        let engine = ContainmentEngine::new(tmp.clone(), true, true, 30);
        let list = engine.get_quarantine_list();
        assert_eq!(list.len(), 0);
        std::fs::remove_dir_all(&tmp).ok();
    }
}
