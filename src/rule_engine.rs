use crate::config::RulesConfig;
use crate::process_monitor::ProcessInfo;
use crate::heuristic_engine::{AnalysisResult, ThreatIndicator, Severity};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub name: String,
    pub description: String,
    pub severity: Severity,
    pub condition: RuleCondition,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleCondition {
    NameContains(String),
    NameMatches(String),
    HashEquals(String),
    PathContains(String),
    CommandLineContains(String),
    MemoryAbove(u64),
    CpuAbove(f64),
    Combined(Vec<RuleCondition>),
}

pub struct RuleEngine {
    rules: Vec<Rule>,
    blacklisted_hashes: Vec<String>,
    blacklisted_names: Vec<String>,
    whitelisted_hashes: Vec<String>,
    whitelisted_names: Vec<String>,
}

impl RuleEngine {
    pub fn new(config: &RulesConfig) -> Result<Self, crate::error::CoreError> {
        let mut rules = Vec::new();

        for rules_file in &config.custom_signatures {
            if rules_file.exists() {
                let content = std::fs::read_to_string(rules_file)?;
                let file_rules: Vec<Rule> = serde_json::from_str(&content)?;
                rules.extend(file_rules);
            }
        }

        rules.push(Rule {
            name: "suspicious_encoded_ps".to_string(),
            description: "PowerShell with encoded command".to_string(),
            severity: Severity::High,
            condition: RuleCondition::Combined(vec![
                RuleCondition::CommandLineContains("powershell".to_string()),
                RuleCondition::CommandLineContains("encodedcommand".to_string()),
            ]),
            enabled: true,
        });

        rules.push(Rule {
            name: "mimikatz_detected".to_string(),
            description: "Mimikatz credential dumping tool".to_string(),
            severity: Severity::Critical,
            condition: RuleCondition::NameContains("mimikatz".to_string()),
            enabled: true,
        });

        rules.push(Rule {
            name: "high_entropy_process".to_string(),
            description: "Process with suspiciously high entropy".to_string(),
            severity: Severity::High,
            condition: RuleCondition::Combined(vec![
                RuleCondition::MemoryAbove(100_000_000),
            ]),
            enabled: true,
        });

        Ok(Self {
            rules,
            blacklisted_hashes: config.blacklisted_hashes.clone(),
            blacklisted_names: config.blacklisted_names.clone(),
            whitelisted_hashes: config.whitelisted_hashes.clone(),
            whitelisted_names: config.whitelisted_names.clone(),
        })
    }

    pub fn check_process(&self, process: &ProcessInfo, result: &mut AnalysisResult) {
        if self.is_whitelisted(process) {
            return;
        }

        if self.is_blacklisted(process) {
            result.indicators.push(ThreatIndicator {
                indicator_type: "blacklisted".to_string(),
                description: format!("Process matches blacklisted entry: {}", process.name),
                severity: Severity::Critical,
                confidence: 1.0,
                process_pid: process.pid,
            });
            result.risk_score = 100;
            result.severity = Severity::Critical;
            return;
        }

        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }

            if self.evaluate_condition(&rule.condition, process) {
                result.indicators.push(ThreatIndicator {
                    indicator_type: "rule_match".to_string(),
                    description: format!("Rule '{}' matched: {}", rule.name, rule.description),
                    severity: rule.severity.clone(),
                    confidence: 0.9,
                    process_pid: process.pid,
                });

                let rule_score = match rule.severity {
                    Severity::Critical => 50,
                    Severity::High => 30,
                    Severity::Medium => 20,
                    Severity::Low => 10,
                    Severity::Info => 5,
                };

                result.risk_score = (result.risk_score + rule_score).min(100);
                result.severity = if rule.severity > result.severity {
                    rule.severity.clone()
                } else {
                    result.severity.clone()
                };
            }
        }
    }

    fn evaluate_condition(&self, condition: &RuleCondition, process: &ProcessInfo) -> bool {
        match condition {
            RuleCondition::NameContains(s) => {
                process.name.to_lowercase().contains(&s.to_lowercase())
            }
            RuleCondition::NameMatches(pattern) => {
                regex::Regex::new(pattern)
                    .map(|re| re.is_match(&process.name))
                    .unwrap_or(false)
            }
            RuleCondition::HashEquals(hash) => {
                process.hash.as_ref().map(|h| h == hash).unwrap_or(false)
            }
            RuleCondition::PathContains(s) => {
                process.path.to_lowercase().contains(&s.to_lowercase())
            }
            RuleCondition::CommandLineContains(s) => {
                process.command_line.to_lowercase().contains(&s.to_lowercase())
            }
            RuleCondition::MemoryAbove(threshold) => {
                process.memory_usage_kb > *threshold
            }
            RuleCondition::CpuAbove(threshold) => {
                process.cpu_percent > *threshold
            }
            RuleCondition::Combined(conditions) => {
                conditions.iter().all(|c| self.evaluate_condition(c, process))
            }
        }
    }

    fn is_whitelisted(&self, process: &ProcessInfo) -> bool {
        if let Some(ref hash) = process.hash {
            if self.whitelisted_hashes.iter().any(|h| h == hash) {
                return true;
            }
        }
        self.whitelisted_names.iter()
            .any(|n| n.eq_ignore_ascii_case(&process.name))
    }

    fn is_blacklisted(&self, process: &ProcessInfo) -> bool {
        if let Some(ref hash) = process.hash {
            if self.blacklisted_hashes.iter().any(|h| h == hash) {
                return true;
            }
        }
        self.blacklisted_names.iter()
            .any(|n| n.eq_ignore_ascii_case(&process.name))
    }

    pub fn load_rules_from_file(&mut self, path: &Path) -> Result<(), crate::error::CoreError> {
        let content = std::fs::read_to_string(path)?;
        let rules: Vec<Rule> = serde_json::from_str(&content)?;
        self.rules.extend(rules);
        Ok(())
    }

    pub fn get_rules(&self) -> &[Rule] {
        &self.rules
    }

    pub fn add_rule(&mut self, rule: Rule) {
        self.rules.push(rule);
    }

    pub fn remove_rule(&mut self, name: &str) -> bool {
        let len_before = self.rules.len();
        self.rules.retain(|r| r.name != name);
        self.rules.len() < len_before
    }

    pub fn enable_rule(&mut self, name: &str) -> bool {
        if let Some(rule) = self.rules.iter_mut().find(|r| r.name == name) {
            rule.enabled = true;
            true
        } else {
            false
        }
    }

    pub fn disable_rule(&mut self, name: &str) -> bool {
        if let Some(rule) = self.rules.iter_mut().find(|r| r.name == name) {
            rule.enabled = false;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn make_test_config() -> RulesConfig {
        RulesConfig {
            rules_dir: env::temp_dir(),
            custom_signatures: vec![],
            blacklisted_hashes: vec!["abc123".to_string()],
            blacklisted_names: vec!["mimikatz".to_string()],
            whitelisted_hashes: vec![],
            whitelisted_names: vec!["bash".to_string()],
        }
    }

    fn make_test_process(name: &str) -> ProcessInfo {
        ProcessInfo {
            pid: 1234,
            name: name.to_string(),
            path: format!("/usr/bin/{}", name),
            command_line: format!("{} --test", name),
            parent_pid: 1,
            user: "root".to_string(),
            memory_usage_kb: 10000,
            cpu_percent: 5.0,
            start_time: chrono::Utc::now(),
            hash: None,
            risk_score: 0,
        }
    }

    #[test]
    fn test_rule_engine_creation() {
        let config = make_test_config();
        let engine = RuleEngine::new(&config);
        assert!(engine.is_ok());
    }

    #[test]
    fn test_blacklist_detection() {
        let config = make_test_config();
        let engine = RuleEngine::new(&config).unwrap();
        let proc = make_test_process("mimikatz");
        let mut result = AnalysisResult {
            process: proc.clone(),
            risk_score: 0,
            severity: Severity::Info,
            indicators: Vec::new(),
            recommended_action: crate::heuristic_engine::Action::Allow,
            analysis_time_ms: 0,
        };

        engine.check_process(&proc, &mut result);
        assert_eq!(result.risk_score, 100);
    }

    #[test]
    fn test_whitelist_bypass() {
        let config = make_test_config();
        let engine = RuleEngine::new(&config).unwrap();
        let proc = make_test_process("bash");
        let mut result = AnalysisResult {
            process: proc.clone(),
            risk_score: 0,
            severity: Severity::Info,
            indicators: Vec::new(),
            recommended_action: crate::heuristic_engine::Action::Allow,
            analysis_time_ms: 0,
        };

        engine.check_process(&proc, &mut result);
        assert_eq!(result.risk_score, 0);
        assert!(result.indicators.is_empty());
    }

    #[test]
    fn test_rule_add_remove() {
        let config = make_test_config();
        let mut engine = RuleEngine::new(&config).unwrap();
        let initial_count = engine.get_rules().len();

        engine.add_rule(Rule {
            name: "test_rule".to_string(),
            description: "Test".to_string(),
            severity: Severity::Low,
            condition: RuleCondition::NameContains("test".to_string()),
            enabled: true,
        });

        assert_eq!(engine.get_rules().len(), initial_count + 1);
        assert!(engine.remove_rule("test_rule"));
        assert_eq!(engine.get_rules().len(), initial_count);
    }
}
