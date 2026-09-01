pub mod compiler;
pub mod default_rules;
pub mod rules;
pub mod scanner;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraMatch {
    pub rule_name: String,
    pub namespace: String,
    pub severity: crate::heuristic_engine::Severity,
    pub description: String,
    pub matched_strings: Vec<String>,
    pub process_pid: Option<u32>,
    pub file_path: Option<String>,
}

pub struct YaraManager {
    rules: Vec<yara_x::Rules>,
}
