use crate::heuristic_engine::Severity;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMetadata {
    pub name: String,
    pub namespace: String,
    pub description: String,
    pub severity: Severity,
    pub tags: Vec<String>,
    pub author: Option<String>,
    pub date: Option<String>,
    pub reference: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMatchResult {
    pub metadata: RuleMetadata,
    pub matched_strings: Vec<MatchedString>,
    pub matched_offsets: Vec<MatchedOffset>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchedString {
    pub identifier: String,
    pub data: Vec<u8>,
    pub offset: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchedOffset {
    pub offset: usize,
    pub length: usize,
}

pub fn tag_to_severity(tags: &[String]) -> Severity {
    for tag in tags {
        let lower = tag.to_lowercase();
        match lower.as_str() {
            "critical" | "severity.critical" => return Severity::Critical,
            "high" | "severity.high" => return Severity::High,
            "medium" | "severity.medium" | "malicious" | "malware" => return Severity::Medium,
            "low" | "severity.low" | "suspicious" => return Severity::Low,
            _ => {}
        }
    }
    Severity::Medium
}

pub fn metadata_from_yara_match(
    rule_name: &str,
    namespace: &str,
    tags: &[String],
    metadata: &[(String, String)],
) -> RuleMetadata {
    let severity = tag_to_severity(tags);
    let description = metadata
        .iter()
        .find(|(k, _)| k == "description")
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    let author = metadata
        .iter()
        .find(|(k, _)| k == "author")
        .map(|(_, v)| v.clone());
    let date = metadata
        .iter()
        .find(|(k, _)| k == "date")
        .map(|(_, v)| v.clone());
    let reference = metadata
        .iter()
        .find(|(k, _)| k == "reference")
        .map(|(_, v)| v.clone());

    RuleMetadata {
        name: rule_name.to_string(),
        namespace: namespace.to_string(),
        description,
        severity,
        tags: tags.to_vec(),
        author,
        date,
        reference,
    }
}
