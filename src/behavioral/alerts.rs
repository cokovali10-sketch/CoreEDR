use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

use super::BehavioralEvent;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn numeric(&self) -> u32 {
        match self {
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralAlert {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub rule_name: String,
    pub severity: Severity,
    pub confidence: f64,
    pub description: String,
    pub events: Vec<BehavioralEvent>,
    pub recommended_action: String,
}

#[derive(Debug, Default)]
pub struct AlertStats {
    pub total_alerts: u64,
    pub by_severity: HashMap<String, u64>,
    pub by_rule: HashMap<String, u64>,
    pub avg_confidence: f64,
    confidence_sum: f64,
    confidence_count: u64,
}

impl AlertStats {
    pub fn record(&mut self, alert: &BehavioralAlert) {
        self.total_alerts += 1;

        *self.by_severity
            .entry(alert.severity.to_string())
            .or_insert(0) += 1;

        *self.by_rule
            .entry(alert.rule_name.clone())
            .or_insert(0) += 1;

        self.confidence_sum += alert.confidence;
        self.confidence_count += 1;
        self.avg_confidence = self.confidence_sum / self.confidence_count as f64;
    }
}

pub struct AlertDeduplicator {
    seen: Mutex<HashMap<String, DateTime<Utc>>>,
    ttl_seconds: u64,
}

impl AlertDeduplicator {
    pub fn new(ttl_seconds: u64) -> Self {
        Self {
            seen: Mutex::new(HashMap::new()),
            ttl_seconds,
        }
    }

    pub fn is_duplicate(&self, alert: &BehavioralAlert) -> bool {
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        let now = Utc::now();

        let key = format!("{}:{}", alert.rule_name, alert.description);

        if let Some(last_seen) = seen.get(&key) {
            if (now - *last_seen).num_seconds() < self.ttl_seconds as i64 {
                return true;
            }
        }

        seen.insert(key, now);
        false
    }

    pub fn cleanup_expired(&self) {
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        let now = Utc::now();
        seen.retain(|_, ts| (now - *ts).num_seconds() < self.ttl_seconds as i64);
    }

    pub fn clear(&self) {
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        seen.clear();
    }

    pub fn count(&self) -> usize {
        let seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        seen.len()
    }
}
