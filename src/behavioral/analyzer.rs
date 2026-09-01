use crate::error::Result;
use super::BehavioralEvent;
use super::alerts::BehavioralAlert;
use super::event_store::EventStore;
use super::rules::{
    BehavioralRule, CredentialAccessPattern, OfficeAppNetworkSpawn,
    PowerShellDownloadExec, PersistenceCreation, RapidFileModification,
    SuspiciousProcessChain,
};

pub struct BehavioralAnalyzer {
    event_store: EventStore,
    rules: Vec<Box<dyn BehavioralRule>>,
    window_seconds: u64,
}

impl BehavioralAnalyzer {
    pub fn new() -> Self {
        Self::with_window(300)
    }

    pub fn with_window(window_seconds: u64) -> Self {
        let rules: Vec<Box<dyn BehavioralRule>> = vec![
            Box::new(OfficeAppNetworkSpawn),
            Box::new(PowerShellDownloadExec),
            Box::new(RapidFileModification),
            Box::new(SuspiciousProcessChain),
            Box::new(CredentialAccessPattern),
            Box::new(PersistenceCreation),
        ];

        Self {
            event_store: EventStore::new(),
            rules,
            window_seconds,
        }
    }

    pub fn with_event_store(event_store: EventStore, window_seconds: u64) -> Self {
        let rules: Vec<Box<dyn BehavioralRule>> = vec![
            Box::new(OfficeAppNetworkSpawn),
            Box::new(PowerShellDownloadExec),
            Box::new(RapidFileModification),
            Box::new(SuspiciousProcessChain),
            Box::new(CredentialAccessPattern),
            Box::new(PersistenceCreation),
        ];

        Self {
            event_store,
            rules,
            window_seconds,
        }
    }

    pub fn ingest_event(&self, event: BehavioralEvent) -> Result<()> {
        self.event_store.add_event(event)
    }

    pub fn analyze(&self) -> Result<Vec<BehavioralAlert>> {
        let events = self.event_store.get_events_in_window(self.window_seconds)?;
        self.analyze_events(&events)
    }

    pub fn analyze_events(&self, events: &[BehavioralEvent]) -> Result<Vec<BehavioralAlert>> {
        let mut alerts = Vec::new();

        for rule in &self.rules {
            if let Some(alert) = rule.evaluate(events) {
                alerts.push(alert);
            }
        }

        alerts.sort_by(|a, b| {
            b.severity().numeric().cmp(&a.severity().numeric())
                .then(b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal))
        });

        let alerts = self.deduplicate_alerts(alerts);
        Ok(alerts)
    }

    pub fn analyze_window(&self, seconds: u64) -> Result<Vec<BehavioralAlert>> {
        let events = self.event_store.get_events_in_window(seconds)?;
        self.analyze_events(&events)
    }

    pub fn analyze_for_pid(&self, pid: u32) -> Result<Vec<BehavioralAlert>> {
        let events = self.event_store.get_events_in_window_for_pid(self.window_seconds, pid)?;
        self.analyze_events(&events)
    }

    pub fn event_store(&self) -> &EventStore {
        &self.event_store
    }

    pub fn add_rule(&mut self, rule: Box<dyn BehavioralRule>) {
        self.rules.push(rule);
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    fn deduplicate_alerts(&self, mut alerts: Vec<BehavioralAlert>) -> Vec<BehavioralAlert> {
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        alerts.drain(..).filter(|a| {
            let key = format!("{}:{}", a.rule_name, a.description);
            seen.insert(key)
        }).collect()
    }

    pub fn compute_threat_score(&self, alerts: &[BehavioralAlert]) -> f64 {
        if alerts.is_empty() {
            return 0.0;
        }

        let total: f64 = alerts.iter()
            .map(|a| a.severity().numeric() as f64 * a.confidence)
            .sum();

        let max_possible = alerts.len() as f64 * 5.0;
        (total / max_possible).min(1.0)
    }
}

impl Default for BehavioralAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}
