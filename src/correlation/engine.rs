use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelatedEvent {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub event_type: EventType,
    pub process_id: Option<u32>,
    pub process_name: Option<String>,
    pub parent_id: Option<u32>,
    pub user: Option<String>,
    pub details: HashMap<String, String>,
    pub chain_id: Option<String>,
    pub severity: Severity,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum EventType {
    ProcessCreation,
    ProcessTermination,
    FileAccess,
    FileCreation,
    FileModification,
    FileDeletion,
    NetworkConnection,
    NetworkListening,
    RegistryModification,
    ServiceCreation,
    ScheduledTask,
    Alert,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Info,
        }
    }

    pub fn to_string(&self) -> String {
        match self {
            Severity::Info => "info".into(),
            Severity::Low => "low".into(),
            Severity::Medium => "medium".into(),
            Severity::High => "high".into(),
            Severity::Critical => "critical".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum IncidentState {
    New,
    Triaged,
    Investigating,
    Contained,
    Eradicating,
    Recovering,
    Resolved,
    Closed,
    Reopened,
}

impl IncidentState {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "new" => IncidentState::New,
            "triaged" => IncidentState::Triaged,
            "investigating" => IncidentState::Investigating,
            "contained" => IncidentState::Contained,
            "eradicating" => IncidentState::Eradicating,
            "recovering" => IncidentState::Recovering,
            "resolved" => IncidentState::Resolved,
            "closed" => IncidentState::Closed,
            "reopened" => IncidentState::Reopened,
            _ => IncidentState::New,
        }
    }

    pub fn can_transition_to(&self, next: &IncidentState) -> bool {
        matches!(
            (self, next),
            (IncidentState::New, IncidentState::Triaged)
                | (IncidentState::Triaged, IncidentState::Investigating)
                | (IncidentState::Investigating, IncidentState::Contained)
                | (IncidentState::Contained, IncidentState::Eradicating)
                | (IncidentState::Eradicating, IncidentState::Recovering)
                | (IncidentState::Recovering, IncidentState::Resolved)
                | (IncidentState::Resolved, IncidentState::Closed)
                | (IncidentState::Closed, IncidentState::Reopened)
                | (IncidentState::Reopened, IncidentState::Investigating)
                | (IncidentState::Investigating, IncidentState::Resolved)
                | (IncidentState::Triaged, IncidentState::Resolved)
        )
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self, IncidentState::Closed)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Incident {
    pub id: String,
    pub title: String,
    pub description: String,
    pub state: IncidentState,
    pub severity: Severity,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub closed_at: Option<DateTime<Utc>>,
    pub assignee: Option<String>,
    pub chain_ids: Vec<String>,
    pub timeline: Vec<IncidentEvent>,
    pub mitre_techniques: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentEvent {
    pub timestamp: DateTime<Utc>,
    pub action: String,
    pub actor: String,
    pub notes: Option<String>,
}

impl Incident {
    pub fn new(title: String, description: String, severity: Severity) -> Self {
        let now = Utc::now();
        Incident {
            id: format!("inc-{}", now.timestamp()),
            title,
            description,
            state: IncidentState::New,
            severity,
            created_at: now,
            updated_at: now,
            closed_at: None,
            assignee: None,
            chain_ids: Vec::new(),
            timeline: Vec::new(),
            mitre_techniques: Vec::new(),
        }
    }

    pub fn transition(
        &mut self,
        next_state: IncidentState,
        actor: String,
        notes: Option<String>,
    ) -> Result<(), String> {
        if !self.state.can_transition_to(&next_state) {
            return Err(format!(
                "Invalid transition: {:?} -> {:?}",
                self.state, next_state
            ));
        }

        self.timeline.push(IncidentEvent {
            timestamp: Utc::now(),
            action: format!("{:?} -> {:?}", self.state, next_state),
            actor,
            notes,
        });

        self.state = next_state;
        self.updated_at = Utc::now();

        if self.state.is_terminal() {
            self.closed_at = Some(Utc::now());
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventChain {
    pub id: String,
    pub events: Vec<CorrelatedEvent>,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub root_cause: Option<String>,
    pub severity: Severity,
    pub mitre_techniques: Vec<String>,
}

pub struct CorrelationEngine {
    events: Vec<CorrelatedEvent>,
    chains: HashMap<String, EventChain>,
    incidents: HashMap<String, Incident>,
    process_tree: HashMap<u32, Vec<u32>>,
    time_window: Duration,
    max_events: usize,
}

impl CorrelationEngine {
    pub fn new() -> Self {
        CorrelationEngine {
            events: Vec::new(),
            chains: HashMap::new(),
            incidents: HashMap::new(),
            process_tree: HashMap::new(),
            time_window: Duration::minutes(5),
            max_events: 100000,
        }
    }

    pub fn with_time_window(mut self, window: Duration) -> Self {
        self.time_window = window;
        self
    }

    pub fn add_event(&mut self, event: CorrelatedEvent) {
        if let Some(parent_id) = event.parent_id {
            self.process_tree
                .entry(parent_id)
                .or_insert_with(Vec::new)
                .push(event.process_id.unwrap_or(0));
        }

        self.events.push(event.clone());

        if self.events.len() > self.max_events {
            let drain_count = self.events.len() - self.max_events;
            self.events.drain(..drain_count);
        }

        self.correlate_event(&event);
    }

    fn correlate_event(&mut self, event: &CorrelatedEvent) {
        let recent_events: Vec<CorrelatedEvent> = self
            .events
            .iter()
            .filter(|e| {
                let time_diff = event.timestamp.signed_duration_since(e.timestamp);
                time_diff <= self.time_window && time_diff >= Duration::zero()
            })
            .cloned()
            .collect();

        let mut chain_events = vec![event.clone()];

        for recent in &recent_events {
            if self.are_related(event, recent) {
                chain_events.push(recent.clone());
            }
        }

        if chain_events.len() > 1 {
            chain_events.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

            let chain_id = format!("chain-{}", uuid_simple());
            let start_time = chain_events.first().unwrap().timestamp;
            let end_time = chain_events.last().unwrap().timestamp;
            let severity = self.calculate_chain_severity(&chain_events);

            let chain = EventChain {
                id: chain_id.clone(),
                events: chain_events,
                start_time,
                end_time,
                root_cause: None,
                severity,
                mitre_techniques: Vec::new(),
            };

            self.chains.insert(chain_id, chain);
        }
    }

    fn are_related(&self, a: &CorrelatedEvent, b: &CorrelatedEvent) -> bool {
        if a.id == b.id {
            return false;
        }

        if let (Some(a_pid), Some(b_pid)) = (a.process_id, b.process_id) {
            if a_pid == b_pid {
                return true;
            }
            if self
                .process_tree
                .get(&a_pid)
                .map_or(false, |children| children.contains(&b_pid))
            {
                return true;
            }
            if self
                .process_tree
                .get(&b_pid)
                .map_or(false, |children| children.contains(&a_pid))
            {
                return true;
            }
        }

        if a.process_id == b.process_id && a.process_id.is_some() {
            return true;
        }

        let time_diff = a
            .timestamp
            .signed_duration_since(b.timestamp)
            .num_seconds()
            .abs();
        if time_diff < 30 {
            if let (Some(a_user), Some(b_user)) = (&a.user, &b.user) {
                if a_user == b_user {
                    return true;
                }
            }
        }

        false
    }

    fn calculate_chain_severity(&self, events: &[CorrelatedEvent]) -> Severity {
        let has_critical = events.iter().any(|e| e.severity == Severity::Critical);
        let has_high = events.iter().any(|e| e.severity == Severity::High);
        let event_count = events.len();

        if has_critical {
            Severity::Critical
        } else if has_high || event_count > 10 {
            Severity::High
        } else if event_count > 5 {
            Severity::Medium
        } else if event_count > 2 {
            Severity::Low
        } else {
            Severity::Info
        }
    }

    pub fn get_chains(&self) -> Vec<&EventChain> {
        self.chains.values().collect()
    }

    pub fn get_chain(&self, id: &str) -> Option<&EventChain> {
        self.chains.get(id)
    }

    pub fn get_process_children(&self, pid: u32) -> Vec<u32> {
        self.process_tree.get(&pid).cloned().unwrap_or_default()
    }

    pub fn get_process_tree(&self, pid: u32, depth: usize) -> Vec<(u32, usize)> {
        let mut result = Vec::new();
        self.get_process_tree_recursive(pid, depth, &mut result);
        result
    }

    fn get_process_tree_recursive(&self, pid: u32, depth: usize, result: &mut Vec<(u32, usize)>) {
        if depth == 0 {
            return;
        }
        result.push((pid, depth));

        if let Some(children) = self.process_tree.get(&pid) {
            for &child in children {
                self.get_process_tree_recursive(child, depth - 1, result);
            }
        }
    }

    pub fn get_events_by_process(&self, pid: u32) -> Vec<&CorrelatedEvent> {
        self.events
            .iter()
            .filter(|e| e.process_id == Some(pid))
            .collect()
    }

    pub fn get_events_in_timerange(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Vec<&CorrelatedEvent> {
        self.events
            .iter()
            .filter(|e| e.timestamp >= start && e.timestamp <= end)
            .collect()
    }

    pub fn get_stats(&self) -> CorrelationStats {
        let mut event_type_counts = HashMap::new();
        for event in &self.events {
            *event_type_counts
                .entry(format!("{:?}", event.event_type))
                .or_insert(0) += 1;
        }

        CorrelationStats {
            total_events: self.events.len(),
            total_chains: self.chains.len(),
            event_type_counts,
            chains_by_severity: self.chains.values().fold(HashMap::new(), |mut acc, chain| {
                *acc.entry(chain.severity.to_string()).or_insert(0) += 1;
                acc
            }),
        }
    }

    pub fn cleanup_old_events(&mut self) {
        let cutoff = Utc::now() - self.time_window * 10;
        self.events.retain(|e| e.timestamp > cutoff);
    }

    pub fn create_incident(
        &mut self,
        title: String,
        description: String,
        severity: Severity,
    ) -> Incident {
        let incident = Incident::new(title, description, severity);
        self.incidents.insert(incident.id.clone(), incident.clone());
        incident
    }

    pub fn get_incident(&self, id: &str) -> Option<&Incident> {
        self.incidents.get(id)
    }

    pub fn get_incidents(&self) -> Vec<&Incident> {
        self.incidents.values().collect()
    }

    pub fn get_active_incidents(&self) -> Vec<&Incident> {
        self.incidents
            .values()
            .filter(|i| !i.state.is_terminal())
            .collect()
    }

    pub fn transition_incident(
        &mut self,
        id: &str,
        next_state: IncidentState,
        actor: String,
        notes: Option<String>,
    ) -> Result<(), String> {
        if let Some(incident) = self.incidents.get_mut(id) {
            incident.transition(next_state, actor, notes)
        } else {
            Err(format!("Incident {} not found", id))
        }
    }

    pub fn link_chain_to_incident(
        &mut self,
        incident_id: &str,
        chain_id: &str,
    ) -> Result<(), String> {
        if let Some(incident) = self.incidents.get_mut(incident_id) {
            if !incident.chain_ids.contains(&chain_id.to_string()) {
                incident.chain_ids.push(chain_id.to_string());
            }
            Ok(())
        } else {
            Err(format!("Incident {} not found", incident_id))
        }
    }

    pub fn get_incident_stats(&self) -> IncidentStats {
        let mut by_state = HashMap::new();
        for incident in self.incidents.values() {
            *by_state.entry(format!("{:?}", incident.state)).or_insert(0) += 1;
        }

        let mut by_severity = HashMap::new();
        for incident in self.incidents.values() {
            *by_severity
                .entry(incident.severity.to_string())
                .or_insert(0) += 1;
        }

        IncidentStats {
            total: self.incidents.len(),
            active: self.get_active_incidents().len(),
            by_state,
            by_severity,
        }
    }
}

impl Default for CorrelationEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Serialize)]
pub struct CorrelationStats {
    pub total_events: usize,
    pub total_chains: usize,
    pub event_type_counts: HashMap<String, usize>,
    pub chains_by_severity: HashMap<String, usize>,
}

#[derive(Debug, Serialize)]
pub struct IncidentStats {
    pub total: usize,
    pub active: usize,
    pub by_state: HashMap<String, usize>,
    pub by_severity: HashMap<String, usize>,
}

fn uuid_simple() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let t = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    format!("{:x}", t.as_nanos())
}
