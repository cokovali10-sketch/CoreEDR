use serde::{Deserialize, Serialize};
use super::engine::{CorrelatedEvent, EventType, Severity};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventTimeline {
    pub events: Vec<TimelineEntry>,
    pub time_range: TimeRange,
    pub process_groups: Vec<ProcessGroup>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEntry {
    pub id: String,
    pub timestamp: String,
    pub event_type: String,
    pub summary: String,
    pub severity: Severity,
    pub process_name: Option<String>,
    pub process_id: Option<u32>,
    pub user: Option<String>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeRange {
    pub start: String,
    pub end: String,
    pub duration_seconds: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessGroup {
    pub pid: u32,
    pub name: String,
    pub user: Option<String>,
    pub events: Vec<TimelineEntry>,
    pub children: Vec<u32>,
}

impl EventTimeline {
    pub fn from_events(events: &[CorrelatedEvent]) -> Self {
        let entries: Vec<TimelineEntry> = events.iter().map(|e| {
            let mut tags = Vec::new();

            if e.process_name.is_some() {
                tags.push("process".into());
            }
            match e.event_type {
                EventType::NetworkConnection | EventType::NetworkListening => {
                    tags.push("network".into());
                }
                EventType::FileAccess | EventType::FileCreation | EventType::FileModification | EventType::FileDeletion => {
                    tags.push("file".into());
                }
                EventType::RegistryModification => {
                    tags.push("registry".into());
                }
                _ => {}
            }

            let summary = Self::generate_summary(e);

            TimelineEntry {
                id: e.id.clone(),
                timestamp: e.timestamp.to_rfc3339(),
                event_type: format!("{:?}", e.event_type),
                summary,
                severity: e.severity.clone(),
                process_name: e.process_name.clone(),
                process_id: e.process_id,
                user: e.user.clone(),
                tags,
            }
        }).collect();

        let time_range = if entries.is_empty() {
            TimeRange {
                start: String::new(),
                end: String::new(),
                duration_seconds: 0,
            }
        } else {
            let start = entries.first()
                .map(|e| e.timestamp.clone())
                .unwrap_or_default();
            let end = entries.last()
                .map(|e| e.timestamp.clone())
                .unwrap_or_default();
            let first_ts = chrono::DateTime::parse_from_rfc3339(&start)
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .unwrap_or_else(|_| chrono::Utc::now());
            let last_ts = chrono::DateTime::parse_from_rfc3339(&end)
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .unwrap_or_else(|_| chrono::Utc::now());
            let duration = last_ts.signed_duration_since(first_ts).num_seconds();

            TimeRange {
                start,
                end,
                duration_seconds: duration,
            }
        };

        let process_groups = Self::group_by_process(events);

        EventTimeline {
            events: entries,
            time_range,
            process_groups,
        }
    }

    fn generate_summary(event: &CorrelatedEvent) -> String {
        match event.event_type {
            EventType::ProcessCreation => {
                let name = event.process_name.as_deref().unwrap_or("unknown");
                let pid = event.process_id.map(|p| p.to_string()).unwrap_or_default();
                format!("Process '{}' started (PID: {})", name, pid)
            }
            EventType::ProcessTermination => {
                let name = event.process_name.as_deref().unwrap_or("unknown");
                format!("Process '{}' terminated", name)
            }
            EventType::FileCreation => {
                let path = event.details.get("file_path").map(|s| s.as_str()).unwrap_or("unknown");
                format!("File created: {}", path)
            }
            EventType::FileModification => {
                let path = event.details.get("file_path").map(|s| s.as_str()).unwrap_or("unknown");
                format!("File modified: {}", path)
            }
            EventType::FileAccess => {
                let path = event.details.get("file_path").map(|s| s.as_str()).unwrap_or("unknown");
                format!("File accessed: {}", path)
            }
            EventType::FileDeletion => {
                let path = event.details.get("file_path").map(|s| s.as_str()).unwrap_or("unknown");
                format!("File deleted: {}", path)
            }
            EventType::NetworkConnection => {
                let ip = event.details.get("remote_ip").map(|s| s.as_str()).unwrap_or("unknown");
                let port = event.details.get("remote_port").map(|s| s.as_str()).unwrap_or("?");
                format!("Network connection to {}:{}", ip, port)
            }
            EventType::NetworkListening => {
                let port = event.details.get("port").map(|s| s.as_str()).unwrap_or("?");
                format!("Listening on port {}", port)
            }
            EventType::RegistryModification => {
                let key = event.details.get("registry_key").map(|s| s.as_str()).unwrap_or("unknown");
                format!("Registry modified: {}", key)
            }
            EventType::ServiceCreation => {
                let name = event.details.get("service_name").map(|s| s.as_str()).unwrap_or("unknown");
                format!("Service created: {}", name)
            }
            EventType::ScheduledTask => {
                let name = event.details.get("task_name").map(|s| s.as_str()).unwrap_or("unknown");
                format!("Scheduled task created: {}", name)
            }
            EventType::Alert => {
                let msg = event.details.get("message").map(|s| s.as_str()).unwrap_or("Alert triggered");
                format!("Alert: {}", msg)
            }
        }
    }

    fn group_by_process(events: &[CorrelatedEvent]) -> Vec<ProcessGroup> {
        let mut groups: std::collections::HashMap<u32, Vec<&CorrelatedEvent>> = std::collections::HashMap::new();

        for event in events {
            if let Some(pid) = event.process_id {
                groups.entry(pid).or_insert_with(Vec::new).push(event);
            }
        }

        groups.into_iter().map(|(pid, proc_events)| {
            let name = proc_events.first()
                .and_then(|e| e.process_name.clone())
                .unwrap_or_else(|| "unknown".into());
            let user = proc_events.first()
                .and_then(|e| e.user.clone());

            let entries: Vec<TimelineEntry> = proc_events.iter().map(|e| {
                TimelineEntry {
                    id: e.id.clone(),
                    timestamp: e.timestamp.to_rfc3339(),
                    event_type: format!("{:?}", e.event_type),
                    summary: Self::generate_summary(e),
                    severity: e.severity.clone(),
                    process_name: e.process_name.clone(),
                    process_id: e.process_id,
                    user: e.user.clone(),
                    tags: Vec::new(),
                }
            }).collect();

            ProcessGroup {
                pid,
                name,
                user,
                events: entries,
                children: Vec::new(),
            }
        }).collect()
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }
}
