use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use crate::correlation::engine::{CorrelatedEvent, EventType, Severity, CorrelationStats};

#[derive(Serialize)]
pub struct CorrelationOverview {
    pub stats: CorrelationStats,
    pub active_chains: usize,
    pub recent_events_count: usize,
}

#[derive(Deserialize)]
pub struct AddEventRequest {
    pub event_type: String,
    pub process_id: Option<u32>,
    pub process_name: Option<String>,
    pub parent_id: Option<u32>,
    pub user: Option<String>,
    pub details: std::collections::HashMap<String, String>,
}

#[derive(Serialize)]
pub struct EventResponse {
    pub id: String,
    pub timestamp: String,
    pub event_type: String,
    pub process_name: Option<String>,
    pub process_id: Option<u32>,
    pub severity: String,
    pub chain_id: Option<String>,
}

pub async fn correlation_overview() -> Json<CorrelationOverview> {
    Json(CorrelationOverview {
        stats: CorrelationStats {
            total_events: 0,
            total_chains: 0,
            event_type_counts: std::collections::HashMap::new(),
            chains_by_severity: std::collections::HashMap::new(),
        },
        active_chains: 0,
        recent_events_count: 0,
    })
}

pub async fn add_correlated_event(
    Json(payload): Json<AddEventRequest>,
) -> Json<EventResponse> {
    let event_type = match payload.event_type.as_str() {
        "process_creation" => EventType::ProcessCreation,
        "process_termination" => EventType::ProcessTermination,
        "file_creation" => EventType::FileCreation,
        "file_modification" => EventType::FileModification,
        "file_access" => EventType::FileAccess,
        "file_deletion" => EventType::FileDeletion,
        "network_connection" => EventType::NetworkConnection,
        "network_listening" => EventType::NetworkListening,
        "registry_modification" => EventType::RegistryModification,
        "service_creation" => EventType::ServiceCreation,
        "scheduled_task" => EventType::ScheduledTask,
        _ => EventType::Alert,
    };

    let id = format!("evt-{}", chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0));

    Json(EventResponse {
        id,
        timestamp: chrono::Utc::now().to_rfc3339(),
        event_type: payload.event_type,
        process_name: payload.process_name,
        process_id: payload.process_id,
        severity: "medium".into(),
        chain_id: None,
    })
}

pub async fn process_tree(
    axum::extract::Path(pid): axum::extract::Path<u32>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "pid": pid,
        "children": [],
        "depth": 0
    }))
}
