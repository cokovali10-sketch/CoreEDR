use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::api::errors::ApiError;
use crate::api::AppState;

#[derive(Debug, Deserialize)]
pub struct AlertFilter {
    pub severity: Option<String>,
    pub acknowledged: Option<bool>,
    pub limit: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct AlertEntry {
    pub id: String,
    pub severity: String,
    pub title: String,
    pub description: String,
    pub source: String,
    pub created_at: String,
    pub acknowledged: bool,
    pub acknowledged_at: Option<String>,
}

pub async fn list_alerts(
    State(state): State<AppState>,
    Query(filter): Query<AlertFilter>,
) -> Result<Json<Value>, ApiError> {
    let scanner = state.scanner.read().await;
    
    let alerts = scanner.get_alerts(
        filter.severity.as_deref(),
        filter.acknowledged,
        filter.limit.unwrap_or(100),
    ).map_err(|e| ApiError::InternalError(e.to_string()))?;
    
    let response: Vec<Value> = alerts.iter().map(|alert| {
        json!(AlertEntry {
            id: alert.id.clone(),
            severity: alert.severity.to_string(),
            title: alert.title.clone(),
            description: alert.description.clone(),
            source: alert.source.clone(),
            created_at: alert.created_at.to_rfc3339(),
            acknowledged: alert.acknowledged,
            acknowledged_at: alert.acknowledged_at.map(|t| t.to_rfc3339()),
        })
    }).collect();

    Ok(Json(json!({ "alerts": response, "count": response.len() })))
}

pub async fn acknowledge_alert(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let mut scanner = state.scanner.write().await;
    
    scanner.acknowledge_alert(&id)
        .map_err(|e| ApiError::InternalError(format!("Failed to acknowledge: {}", e)))?;
    
    Ok(Json(json!({
        "status": "acknowledged",
        "message": format!("Alert {} acknowledged", id)
    })))
}
