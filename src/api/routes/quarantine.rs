use axum::{
    extract::{Path, State},
    Json,
};
use serde::Serialize;
use serde_json::{json, Value};

use crate::api::errors::ApiError;
use crate::api::AppState;

#[derive(Debug, Serialize)]
pub struct QuarantineEntry {
    pub id: String,
    pub original_path: String,
    pub quarantine_path: String,
    pub threat_name: String,
    pub threat_level: String,
    pub quarantined_at: String,
    pub file_hash: String,
}

pub async fn list_quarantine(
    State(state): State<AppState>,
) -> Result<Json<Value>, ApiError> {
    let scanner = state.scanner.read().await;
    let entries = scanner.get_quarantine_entries()
        .map_err(|e| ApiError::InternalError(e.to_string()))?;
    
    let response: Vec<Value> = entries.iter().map(|entry| {
        json!(QuarantineEntry {
            id: entry.id.clone(),
            original_path: entry.original_path.clone(),
            quarantine_path: entry.quarantine_path.clone(),
            threat_name: entry.threat_name.clone(),
            threat_level: entry.threat_level.clone(),
            quarantined_at: entry.quarantined_at.to_rfc3339(),
            file_hash: entry.file_hash.clone(),
        })
    }).collect();

    Ok(Json(json!({ "entries": response })))
}

pub async fn get_quarantine_entry(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let scanner = state.scanner.read().await;
    
    let entry = scanner.get_quarantine_entry(&id)
        .ok_or_else(|| ApiError::NotFound(format!("Quarantine entry {} not found", id)))?;
    
    Ok(Json(json!(QuarantineEntry {
        id: entry.id.clone(),
        original_path: entry.original_path.clone(),
        quarantine_path: entry.quarantine_path.clone(),
        threat_name: entry.threat_name.clone(),
        threat_level: entry.threat_level.clone(),
        quarantined_at: entry.quarantined_at.to_rfc3339(),
        file_hash: entry.file_hash.clone(),
    })))
}

pub async fn restore_entry(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let mut scanner = state.scanner.write().await;
    
    scanner.restore_quarantine_entry(&id)
        .map_err(|e| ApiError::InternalError(format!("Failed to restore: {}", e)))?;
    
    Ok(Json(json!({
        "status": "restored",
        "message": format!("Entry {} restored successfully", id)
    })))
}

pub async fn delete_entry(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let mut scanner = state.scanner.write().await;
    
    scanner.delete_quarantine_entry(&id)
        .map_err(|e| ApiError::InternalError(format!("Failed to delete: {}", e)))?;
    
    Ok(Json(json!({
        "status": "deleted",
        "message": format!("Entry {} deleted successfully", id)
    })))
}
