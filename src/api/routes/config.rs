use axum::{
    extract::State,
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::api::errors::ApiError;
use crate::api::AppState;

#[derive(Debug, Serialize, Deserialize)]
pub struct ConfigResponse {
    pub scan_paths: Vec<String>,
    pub scan_interval_seconds: u64,
    pub real_time_protection: bool,
    pub quarantine_on_threat: bool,
    pub notifications_enabled: bool,
    pub log_level: String,
    pub auto_update: bool,
    pub update_interval_hours: u64,
}

#[derive(Debug, Deserialize)]
pub struct UpdateConfigRequest {
    pub scan_paths: Option<Vec<String>>,
    pub scan_interval_seconds: Option<u64>,
    pub real_time_protection: Option<bool>,
    pub quarantine_on_threat: Option<bool>,
    pub notifications_enabled: Option<bool>,
    pub log_level: Option<String>,
    pub auto_update: Option<bool>,
    pub update_interval_hours: Option<u64>,
}

pub async fn get_config(
    State(state): State<AppState>,
) -> Result<Json<Value>, ApiError> {
    let config = state.config.read().await;
    
    Ok(Json(json!(ConfigResponse {
        scan_paths: config.scan_paths.clone(),
        scan_interval_seconds: config.scan_interval_seconds,
        real_time_protection: config.real_time_protection,
        quarantine_on_threat: config.quarantine_on_threat,
        notifications_enabled: config.notifications_enabled,
        log_level: config.log_level.clone(),
        auto_update: config.auto_update,
        update_interval_hours: config.update_interval_hours,
    })))
}

pub async fn update_config(
    State(state): State<AppState>,
    Json(request): Json<UpdateConfigRequest>,
) -> Result<Json<Value>, ApiError> {
    let mut config = state.config.write().await;
    
    if let Some(paths) = request.scan_paths {
        config.scan_paths = paths;
    }
    if let Some(interval) = request.scan_interval_seconds {
        config.scan_interval_seconds = interval;
    }
    if let Some(protection) = request.real_time_protection {
        config.real_time_protection = protection;
    }
    if let Some(quarantine) = request.quarantine_on_threat {
        config.quarantine_on_threat = quarantine;
    }
    if let Some(notifications) = request.notifications_enabled {
        config.notifications_enabled = notifications;
    }
    if let Some(level) = request.log_level {
        config.log_level = level;
    }
    if let Some(auto_update) = request.auto_update {
        config.auto_update = auto_update;
    }
    if let Some(interval) = request.update_interval_hours {
        config.update_interval_hours = interval;
    }
    
    config.save()
        .map_err(|e| ApiError::InternalError(format!("Failed to save config: {}", e)))?;
    
    Ok(Json(json!({
        "status": "updated",
        "message": "Configuration updated successfully"
    })))
}
