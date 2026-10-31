use axum::{extract::State, Json};
use serde::Serialize;
use serde_json::{json, Value};

use crate::api::errors::ApiError;
use crate::api::AppState;

#[derive(Debug, Serialize)]
pub struct SystemStatus {
    pub version: String,
    pub scanner_running: bool,
    pub uptime_seconds: u64,
    pub real_time_protection: bool,
    pub last_scan_time: Option<String>,
    pub yara_rules_count: u32,
    pub model_loaded: bool,
}

#[derive(Debug, Serialize)]
pub struct ScanStats {
    pub total_scans: u64,
    pub total_files_scanned: u64,
    pub total_threats_found: u64,
    pub total_quarantined: u64,
    pub average_scan_duration_ms: f64,
    pub last_scan_duration_ms: Option<f64>,
}

pub async fn get_status(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    let scanner = state.scanner.read().await;
    let config = state.config.read().await;

    let status = SystemStatus {
        version: env!("CARGO_PKG_VERSION").to_string(),
        scanner_running: scanner.is_running(),
        uptime_seconds: scanner.uptime_seconds(),
        real_time_protection: config.real_time_protection,
        last_scan_time: scanner.last_scan_time().map(|t| t.to_rfc3339()),
        yara_rules_count: scanner.yara_rules_count(),
        model_loaded: scanner.is_model_loaded(),
    };

    Ok(Json(json!(status)))
}

pub async fn get_stats(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    let scanner = state.scanner.read().await;

    let stats = scanner
        .get_stats()
        .map_err(|e| ApiError::InternalError(e.to_string()))?;

    Ok(Json(json!(ScanStats {
        total_scans: stats.total_scans,
        total_files_scanned: stats.total_files_scanned,
        total_threats_found: stats.total_threats_found,
        total_quarantined: stats.total_quarantined,
        average_scan_duration_ms: stats.average_scan_duration_ms,
        last_scan_duration_ms: stats.last_scan_duration_ms,
    })))
}
