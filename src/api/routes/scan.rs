use axum::{
    extract::{Path, State},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::api::errors::ApiError;
use crate::api::AppState;
use crate::scanner::ScanRequest;

#[derive(Debug, Deserialize)]
pub struct StartScanRequest {
    pub path: Option<String>,
    pub recursive: Option<bool>,
    pub scan_type: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ScanResponse {
    pub scan_id: String,
    pub status: String,
    pub message: String,
}

pub async fn start_scan(
    State(state): State<AppState>,
    Json(request): Json<StartScanRequest>,
) -> Result<Json<Value>, ApiError> {
    let scan_id = Uuid::new_v4().to_string();

    let scan_request = ScanRequest {
        path: request.path.unwrap_or_else(|| "/".to_string()),
        recursive: request.recursive.unwrap_or(true),
        scan_type: request.scan_type.unwrap_or_else(|| "full".to_string()),
    };

    let scanner = state.scanner.clone();
    let id = scan_id.clone();

    tokio::spawn(async move {
        let mut scanner = scanner.write().await;
        if let Err(e) = scanner.start_scan(&id, scan_request).await {
            tracing::error!("Scan failed: {}", e);
        }
    });

    Ok(Json(json!(ScanResponse {
        scan_id: scan_id,
        status: "started".to_string(),
        message: "Scan initiated successfully".to_string(),
    })))
}

#[derive(Debug, Serialize)]
pub struct ScanStatus {
    pub scan_id: String,
    pub status: String,
    pub progress: f64,
    pub files_scanned: u64,
    pub threats_found: u32,
    pub start_time: String,
    pub end_time: Option<String>,
}

pub async fn get_scan_status(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let scanner = state.scanner.read().await;

    let scan_info = scanner
        .get_scan_status(&id)
        .ok_or_else(|| ApiError::NotFound(format!("Scan {} not found", id)))?;

    Ok(Json(json!(ScanStatus {
        scan_id: scan_info.id,
        status: scan_info.status.to_string(),
        progress: scan_info.progress,
        files_scanned: scan_info.files_scanned,
        threats_found: scan_info.threats_found,
        start_time: scan_info.start_time.to_rfc3339(),
        end_time: scan_info.end_time.map(|t| t.to_rfc3339()),
    })))
}
