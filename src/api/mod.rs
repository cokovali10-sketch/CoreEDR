pub mod routes;
pub mod middleware;
pub mod errors;
pub mod websocket;

use crate::error::CoreError;
use crate::scanner::Scanner;
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct AppState {
    pub scanner: Arc<RwLock<Scanner>>,
    pub config: Arc<RwLock<crate::config::Config>>,
}

pub fn create_router(state: AppState) -> axum::Router {
    use axum::routing::{get, post, put, delete};
    
    axum::Router::new()
        .route("/api/health", get(routes::health::health_check))
        .route("/api/system/status", get(routes::system::get_status))
        .route("/api/system/stats", get(routes::system::get_stats))
        .route("/api/scan", post(routes::scan::start_scan))
        .route("/api/scan/:id", get(routes::scan::get_scan_status))
        .route("/api/quarantine", get(routes::quarantine::list_quarantine))
        .route("/api/quarantine/:id", get(routes::quarantine::get_quarantine_entry))
        .route("/api/quarantine/:id/restore", post(routes::quarantine::restore_entry))
        .route("/api/quarantine/:id", delete(routes::quarantine::delete_entry))
        .route("/api/alerts", get(routes::alerts::list_alerts))
        .route("/api/alerts/:id/acknowledge", post(routes::alerts::acknowledge_alert))
        .route("/api/config", get(routes::config::get_config))
        .route("/api/config", put(routes::config::update_config))
        .route("/api/rules", get(routes::rules::list_rules))
        .route("/api/rules", post(routes::rules::add_rule))
        .route("/api/ws", get(websocket::ws_handler))
        .layer(middleware::logging::create_logging_layer())
        .layer(middleware::auth::create_auth_layer())
        .with_state(state)
}
