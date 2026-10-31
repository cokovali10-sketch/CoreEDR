use axum::body::Body;
use axum::http::Request;
use axum::http::StatusCode;
use tower::ServiceExt;

#[tokio::test]
async fn test_health_endpoint() {
    let app = create_test_app();
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_stats_endpoint() {
    let app = create_test_app();
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/stats")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_mitre_overview_endpoint() {
    let app = create_test_app();
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/mitre/overview")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_correlation_overview_endpoint() {
    let app = create_test_app();
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/correlation/overview")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

fn create_test_app() -> axum::Router {
    use coreedr::api::AppState;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    let config = coreedr::config::Config::default_config();
    let scanner = coreedr::scanner::Scanner::new(config.clone()).unwrap();

    let state = AppState {
        scanner: Arc::new(RwLock::new(scanner)),
        config: Arc::new(RwLock::new(config)),
    };

    coreedr::api::create_router(state)
}
