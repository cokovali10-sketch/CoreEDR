use axum::{
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
};
use std::time::Instant;
use tower_http::trace::TraceLayer;

pub fn create_logging_layer() -> TraceLayer<impl Fn(tower_http::classify::SharedClassifier) -> tower_http::trace::DefaultOnRequest + Clone> {
    TraceLayer::new_for_http()
        .on_request(|request: &Request<axum::body::Body>, _span: &tracing::Span| {
            tracing::info!(
                method = %request.method(),
                path = %request.uri().path(),
                "Request received"
            );
        })
        .on_response(|response: &Response, latency: std::time::Duration, _span: &tracing::Span| {
            tracing::info!(
                status = %response.status().as_u16(),
                latency_ms = %latency.as_millis(),
                "Response sent"
            );
        })
}

pub async fn logging_middleware(
    request: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let start = Instant::now();
    
    let response = next.run(request).await;
    
    let duration = start.elapsed();
    let status = response.status().as_u16();
    
    tracing::info!(
        method = %method,
        path = %path,
        status = status,
        latency_ms = %duration.as_millis(),
        "Request completed"
    );
    
    Ok(response)
}
