use axum::{
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
};
use tower_http::validate_request::ValidateRequestHeaderLayer;

use crate::api::AppState;

const API_KEY_HEADER: &str = "X-API-Key";

pub fn create_auth_layer() -> ValidateRequestHeaderLayer<impl Fn(&mut Request<axum::body::Body>) -> bool + Clone> {
    ValidateRequestHeaderLayer::custom(|request: &mut Request<axum::body::Body>| {
        let path = request.uri().path();
        
        if path == "/api/health" {
            return true;
        }
        
        let headers = request.headers();
        let api_key = headers
            .get(API_KEY_HEADER)
            .and_then(|value| value.to_str().ok());
        
        match api_key {
            Some(key) => {
                let expected_key = std::env::var("COREEDR_API_KEY")
                    .unwrap_or_else(|_| "default-dev-key".to_string());
                key == expected_key
            }
            None => false,
        }
    })
}

pub async fn auth_middleware(
    request: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let path = request.uri().path();
    
    if path == "/api/health" {
        return Ok(next.run(request).await);
    }
    
    let api_key = request
        .headers()
        .get(API_KEY_HEADER)
        .and_then(|value| value.to_str().ok());
    
    match api_key {
        Some(key) => {
            let expected_key = std::env::var("COREEDR_API_KEY")
                .unwrap_or_else(|_| "default-dev-key".to_string());
            
            if key == expected_key {
                Ok(next.run(request).await)
            } else {
                Err(StatusCode::UNAUTHORIZED)
            }
        }
        None => Err(StatusCode::UNAUTHORIZED),
    }
}
