use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::api::errors::ApiError;
use crate::api::AppState;

#[derive(Debug, Serialize)]
pub struct RuleEntry {
    pub id: String,
    pub name: String,
    pub rule_type: String,
    pub content: String,
    pub enabled: bool,
    pub created_at: String,
    pub author: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AddRuleRequest {
    pub name: String,
    pub rule_type: String,
    pub content: String,
    pub enabled: Option<bool>,
    pub author: Option<String>,
}

pub async fn list_rules(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    let scanner = state.scanner.read().await;

    let rules = scanner
        .get_rules()
        .map_err(|e| ApiError::InternalError(e.to_string()))?;

    let response: Vec<Value> = rules
        .iter()
        .map(|rule| {
            json!(RuleEntry {
                id: rule.id.clone(),
                name: rule.name.clone(),
                rule_type: rule.rule_type.clone(),
                content: rule.content.clone(),
                enabled: rule.enabled,
                created_at: rule.created_at.to_rfc3339(),
                author: rule.author.clone(),
            })
        })
        .collect();

    Ok(Json(json!({ "rules": response, "count": response.len() })))
}

pub async fn add_rule(
    State(state): State<AppState>,
    Json(request): Json<AddRuleRequest>,
) -> Result<Json<Value>, ApiError> {
    let mut scanner = state.scanner.write().await;

    let rule_id = scanner
        .add_rule(
            &request.name,
            &request.rule_type,
            &request.content,
            request.enabled.unwrap_or(true),
            request.author.as_deref(),
        )
        .map_err(|e| ApiError::InternalError(format!("Failed to add rule: {}", e)))?;

    Ok(Json(json!({
        "status": "added",
        "rule_id": rule_id,
        "message": format!("Rule '{}' added successfully", request.name)
    })))
}
