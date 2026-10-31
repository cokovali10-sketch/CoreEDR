use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize)]
pub struct MitreOverview {
    pub total_techniques: usize,
    pub covered_techniques: usize,
    pub coverage_percentage: f64,
    pub total_detections: u32,
    pub tactic_summary: HashMap<String, usize>,
    pub high_confidence_count: usize,
}

#[derive(Serialize)]
pub struct TechniqueInfo {
    pub id: String,
    pub name: String,
    pub tactic: String,
    pub description: String,
    pub detection_hints: Vec<String>,
    pub data_sources: Vec<String>,
    pub platforms: Vec<String>,
}

#[derive(Serialize)]
pub struct MappingResult {
    pub technique_id: String,
    pub tactic: String,
    pub confidence: f64,
    pub evidence: Vec<String>,
    pub timestamp: String,
}

pub async fn mitre_overview() -> Json<MitreOverview> {
    let mapper = crate::mitre::MitreMapper::new();
    let tactic_summary = mapper.get_tactic_summary();
    let total = mapper.get_technique_count();

    Json(MitreOverview {
        total_techniques: total,
        covered_techniques: 0,
        coverage_percentage: 0.0,
        total_detections: 0,
        tactic_summary,
        high_confidence_count: 0,
    })
}

pub async fn mitre_techniques() -> Json<Vec<TechniqueInfo>> {
    let mapper = crate::mitre::MitreMapper::new();
    let mut techniques = Vec::new();

    for tech in mapper.get_techniques_by_tactic(crate::mitre::Tactic::Execution) {
        techniques.push(TechniqueInfo {
            id: tech.id.0.clone(),
            name: tech.name.clone(),
            tactic: tech.tactic.name().to_string(),
            description: tech.description.clone(),
            detection_hints: tech.detection_hints.clone(),
            data_sources: tech.data_sources.clone(),
            platforms: tech.platforms.clone(),
        });
    }

    for tactic in crate::mitre::Tactic::all() {
        for tech in mapper.get_techniques_by_tactic(tactic) {
            if !techniques.iter().any(|t| t.id == tech.id.0) {
                techniques.push(TechniqueInfo {
                    id: tech.id.0.clone(),
                    name: tech.name.clone(),
                    tactic: tech.tactic.name().to_string(),
                    description: tech.description.clone(),
                    detection_hints: tech.detection_hints.clone(),
                    data_sources: tech.data_sources.clone(),
                    platforms: tech.platforms.clone(),
                });
            }
        }
    }

    Json(techniques)
}

#[derive(Deserialize)]
pub struct MapEventRequest {
    pub event_type: String,
    pub severity: String,
    pub source: String,
    pub details: HashMap<String, String>,
}

pub async fn mitre_map_event(Json(payload): Json<MapEventRequest>) -> Json<Vec<MappingResult>> {
    let mapper = crate::mitre::MitreMapper::new();
    let event = crate::mitre::mapper::DetectionEvent {
        event_type: payload.event_type,
        severity: payload.severity,
        source: payload.source,
        details: payload.details,
        timestamp: chrono::Utc::now().to_rfc3339(),
    };

    let mappings = mapper.map_event(&event);
    let results: Vec<MappingResult> = mappings
        .into_iter()
        .map(|m| MappingResult {
            technique_id: m.technique_id,
            tactic: m.tactic,
            confidence: m.confidence,
            evidence: m.evidence,
            timestamp: m.timestamp,
        })
        .collect();

    Json(results)
}
