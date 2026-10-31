use coreedr::mitre::mapper::{DetectionEvent, MitreMapper};
use coreedr::mitre::matrix::MitreMatrix;
use coreedr::mitre::techniques::{build_technique_database, Tactic, Technique};
use std::collections::HashMap;

#[test]
fn test_technique_database() {
    let db = build_technique_database();
    assert!(!db.is_empty());
    assert!(db.len() >= 20);
}

#[test]
fn test_get_technique_by_id() {
    let db = build_technique_database();
    let technique = db.values().find(|t| t.id.0 == "T1059");
    assert!(technique.is_some());
    let technique = technique.unwrap();
    assert_eq!(technique.id.0, "T1059");
}

#[test]
fn test_mitre_mapper_new() {
    let mapper = MitreMapper::new();
    // keyword_map is private; just ensure construction succeeds
    let _ = mapper;
}

#[test]
fn test_map_event_to_techniques() {
    let mapper = MitreMapper::new();
    let mut details = HashMap::new();
    details.insert(
        "CommandLine".to_string(),
        "powershell -encodedcommand".to_string(),
    );

    let event = DetectionEvent {
        event_type: "process_creation".to_string(),
        severity: "high".to_string(),
        source: "coreedr".to_string(),
        details,
        timestamp: chrono::Utc::now().to_rfc3339(),
    };

    let techniques = mapper.map_event(&event);
    assert!(!techniques.is_empty());
}

#[test]
fn test_mitre_matrix() {
    let matrix = MitreMatrix::new();
    assert!(matrix.total_techniques > 0);
    assert!(matrix.tactics.len() >= 10);
    assert!(matrix.get_coverage_percentage() >= 0.0);
}
