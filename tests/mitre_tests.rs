use crate::mitre::techniques::{TechniqueDatabase, Technique, Tactic};
use crate::mitre::mapper::MitreMapper;
use crate::mitre::matrix::MitreMatrix;
use std::collections::HashMap;

#[test]
fn test_technique_database_new() {
    let db = TechniqueDatabase::new();
    assert!(!db.techniques.is_empty());
    assert!(!db.tactics.is_empty());
}

#[test]
fn test_technique_count() {
    let db = TechniqueDatabase::new();
    assert!(db.techniques.len() >= 30);
    assert!(db.tactics.len() >= 10);
}

#[test]
fn test_get_technique_by_id() {
    let db = TechniqueDatabase::new();
    let technique = db.get_technique("T1059");
    assert!(technique.is_some());
    let technique = technique.unwrap();
    assert_eq!(technique.id, "T1059");
}

#[test]
fn test_mitre_mapper_new() {
    let mapper = MitreMapper::new();
    assert!(mapper.keyword_rules.len() > 0);
}

#[test]
fn test_map_event_to_techniques() {
    let mapper = MitreMapper::new();
    let mut details = HashMap::new();
    details.insert("CommandLine".to_string(), "powershell -encodedcommand".to_string());

    let techniques = mapper.map_event("process_creation", &details);
    assert!(!techniques.is_empty());
}

#[test]
fn test_mitre_matrix() {
    let matrix = MitreMatrix::new();
    let overview = matrix.get_overview();
    assert!(overview.total_techniques > 0);
    assert!(overview.total_tactics > 0);
}
