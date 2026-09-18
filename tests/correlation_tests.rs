use crate::correlation::engine::{CorrelationEngine, EventType, Severity};
use crate::correlation::chain::{ChainBuilder, build_chain_from_events};
use crate::correlation::timeline::EventTimeline;
use std::collections::HashMap;

#[test]
fn test_correlation_engine_new() {
    let engine = CorrelationEngine::new();
    let stats = engine.get_stats();
    assert_eq!(stats.total_events, 0);
    assert_eq!(stats.total_chains, 0);
}

#[test]
fn test_add_event() {
    let mut engine = CorrelationEngine::new();
    let event = crate::correlation::engine::CorrelatedEvent {
        id: "test-1".to_string(),
        timestamp: chrono::Utc::now(),
        event_type: EventType::ProcessCreation,
        process_id: Some(1234),
        process_name: Some("test.exe".to_string()),
        parent_id: None,
        user: Some("root".to_string()),
        details: HashMap::new(),
        severity: Severity::Medium,
    };
    engine.add_event(event);
    let stats = engine.get_stats();
    assert_eq!(stats.total_events, 1);
}

#[test]
fn test_chain_builder() {
    let chain = ChainBuilder::new("chain-1")
        .name("Test Chain")
        .description("A test chain")
        .severity(Severity::High)
        .kill_chain_phase("Execution")
        .mitre_technique("T1059", "Execution", 0.8)
        .indicator("suspicious_process")
        .build();

    assert_eq!(chain.id, "chain-1");
    assert_eq!(chain.name, "Test Chain");
    assert_eq!(chain.severity, Severity::High);
    assert_eq!(chain.mitre_techniques.len(), 1);
    assert_eq!(chain.indicators.len(), 1);
}

#[test]
fn test_build_chain_from_events() {
    let events = vec![
        crate::correlation::engine::CorrelatedEvent {
            id: "evt-1".to_string(),
            timestamp: chrono::Utc::now(),
            event_type: EventType::ProcessCreation,
            process_id: Some(100),
            process_name: Some("parent.exe".to_string()),
            parent_id: None,
            user: Some("user1".to_string()),
            details: HashMap::new(),
            severity: Severity::Low,
        },
        crate::correlation::engine::CorrelatedEvent {
            id: "evt-2".to_string(),
            timestamp: chrono::Utc::now(),
            event_type: EventType::ProcessCreation,
            process_id: Some(101),
            process_name: Some("child.exe".to_string()),
            parent_id: Some(100),
            user: Some("user1".to_string()),
            details: HashMap::new(),
            severity: Severity::High,
        },
    ];

    let chain = build_chain_from_events(&events, "chain-test");
    assert!(chain.is_some());
    let chain = chain.unwrap();
    assert_eq!(chain.nodes.len(), 2);
    assert_eq!(chain.links.len(), 1);
}

#[test]
fn test_event_timeline() {
    let events = vec![
        crate::correlation::engine::CorrelatedEvent {
            id: "evt-1".to_string(),
            timestamp: chrono::Utc::now(),
            event_type: EventType::ProcessCreation,
            process_id: Some(100),
            process_name: Some("test.exe".to_string()),
            parent_id: None,
            user: Some("user1".to_string()),
            details: HashMap::new(),
            severity: Severity::Info,
        },
    ];

    let timeline = EventTimeline::from_events(&events);
    assert_eq!(timeline.events.len(), 1);
    assert!(!timeline.events[0].summary.is_empty());
}
