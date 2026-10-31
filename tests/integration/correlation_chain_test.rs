use coreedr::correlation::chain::{build_chain_from_events, ChainBuilder, ChainLink, ChainNode};
use coreedr::correlation::engine::{CorrelatedEvent, EventType, Severity};
use std::collections::HashMap;

#[test]
fn test_chain_builder() {
    let chain = ChainBuilder::new("chain-1")
        .name("Test Chain")
        .description("desc")
        .severity(Severity::High)
        .build();
    assert_eq!(chain.id, "chain-1");
    assert_eq!(chain.name, "Test Chain");
}

#[test]
fn test_build_chain_from_events_empty() {
    let events: Vec<CorrelatedEvent> = vec![];
    let result = build_chain_from_events(&events, "chain-2");
    assert!(result.is_none());
}
