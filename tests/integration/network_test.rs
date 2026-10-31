use coreedr::network::monitor::NetworkMonitor;
use coreedr::network::rules::{NetworkRuleConfig, NetworkRuleEngine};
use std::net::IpAddr;

#[test]
fn test_network_monitor_new() {
    let monitor = NetworkMonitor::new();
    assert!(!monitor.is_running());
    assert!(monitor.get_connections().is_empty());
    assert!(monitor.get_events().is_empty());
}

#[test]
fn test_network_monitor_scan_once() {
    let mut monitor = NetworkMonitor::new();
    let events = monitor.scan_once();
    // scan_once should not panic; result may be Ok or Err depending on OS
    let _ = events;
}

#[test]
fn test_network_rule_engine() {
    let config = NetworkRuleConfig::default();
    let engine = NetworkRuleEngine::new(config);
    let _ = engine;
}
