use coreedr::alert::AlertManager;
use coreedr::heuristic_engine::{AnalysisResult, Severity, Action};
use coreedr::logger::{SecurityLogger, EventCategory};
use coreedr::process_monitor::ProcessInfo;

fn make_result(name: &str, pid: u32, score: u32) -> AnalysisResult {
    AnalysisResult {
        process: ProcessInfo {
            pid,
            name: name.to_string(),
            path: format!("/usr/bin/{}", name),
            command_line: String::new(),
            parent_pid: 1,
            user: "root".to_string(),
            memory_usage_kb: 10000,
            cpu_percent: 5.0,
            start_time: chrono::Utc::now(),
            hash: None,
            risk_score: score,
            chain_depth: 0,
            root_pid: 1,
        },
        risk_score: score,
        severity: Severity::from_score(score),
        indicators: Vec::new(),
        recommended_action: Action::Alert,
        analysis_time_ms: 10,
    }
}

fn make_logger() -> (SecurityLogger, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let log_path = tmp.path().join("test.log");
    let logger = SecurityLogger::new(&log_path, false).unwrap();
    (logger, tmp)
}

#[test]
fn test_alert_generation() {
    let (logger, _tmp) = make_logger();
    let mut manager = AlertManager::new(100, 0);
    let result = make_result("mimikatz", 1234, 85);

    let alert = manager.process_analysis(&result, &logger);
    assert!(alert.is_some(), "High-risk process should generate an alert");

    let alert = alert.unwrap();
    assert_eq!(alert.process_name, "mimikatz");
    assert_eq!(alert.process_pid, 1234);
    assert_eq!(alert.risk_score, 85);
    assert!(!alert.acknowledged);
    assert!(alert.id.starts_with("ALERT-"));
}

#[test]
fn test_alert_cooldown() {
    let (logger, _tmp) = make_logger();
    let mut manager = AlertManager::new(100, 300);
    let result = make_result("bad_process", 5555, 70);

    let alert1 = manager.process_analysis(&result, &logger);
    assert!(alert1.is_some(), "First alert should be generated");

    let alert2 = manager.process_analysis(&result, &logger);
    assert!(alert2.is_none(), "Second alert should be suppressed by cooldown");
}

#[test]
fn test_alert_acknowledgment() {
    let (logger, _tmp) = make_logger();
    let mut manager = AlertManager::new(100, 0);
    let result = make_result("suspicious_tool", 8888, 75);

    let alert = manager.process_analysis(&result, &logger).unwrap();
    assert!(!alert.acknowledged);

    let ack_result = manager.acknowledge(&alert.id);
    assert!(ack_result, "Acknowledge should return true for valid alert id");

    let alerts = manager.get_all_alerts();
    assert!(alerts[0].acknowledged, "Alert should be marked acknowledged");

    let active = manager.get_active_alerts();
    assert!(active.is_empty(), "No active alerts after acknowledgment");
}

#[test]
fn test_alert_severity_filter() {
    let (logger, _tmp) = make_logger();
    let mut manager = AlertManager::new(100, 0);

    manager.process_analysis(&make_result("high_proc", 1, 80), &logger);
    manager.process_analysis(&make_result("med_proc", 2, 50), &logger);
    manager.process_analysis(&make_result("high_proc2", 3, 75), &logger);

    let high_alerts = manager.get_alerts_by_severity(&Severity::High);
    assert_eq!(high_alerts.len(), 2, "Should have 2 High severity alerts");

    let med_alerts = manager.get_alerts_by_severity(&Severity::Medium);
    assert_eq!(med_alerts.len(), 1, "Should have 1 Medium severity alert");
}

#[test]
fn test_alert_stats() {
    let (logger, _tmp) = make_logger();
    let mut manager = AlertManager::new(100, 0);

    manager.process_analysis(&make_result("crit", 1, 95), &logger);
    manager.process_analysis(&make_result("high", 2, 70), &logger);

    let stats = manager.get_stats();
    assert_eq!(stats.total, 2);
    assert_eq!(stats.critical, 1);
    assert_eq!(stats.high, 1);
}

#[test]
fn test_low_severity_no_alert() {
    let (logger, _tmp) = make_logger();
    let mut manager = AlertManager::new(100, 0);
    let result = make_result("normal_proc", 1000, 15);

    let alert = manager.process_analysis(&result, &logger);
    assert!(alert.is_none(), "Low severity should not generate an alert");
}

#[test]
fn test_max_alerts_limit() {
    let (logger, _tmp) = make_logger();
    let mut manager = AlertManager::new(2, 0);

    manager.process_analysis(&make_result("p1", 1, 70), &logger);
    manager.process_analysis(&make_result("p2", 2, 75), &logger);
    manager.process_analysis(&make_result("p3", 3, 80), &logger);

    assert_eq!(manager.get_all_alerts().len(), 2, "Should cap at max_alerts");
}

#[test]
fn test_clear_acknowledged() {
    let (logger, _tmp) = make_logger();
    let mut manager = AlertManager::new(100, 0);

    let alert = manager.process_analysis(&make_result("ack_test", 1, 70), &logger).unwrap();
    manager.acknowledge(&alert.id);
    manager.clear_acknowledged();

    assert!(manager.get_all_alerts().is_empty(), "Acknowledged alerts should be cleared");
}
