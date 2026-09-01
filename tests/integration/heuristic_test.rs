use coreedr::config::DetectionConfig;
use coreedr::heuristic_engine::{HeuristicEngine, Severity, Action};
use coreedr::process_monitor::ProcessInfo;
use std::path::PathBuf;

fn make_detection_config() -> DetectionConfig {
    DetectionConfig {
        enable_heuristic: true,
        enable_signature: true,
        enable_behavioral: false,
        entropy_threshold: 7.5,
        suspicious_api_threshold: 5,
        max_process_chain_depth: 10,
        yara_rules_path: PathBuf::from("./rules"),
    }
}

fn make_process(name: &str, pid: u32, memory: u64, cpu: f64, cmd: &str) -> ProcessInfo {
    ProcessInfo {
        pid,
        name: name.to_string(),
        path: format!("/usr/bin/{}", name),
        command_line: cmd.to_string(),
        parent_pid: 1,
        user: "root".to_string(),
        memory_usage_kb: memory,
        cpu_percent: cpu,
        start_time: chrono::Utc::now(),
        hash: None,
        risk_score: 0,
    }
}

#[test]
fn test_suspicious_process_detected() {
    let config = make_detection_config();
    let mut engine = HeuristicEngine::new(config);
    let proc = make_process("mimikatz", 1234, 50000, 45.0, "mimikatz sekurlsa::logonpasswords");
    let result = engine.analyze(&proc);

    assert!(result.risk_score >= 40, "mimikatz should have high risk score, got {}", result.risk_score);
    assert!(
        matches!(result.severity, Severity::High | Severity::Critical),
        "mimikatz severity should be High or Critical, got {:?}",
        result.severity
    );
    assert!(!result.indicators.is_empty(), "mimikatz should produce indicators");
}

#[test]
fn test_clean_process_low_score() {
    let config = make_detection_config();
    let mut engine = HeuristicEngine::new(config);
    let proc = make_process("bash", 100, 5000, 2.0, "bash --login");
    let result = engine.analyze(&proc);

    assert!(result.risk_score < 30, "bash should have low risk score, got {}", result.risk_score);
    assert!(
        matches!(result.severity, Severity::Info | Severity::Low),
        "bash severity should be Info or Low, got {:?}",
        result.severity
    );
}

#[test]
fn test_severity_mapping() {
    assert_eq!(Severity::from_score(0), Severity::Info);
    assert_eq!(Severity::from_score(10), Severity::Info);
    assert_eq!(Severity::from_score(20), Severity::Info);
    assert_eq!(Severity::from_score(21), Severity::Low);
    assert_eq!(Severity::from_score(40), Severity::Low);
    assert_eq!(Severity::from_score(41), Severity::Medium);
    assert_eq!(Severity::from_score(60), Severity::Medium);
    assert_eq!(Severity::from_score(61), Severity::High);
    assert_eq!(Severity::from_score(80), Severity::High);
    assert_eq!(Severity::from_score(81), Severity::Critical);
    assert_eq!(Severity::from_score(100), Severity::Critical);
}

#[test]
fn test_batch_analysis() {
    let config = make_detection_config();
    let mut engine = HeuristicEngine::new(config);
    let processes = vec![
        make_process("mimikatz", 100, 50000, 40.0, "mimikatz sekurlsa"),
        make_process("bash", 101, 5000, 1.0, "bash"),
        make_process("lazagne", 102, 30000, 30.0, "lazagne all"),
    ];

    let results = engine.batch_analyze(&processes);
    assert_eq!(results.len(), 3);

    let summary = engine.get_threat_summary(&results);
    assert_eq!(summary.total, 3);
    assert!(summary.total_indicators > 0, "Batch analysis should find indicators");
}

#[test]
fn test_high_cpu_process() {
    let config = make_detection_config();
    let mut engine = HeuristicEngine::new(config);
    let proc = make_process("stress", 500, 10000, 95.0, "stress --cpu 4");
    let result = engine.analyze(&proc);

    assert!(
        result.risk_score >= 15,
        "High CPU process should score at least 15, got {}",
        result.risk_score
    );
}

#[test]
fn test_hidden_process_detection() {
    let config = make_detection_config();
    let mut engine = HeuristicEngine::new(config);
    let proc = ProcessInfo {
        pid: 200,
        name: ".hidden_agent".to_string(),
        path: String::new(),
        command_line: String::new(),
        parent_pid: 1,
        user: "nobody".to_string(),
        memory_usage_kb: 1000,
        cpu_percent: 5.0,
        start_time: chrono::Utc::now(),
        hash: None,
        risk_score: 0,
    };
    let result = engine.analyze(&proc);

    assert!(
        result.risk_score >= 20,
        "Hidden process should score at least 20, got {}",
        result.risk_score
    );
}

#[test]
fn test_empty_path_suspicious() {
    let config = make_detection_config();
    let mut engine = HeuristicEngine::new(config);
    let proc = ProcessInfo {
        pid: 300,
        name: "unknown_proc".to_string(),
        path: String::new(),
        command_line: String::new(),
        parent_pid: 1,
        user: "root".to_string(),
        memory_usage_kb: 5000,
        cpu_percent: 10.0,
        start_time: chrono::Utc::now(),
        hash: None,
        risk_score: 0,
    };
    let result = engine.analyze(&proc);

    assert!(
        result.risk_score >= 30,
        "Process with empty path and cmd should score >= 30, got {}",
        result.risk_score
    );
}
