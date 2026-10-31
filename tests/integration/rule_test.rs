use coreedr::config::RulesConfig;
use coreedr::rule_engine::{RuleEngine, Rule, RuleCondition};
use coreedr::heuristic_engine::{AnalysisResult, Severity, Action};
use coreedr::process_monitor::ProcessInfo;

fn make_rules_config() -> RulesConfig {
    RulesConfig {
        rules_dir: std::env::temp_dir(),
        custom_signatures: vec![],
        blacklisted_hashes: vec!["abc123deadbeef".to_string()],
        blacklisted_names: vec!["mimikatz".to_string()],
        whitelisted_hashes: vec![],
        whitelisted_names: vec!["bash".to_string()],
    }
}

fn make_test_process(name: &str) -> ProcessInfo {
    ProcessInfo {
        pid: 1234,
        name: name.to_string(),
        path: format!("/usr/bin/{}", name),
        command_line: format!("{} --test", name),
        parent_pid: 1,
        user: "root".to_string(),
        memory_usage_kb: 10000,
        cpu_percent: 5.0,
        start_time: chrono::Utc::now(),
        hash: None,
        risk_score: 0,
        chain_depth: 0,
        root_pid: 1,
    }
}

fn make_result(process: &ProcessInfo) -> AnalysisResult {
    AnalysisResult {
        process: process.clone(),
        risk_score: 0,
        severity: Severity::Info,
        indicators: Vec::new(),
        recommended_action: Action::Allow,
        analysis_time_ms: 0,
    }
}

#[test]
fn test_rule_engine_creation() {
    let config = make_rules_config();
    let engine = RuleEngine::new(&config);
    assert!(engine.is_ok(), "RuleEngine should create successfully");

    let engine = engine.unwrap();
    assert!(!engine.get_rules().is_empty(), "Engine should have built-in rules");
}

#[test]
fn test_blacklist_detection() {
    let config = make_rules_config();
    let engine = RuleEngine::new(&config).unwrap();
    let proc = make_test_process("mimikatz");
    let mut result = make_result(&proc);

    engine.check_process(&proc, &mut result);

    assert_eq!(result.risk_score, 100, "Blacklisted process should score 100");
    assert_eq!(result.severity, Severity::Critical);
    assert!(!result.indicators.is_empty());
}

#[test]
fn test_whitelist_bypass() {
    let config = make_rules_config();
    let engine = RuleEngine::new(&config).unwrap();
    let proc = make_test_process("bash");
    let mut result = make_result(&proc);

    engine.check_process(&proc, &mut result);

    assert_eq!(result.risk_score, 0, "Whitelisted process should not be flagged");
    assert!(result.indicators.is_empty());
}

#[test]
fn test_custom_rule_add() {
    let config = make_rules_config();
    let mut engine = RuleEngine::new(&config).unwrap();
    let initial_count = engine.get_rules().len();

    let custom_rule = Rule {
        name: "detect_suspicious_tool".to_string(),
        description: "Detects a custom suspicious tool".to_string(),
        severity: Severity::High,
        condition: RuleCondition::NameContains("suspicious_tool".to_string()),
        enabled: true,
    };

    engine.add_rule(custom_rule);
    assert_eq!(engine.get_rules().len(), initial_count + 1);

    let proc = make_test_process("suspicious_tool");
    let mut result = make_result(&proc);
    engine.check_process(&proc, &mut result);

    assert!(
        result.risk_score > 0,
        "Custom rule should flag suspicious_tool"
    );
    assert!(
        result.indicators.iter().any(|i| i.indicator_type == "rule_match"),
        "Should have rule_match indicator"
    );
}

#[test]
fn test_rule_disable() {
    let config = make_rules_config();
    let mut engine = RuleEngine::new(&config).unwrap();

    let disabled_rule = Rule {
        name: "disabled_test_rule".to_string(),
        description: "Disabled rule".to_string(),
        severity: Severity::Critical,
        condition: RuleCondition::NameContains("should_not_match".to_string()),
        enabled: false,
    };

    engine.add_rule(disabled_rule);
    engine.disable_rule("disabled_test_rule");

    let proc = make_test_process("should_not_match");
    let mut result = make_result(&proc);
    engine.check_process(&proc, &mut result);

    assert_eq!(result.risk_score, 0, "Disabled rule should not affect score");
}

#[test]
fn test_rule_remove() {
    let config = make_rules_config();
    let mut engine = RuleEngine::new(&config).unwrap();
    let initial_count = engine.get_rules().len();

    engine.add_rule(Rule {
        name: "temp_rule".to_string(),
        description: "Temporary".to_string(),
        severity: Severity::Low,
        condition: RuleCondition::NameContains("temp".to_string()),
        enabled: true,
    });

    assert_eq!(engine.get_rules().len(), initial_count + 1);
    assert!(engine.remove_rule("temp_rule"));
    assert_eq!(engine.get_rules().len(), initial_count);
    assert!(!engine.remove_rule("temp_rule"), "Removing nonexistent rule should return false");
}

#[test]
fn test_blacklisted_hash() {
    let config = make_rules_config();
    let engine = RuleEngine::new(&config).unwrap();
    let mut proc = make_test_process("legit_process");
    proc.hash = Some("abc123deadbeef".to_string());
    let mut result = make_result(&proc);

    engine.check_process(&proc, &mut result);

    assert_eq!(result.risk_score, 100, "Blacklisted hash should score 100");
    assert_eq!(result.severity, Severity::Critical);
}
