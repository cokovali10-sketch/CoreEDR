use coreedr::behavioral::analyzer::BehavioralAnalyzer;
use coreedr::behavioral::rules::SuspiciousProcessChain;

#[test]
fn test_behavioral_analyzer_new() {
    let analyzer = BehavioralAnalyzer::new();
    assert_eq!(analyzer.rule_count(), 6);
}

#[test]
fn test_behavioral_analyzer_with_window() {
    let analyzer = BehavioralAnalyzer::with_window(60);
    assert_eq!(analyzer.rule_count(), 6);
}

#[test]
fn test_behavioral_analyze_empty() {
    let analyzer = BehavioralAnalyzer::new();
    let alerts = analyzer.analyze().unwrap();
    assert!(alerts.is_empty());
}

#[test]
fn test_compute_threat_score_empty() {
    let analyzer = BehavioralAnalyzer::new();
    let score = analyzer.compute_threat_score(&[]);
    assert_eq!(score, 0.0);
}