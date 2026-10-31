use coreedr::logger::{EventCategory, LogLevel, SecurityLogger};

#[test]
fn test_logger_creation() {
    let tmp = tempfile::tempdir().unwrap();
    let log_path = tmp.path().join("test.log");
    let logger = SecurityLogger::new(&log_path, false);
    assert!(logger.is_ok(), "Logger should create without error");
}

#[test]
fn test_log_write() {
    let tmp = tempfile::tempdir().unwrap();
    let log_path = tmp.path().join("test.log");
    let logger = SecurityLogger::new(&log_path, false).unwrap();

    logger.info(EventCategory::System, "test", "Info message");
    logger.warning(EventCategory::ProcessMonitor, "test", "Warning message");
    logger.error(EventCategory::Containment, "test", "Error message");
    logger.critical(EventCategory::HeuristicAnalysis, "test", "Critical message");

    let stats = logger.get_stats();
    assert_eq!(stats.total_events, 4);
    assert_eq!(stats.info_count, 1);
    assert_eq!(stats.warning_count, 1);
    assert_eq!(stats.error_count, 1);
    assert_eq!(stats.critical_count, 1);
}

#[test]
fn test_json_format() {
    let tmp = tempfile::tempdir().unwrap();
    let log_path = tmp.path().join("json_test.log");
    let logger = SecurityLogger::new(&log_path, true).unwrap();

    logger.info(EventCategory::System, "test", "JSON test event");

    let content = std::fs::read_to_string(&log_path).unwrap();
    assert!(
        content.contains("\"level\":\"Info\""),
        "JSON log should contain level field"
    );
    assert!(
        content.contains("\"category\":\"System\""),
        "JSON log should contain category field"
    );
    assert!(
        content.contains("JSON test event"),
        "JSON log should contain message"
    );
}

#[test]
fn test_text_format() {
    let tmp = tempfile::tempdir().unwrap();
    let log_path = tmp.path().join("text_test.log");
    let logger = SecurityLogger::new(&log_path, false).unwrap();

    logger.info(EventCategory::System, "test", "Text test event");

    let content = std::fs::read_to_string(&log_path).unwrap();
    assert!(
        content.contains("INFO"),
        "Text log should contain INFO level"
    );
    assert!(
        content.contains("Text test event"),
        "Text log should contain message"
    );
}

#[test]
fn test_recent_events() {
    let tmp = tempfile::tempdir().unwrap();
    let log_path = tmp.path().join("recent_test.log");
    let logger = SecurityLogger::new(&log_path, false).unwrap();

    for i in 0..10 {
        logger.info(EventCategory::System, "test", &format!("Event {}", i));
    }

    let recent = logger.get_recent_events(5);
    assert_eq!(recent.len(), 5);
    assert_eq!(
        recent[0].message, "Event 9",
        "Most recent event should be last written"
    );
}

#[test]
fn test_events_by_level() {
    let tmp = tempfile::tempdir().unwrap();
    let log_path = tmp.path().join("level_test.log");
    let logger = SecurityLogger::new(&log_path, false).unwrap();

    logger.info(EventCategory::System, "test", "info 1");
    logger.info(EventCategory::System, "test", "info 2");
    logger.warning(EventCategory::System, "test", "warn 1");
    logger.error(EventCategory::System, "test", "err 1");

    let warnings = logger.get_events_by_level(LogLevel::Warning);
    assert_eq!(warnings.len(), 1);

    let infos = logger.get_events_by_level(LogLevel::Info);
    assert_eq!(infos.len(), 2);

    let errors = logger.get_events_by_level(LogLevel::Error);
    assert_eq!(errors.len(), 1);
}

#[test]
fn test_logger_with_pid_and_score() {
    let tmp = tempfile::tempdir().unwrap();
    let log_path = tmp.path().join("pid_test.log");
    let logger = SecurityLogger::new(&log_path, false).unwrap();

    logger.log(
        LogLevel::Warning,
        EventCategory::HeuristicAnalysis,
        "scanner",
        "Suspicious process found",
        Some("Detailed info".to_string()),
        Some(42),
        Some(75),
    );

    let content = std::fs::read_to_string(&log_path).unwrap();
    assert!(content.contains("[PID:42]"), "Should contain PID info");
    assert!(content.contains("score=75"), "Should contain risk score");
    assert!(content.contains("Detailed info"), "Should contain details");
}
