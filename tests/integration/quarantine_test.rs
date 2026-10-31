use coreedr::containment::ContainmentEngine;
use coreedr::heuristic_engine::Action;
use coreedr::logger::{EventCategory, SecurityLogger};
use std::fs;

fn make_quarantine_engine() -> (ContainmentEngine, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let qpath = tmp.path().join("quarantine");
    fs::create_dir_all(&qpath).unwrap();
    let engine = ContainmentEngine::new(qpath, true, true, 60);
    (engine, tmp)
}

#[test]
fn test_quarantine_add_and_list() {
    let (mut engine, _tmp) = make_quarantine_engine();
    let log_path = _tmp.path().join("test.log");
    let logger = SecurityLogger::new(&log_path, false).unwrap();

    let action = engine.execute_action(9999, "test_process", Action::Quarantine, &logger);

    assert!(
        matches!(
            action.result,
            coreedr::containment::ContainmentResult::Success
        ),
        "Quarantine action should succeed"
    );

    let list = engine.get_quarantine_list();
    assert!(
        !list.is_empty(),
        "Quarantine list should have at least one entry"
    );
    assert!(
        list.iter().any(|f| f.contains("test_process")),
        "Quarantine list should contain our test process"
    );
}

#[test]
fn test_quarantine_list_empty() {
    let (engine, _tmp) = make_quarantine_engine();
    let list = engine.get_quarantine_list();
    assert!(
        list.is_empty(),
        "Fresh quarantine directory should be empty"
    );
}

#[test]
fn test_quarantine_multiple_entries() {
    let (mut engine, _tmp) = make_quarantine_engine();
    let log_path = _tmp.path().join("test.log");
    let logger = SecurityLogger::new(&log_path, false).unwrap();

    engine.execute_action(1001, "malware_a", Action::Quarantine, &logger);
    engine.execute_action(1002, "malware_b", Action::Quarantine, &logger);
    engine.execute_action(1003, "malware_c", Action::Quarantine, &logger);

    let list = engine.get_quarantine_list();
    assert_eq!(list.len(), 3, "Quarantine should have 3 entries");
}

#[test]
fn test_quarantine_restore() {
    let (engine, _tmp) = make_quarantine_engine();
    let log_path = _tmp.path().join("test.log");
    let logger = SecurityLogger::new(&log_path, false).unwrap();
    let _ = &logger;

    let qpath = _tmp.path().join("quarantine");
    let entry_path = qpath.join("test_file.json");
    fs::write(&entry_path, r#"{"pid":1234}"#).unwrap();

    let result = engine.restore_from_quarantine("test_file.json");
    assert!(result.is_ok(), "Restore should succeed");

    let list = engine.get_quarantine_list();
    assert!(
        list.is_empty(),
        "Restored file should be removed from quarantine"
    );
}

#[test]
fn test_quarantine_restore_nonexistent() {
    let (engine, _tmp) = make_quarantine_engine();
    let log_path = _tmp.path().join("test.log");
    let logger = SecurityLogger::new(&log_path, false).unwrap();
    let _ = &logger;

    let result = engine.restore_from_quarantine("no_such_file.json");
    assert!(result.is_err(), "Restoring nonexistent entry should fail");
}

#[test]
fn test_kill_action() {
    let tmp = tempfile::tempdir().unwrap();
    let qpath = tmp.path().join("quarantine");
    std::fs::create_dir_all(&qpath).unwrap();
    let mut engine = ContainmentEngine::new(qpath, false, true, 60);
    let _tmp = tmp;
    let log_path = _tmp.path().join("test.log");
    let logger = SecurityLogger::new(&log_path, false).unwrap();

    let action = engine.execute_action(1, "init", Action::Kill, &logger);
    assert!(
        matches!(
            action.result,
            coreedr::containment::ContainmentResult::Skipped
        ),
        "Kill should be skipped when auto_kill is disabled"
    );
}

#[test]
fn test_monitor_action() {
    let (mut engine, _tmp) = make_quarantine_engine();
    let log_path = _tmp.path().join("test.log");
    let logger = SecurityLogger::new(&log_path, false).unwrap();

    let action = engine.execute_action(1, "bash", Action::Monitor, &logger);
    assert!(
        matches!(
            action.result,
            coreedr::containment::ContainmentResult::Skipped
        ),
        "Monitor action should return Skipped"
    );
}

#[test]
fn test_quarantine_on_disk() {
    let tmp = tempfile::tempdir().unwrap();
    let qpath = tmp.path().join("qdir");
    fs::create_dir_all(&qpath).unwrap();

    fs::write(qpath.join("a.json"), "{}").unwrap();
    fs::write(qpath.join("b.json"), "{}").unwrap();

    let engine = ContainmentEngine::new(qpath, false, false, 30);
    let list = engine.get_quarantine_list();
    assert_eq!(list.len(), 2);
}
