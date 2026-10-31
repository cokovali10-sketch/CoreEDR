use coreedr::yara::YaraManager;

#[test]
fn test_yara_manager_new() {
    let manager = YaraManager::new();
    let matches = manager.scan_bytes(b"hello").unwrap();
    assert!(matches.is_empty());
}

#[test]
fn test_yara_scan_bytes_no_rules() {
    let manager = YaraManager::new();
    let matches = manager.scan_bytes(b"some data").unwrap();
    assert!(matches.is_empty());
}
