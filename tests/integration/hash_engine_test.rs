use coreedr::hash_engine::HashEngine;
use std::fs;
use std::io::Write;
use tempfile::TempDir;

#[test]
fn test_hash_bytes_deterministic() {
    let engine = HashEngine::new(7.5);
    let h1 = engine.hash_bytes(b"hello world");
    let h2 = engine.hash_bytes(b"hello world");
    assert_eq!(h1, h2);
    assert_eq!(h1.len(), 64); // sha256 hex
}

#[test]
fn test_hash_file() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("test.txt");
    let mut f = fs::File::create(&path).unwrap();
    f.write_all(b"test content").unwrap();
    drop(f);

    let engine = HashEngine::new(7.5);
    let result = engine.hash_file(&path).unwrap();
    assert!(!result.sha256.is_empty());
    assert!(result.size > 0);
}

#[test]
fn test_calculate_entropy() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("test.txt");
    fs::write(&path, b"aaaa").unwrap();

    let engine = HashEngine::new(7.5);
    let entropy = engine.calculate_file_entropy(&path).unwrap();
    assert!(entropy >= 0.0 && entropy <= 8.0);
}

#[test]
fn test_is_known_malicious() {
    let engine = HashEngine::new(7.5);
    let blacklist = vec!["abc123".to_string()];
    assert!(engine.is_known_malicious("abc123", &blacklist));
    assert!(!engine.is_known_malicious("xyz", &blacklist));
}

#[test]
fn test_is_whitelisted() {
    let engine = HashEngine::new(7.5);
    let whitelist = vec!["goodhash".to_string()];
    assert!(engine.is_whitelisted("goodhash", &whitelist));
    assert!(!engine.is_whitelisted("bad", &whitelist));
}

#[test]
fn test_quick_hash() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("q.txt");
    fs::write(&path, b"quick").unwrap();
    let h = HashEngine::quick_hash(&path).unwrap();
    assert_eq!(h.len(), 64);
}