use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use sha2::{Digest, Sha256};

use crate::error::{CoreError, Result};

pub struct IntegrityChecker {
    known_hashes: Mutex<HashMap<PathBuf, String>>,
    hash_store_path: Option<PathBuf>,
}

impl IntegrityChecker {
    pub fn new() -> Self {
        Self {
            known_hashes: Mutex::new(HashMap::new()),
            hash_store_path: None,
        }
    }

    pub fn with_store(path: PathBuf) -> Self {
        Self {
            known_hashes: Mutex::new(HashMap::new()),
            hash_store_path: Some(path),
        }
    }

    pub fn store_current_hash(&self) -> Result<()> {
        let exe_path = std::env::current_exe()
            .map_err(|e| CoreError::Platform(format!("Failed to get exe path: {e}")))?;

        let hash = compute_file_hash(&exe_path)?;

        let mut hashes = self
            .known_hashes
            .lock()
            .map_err(|e| CoreError::Internal(format!("Lock poisoned: {e}")))?;
        hashes.insert(exe_path, hash);

        if let Some(ref store_path) = self.hash_store_path {
            self.persist_hashes(&hashes, store_path)?;
        }

        Ok(())
    }

    pub fn verify_self_integrity(&self) -> Result<bool> {
        let exe_path = std::env::current_exe()
            .map_err(|e| CoreError::Platform(format!("Failed to get exe path: {e}")))?;

        let current_hash = compute_file_hash(&exe_path)?;

        let hashes = self
            .known_hashes
            .lock()
            .map_err(|e| CoreError::Internal(format!("Lock poisoned: {e}")))?;

        if let Some(stored_hash) = hashes.get(&exe_path) {
            Ok(current_hash == *stored_hash)
        } else {
            Ok(true)
        }
    }

    pub fn verify_config_integrity(&self, path: &Path) -> Result<bool> {
        let current_hash = compute_file_hash(path)?;

        let hashes = self
            .known_hashes
            .lock()
            .map_err(|e| CoreError::Internal(format!("Lock poisoned: {e}")))?;

        if let Some(stored_hash) = hashes.get(path) {
            Ok(current_hash == *stored_hash)
        } else {
            Ok(true)
        }
    }

    pub fn store_config_hash(&self, path: &Path) -> Result<()> {
        let hash = compute_file_hash(path)?;

        let mut hashes = self
            .known_hashes
            .lock()
            .map_err(|e| CoreError::Internal(format!("Lock poisoned: {e}")))?;
        hashes.insert(path.to_path_buf(), hash);

        if let Some(ref store_path) = self.hash_store_path {
            self.persist_hashes(&hashes, store_path)?;
        }

        Ok(())
    }

    pub fn detect_tamper(&self, path: &Path) -> Result<TamperResult> {
        let exists = path.exists();
        let hashes = self
            .known_hashes
            .lock()
            .map_err(|e| CoreError::Internal(format!("Lock poisoned: {e}")))?;

        if !exists {
            if hashes.contains_key(path) {
                return Ok(TamperResult::Deleted);
            }
            return Ok(TamperResult::NotTracked);
        }

        if let Some(stored_hash) = hashes.get(path) {
            let current_hash = compute_file_hash(path)?;
            if current_hash != *stored_hash {
                return Ok(TamperResult::Modified {
                    expected: stored_hash.clone(),
                    actual: current_hash,
                });
            }
            Ok(TamperResult::Intact)
        } else {
            Ok(TamperResult::NotTracked)
        }
    }

    pub fn clear(&self) -> Result<()> {
        let mut hashes = self
            .known_hashes
            .lock()
            .map_err(|e| CoreError::Internal(format!("Lock poisoned: {e}")))?;
        hashes.clear();
        Ok(())
    }

    fn persist_hashes(&self, hashes: &HashMap<PathBuf, String>, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(hashes)
            .map_err(|e| CoreError::Internal(format!("Failed to serialize hashes: {e}")))?;

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        fs::write(path, json)?;
        Ok(())
    }
}

impl Default for IntegrityChecker {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub enum TamperResult {
    Intact,
    Modified { expected: String, actual: String },
    Deleted,
    NotTracked,
}

fn compute_file_hash(path: &Path) -> Result<String> {
    let data = fs::read(path).map_err(|e| CoreError::Io(e))?;

    let mut hasher = Sha256::new();
    hasher.update(&data);
    let result = hasher.finalize();

    Ok(hex::encode(result))
}
