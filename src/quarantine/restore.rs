use crate::error::{CoreError, Result};
use crate::hash_engine::HashEngine;
use crate::quarantine::{QuarantineEntry, QuarantineStatus};
use crate::quarantine::store::QuarantineStore;
use crate::yara::YaraManager;

pub struct QuarantineRestore {
    store: QuarantineStore,
    scan_before_restore: bool,
}

impl QuarantineRestore {
    pub fn new(store: QuarantineStore, scan_before_restore: bool) -> Self {
        Self {
            store,
            scan_before_restore,
        }
    }

    pub fn restore_entry(
        &self,
        id: &str,
        restore_path: &std::path::Path,
        password: &[u8],
    ) -> Result<QuarantineEntry> {
        let entry = self
            .store
            .get_entry(id)?
            .ok_or_else(|| CoreError::Quarantine(format!("Entry {} not found", id)))?;

        if matches!(entry.status, QuarantineStatus::Restored | QuarantineStatus::Deleted) {
            return Err(CoreError::Quarantine(format!(
                "Entry {} has already been {}",
                id,
                match entry.status {
                    QuarantineStatus::Restored => "restored",
                    QuarantineStatus::Deleted => "deleted",
                    _ => "processed",
                }
            )));
        }

        if let Some(ref quarantine_path) = entry.quarantine_path {
            let quarantine_file = std::path::PathBuf::from(quarantine_path);
            if !quarantine_file.exists() {
                return Err(CoreError::Quarantine(format!(
                    "Quarantined file not found: {}",
                    quarantine_path
                )));
            }

            if entry.encrypted {
                super::encryption::decrypt_file(&quarantine_file, restore_path, password)?;
            } else {
                std::fs::copy(&quarantine_file, restore_path)?;
            }
        } else {
            return Err(CoreError::Quarantine(format!(
                "No quarantine path stored for entry {}",
                id
            )));
        }

        if let Some(ref expected_hash) = entry.hash {
            let hash_engine = HashEngine::new(7.5);
            let hash_result = hash_engine.hash_file(restore_path)
                .map_err(|e| CoreError::Quarantine(format!("Hash verification failed: {}", e)))?;

            if hash_result.sha256 != *expected_hash {
                std::fs::remove_file(restore_path).ok();
                return Err(CoreError::Quarantine(format!(
                    "Integrity check failed for entry {}: expected {}, got {}",
                    id, expected_hash, hash_result.sha256
                )));
            }
        }

        if self.scan_before_restore {
            let yara_manager = YaraManager::new();
            let matches = yara_manager.scan_file(restore_path)?;
            if !matches.is_empty() {
                std::fs::remove_file(restore_path).ok();
                let threat_names: Vec<String> = matches.iter().map(|m| m.rule_name.clone()).collect();
                return Err(CoreError::Quarantine(format!(
                    "Restore aborted: file still matches YARA rules: {}",
                    threat_names.join(", ")
                )));
            }
        }

        self.store
            .update_status(id, QuarantineStatus::Restored, Some("Restored by user".to_string()))?;

        let mut restored_entry = entry.clone();
        restored_entry.status = QuarantineStatus::Restored;

        Ok(restored_entry)
    }

    pub fn bulk_restore(
        &self,
        ids: &[String],
        restore_dir: &std::path::Path,
        password: &[u8],
    ) -> Result<Vec<QuarantineEntry>> {
        let mut restored = Vec::new();
        let mut errors = Vec::new();

        for id in ids {
            let restore_path = restore_dir.join(format!("restored_{}", id));
            match self.restore_entry(id, &restore_path, password) {
                Ok(entry) => restored.push(entry),
                Err(e) => errors.push((id.clone(), e.to_string())),
            }
        }

        if !errors.is_empty() {
            let error_msgs: Vec<String> =
                errors.iter().map(|(id, e)| format!("{}: {}", id, e)).collect();
            eprintln!("Some restorations failed: {}", error_msgs.join("; "));
        }

        Ok(restored)
    }
}
