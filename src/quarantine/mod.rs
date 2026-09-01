pub mod cleanup;
pub mod encryption;
pub mod restore;
pub mod store;

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineEntry {
    pub id: String,
    pub process_name: String,
    pub pid: u32,
    pub hash: Option<String>,
    pub path: Option<String>,
    pub quarantine_path: Option<String>,
    pub quarantine_time: chrono::DateTime<chrono::Utc>,
    pub reason: String,
    pub risk_score: u32,
    pub status: QuarantineStatus,
    pub notes: Option<String>,
    pub original_size: Option<u64>,
    pub encrypted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum QuarantineStatus {
    Pending,
    Reviewed,
    Restored,
    Deleted,
}

pub struct QuarantineManager {
    quarantine_path: PathBuf,
}

impl QuarantineManager {
    pub fn new(quarantine_path: PathBuf) -> Self {
        std::fs::create_dir_all(&quarantine_path).ok();
        Self { quarantine_path }
    }

    pub fn add_entry(&self, entry: QuarantineEntry) -> crate::error::Result<()> {
        let filename = format!("{}.json", entry.id);
        let path = self.quarantine_path.join(&filename);
        let json = serde_json::to_string_pretty(&entry)?;
        std::fs::write(&path, json)?;
        Ok(())
    }

    pub fn get_entry(&self, id: &str) -> crate::error::Result<Option<QuarantineEntry>> {
        let filename = format!("{}.json", id);
        let path = self.quarantine_path.join(&filename);

        if !path.exists() {
            return Ok(None);
        }

        let content = std::fs::read_to_string(&path)?;
        let entry: QuarantineEntry = serde_json::from_str(&content)?;
        Ok(Some(entry))
    }

    pub fn list_entries(&self) -> Vec<QuarantineEntry> {
        let mut entries = Vec::new();

        if let Ok(dir_entries) = std::fs::read_dir(&self.quarantine_path) {
            for entry in dir_entries.flatten() {
                let path = entry.path();
                if path.extension().map(|e| e == "json").unwrap_or(false) {
                    if let Ok(content) = std::fs::read_to_string(&path) {
                        if let Ok(entry) = serde_json::from_str::<QuarantineEntry>(&content) {
                            entries.push(entry);
                        }
                    }
                }
            }
        }

        entries.sort_by(|a, b| b.quarantine_time.cmp(&a.quarantine_time));
        entries
    }

    pub fn update_status(
        &self,
        id: &str,
        status: QuarantineStatus,
        notes: Option<String>,
    ) -> crate::error::Result<()> {
        if let Some(mut entry) = self.get_entry(id)? {
            entry.status = status;
            if let Some(n) = notes {
                entry.notes = Some(n);
            }

            let filename = format!("{}.json", id);
            let path = self.quarantine_path.join(&filename);
            let json = serde_json::to_string_pretty(&entry)?;
            std::fs::write(&path, json)?;
        }
        Ok(())
    }

    pub fn delete_entry(&self, id: &str) -> crate::error::Result<()> {
        let filename = format!("{}.json", id);
        let path = self.quarantine_path.join(&filename);
        if path.exists() {
            std::fs::remove_file(&path)?;
        }

        let data_filename = format!("{}.dat", id);
        let data_path = self.quarantine_path.join(&data_filename);
        if data_path.exists() {
            std::fs::remove_file(&data_path)?;
        }

        Ok(())
    }

    pub fn get_stats(&self) -> QuarantineStats {
        let entries = self.list_entries();
        let mut stats = QuarantineStats::default();
        stats.total = entries.len() as u32;

        for entry in &entries {
            match entry.status {
                QuarantineStatus::Pending => stats.pending += 1,
                QuarantineStatus::Reviewed => stats.reviewed += 1,
                QuarantineStatus::Restored => stats.restored += 1,
                QuarantineStatus::Deleted => stats.deleted += 1,
            }
        }

        stats
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct QuarantineStats {
    pub total: u32,
    pub pending: u32,
    pub reviewed: u32,
    pub restored: u32,
    pub deleted: u32,
}
