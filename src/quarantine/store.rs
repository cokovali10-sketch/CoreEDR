use crate::error::{CoreError, Result};
use crate::quarantine::{QuarantineEntry, QuarantineStats, QuarantineStatus};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Mutex;

#[derive(Debug, Serialize, Deserialize)]
struct QuarantineIndex {
    entries: Vec<QuarantineEntry>,
}

pub struct QuarantineStore {
    index_path: PathBuf,
    data_dir: PathBuf,
    index: Mutex<QuarantineIndex>,
}

impl QuarantineStore {
    pub fn new(store_dir: PathBuf) -> Result<Self> {
        let data_dir = store_dir.join("data");
        let index_path = store_dir.join("index.json");

        std::fs::create_dir_all(&data_dir)?;

        let index = if index_path.exists() {
            let content = std::fs::read_to_string(&index_path)?;
            serde_json::from_str(&content).unwrap_or(QuarantineIndex {
                entries: Vec::new(),
            })
        } else {
            QuarantineIndex {
                entries: Vec::new(),
            }
        };

        Ok(Self {
            index_path,
            data_dir,
            index: Mutex::new(index),
        })
    }

    pub fn add_entry(&self, entry: QuarantineEntry) -> Result<()> {
        let mut index = self
            .index
            .lock()
            .map_err(|e| CoreError::Quarantine(format!("Lock poisoned: {}", e)))?;

        index.entries.push(entry);
        self.persist_index(&index)?;
        Ok(())
    }

    pub fn get_entry(&self, id: &str) -> Result<Option<QuarantineEntry>> {
        let index = self
            .index
            .lock()
            .map_err(|e| CoreError::Quarantine(format!("Lock poisoned: {}", e)))?;

        Ok(index
            .entries
            .iter()
            .find(|e| e.id == id)
            .cloned())
    }

    pub fn list_entries(&self) -> Result<Vec<QuarantineEntry>> {
        let index = self
            .index
            .lock()
            .map_err(|e| CoreError::Quarantine(format!("Lock poisoned: {}", e)))?;

        Ok(index.entries.clone())
    }

    pub fn update_status(
        &self,
        id: &str,
        status: QuarantineStatus,
        notes: Option<String>,
    ) -> Result<()> {
        let mut index = self
            .index
            .lock()
            .map_err(|e| CoreError::Quarantine(format!("Lock poisoned: {}", e)))?;

        if let Some(entry) = index.entries.iter_mut().find(|e| e.id == id) {
            entry.status = status;
            if let Some(n) = notes {
                entry.notes = Some(n);
            }
            self.persist_index(&index)?;
        }

        Ok(())
    }

    pub fn delete_entry(&self, id: &str) -> Result<()> {
        let mut index = self
            .index
            .lock()
            .map_err(|e| CoreError::Quarantine(format!("Lock poisoned: {}", e)))?;

        index.entries.retain(|e| e.id != id);

        let data_file = self.data_dir.join(format!("{}.dat", id));
        if data_file.exists() {
            std::fs::remove_file(&data_file)?;
        }

        self.persist_index(&index)?;
        Ok(())
    }

    pub fn get_stats(&self) -> Result<QuarantineStats> {
        let index = self
            .index
            .lock()
            .map_err(|e| CoreError::Quarantine(format!("Lock poisoned: {}", e)))?;

        let mut stats = QuarantineStats::default();
        stats.total = index.entries.len() as u32;

        for entry in &index.entries {
            match entry.status {
                QuarantineStatus::Pending => stats.pending += 1,
                QuarantineStatus::Reviewed => stats.reviewed += 1,
                QuarantineStatus::Restored => stats.restored += 1,
                QuarantineStatus::Deleted => stats.deleted += 1,
            }
        }

        Ok(stats)
    }

    fn persist_index(&self, index: &QuarantineIndex) -> Result<()> {
        let json = serde_json::to_string_pretty(index)
            .map_err(|e| CoreError::Quarantine(format!("Failed to serialize index: {}", e)))?;
        std::fs::write(&self.index_path, json)?;
        Ok(())
    }
}
