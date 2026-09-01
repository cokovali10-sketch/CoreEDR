use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineEntry {
    pub id: String,
    pub process_name: String,
    pub pid: u32,
    pub hash: Option<String>,
    pub path: Option<String>,
    pub quarantine_time: chrono::DateTime<chrono::Utc>,
    pub reason: String,
    pub risk_score: u32,
    pub status: QuarantineStatus,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

    pub fn add_entry(&self, entry: QuarantineEntry) -> Result<(), Box<dyn std::error::Error>> {
        let filename = format!("{}.json", entry.id);
        let path = self.quarantine_path.join(&filename);
        let json = serde_json::to_string_pretty(&entry)?;
        std::fs::write(&path, json)?;
        Ok(())
    }

    pub fn get_entry(&self, id: &str) -> Result<Option<QuarantineEntry>, Box<dyn std::error::Error>> {
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
    ) -> Result<(), Box<dyn std::error::Error>> {
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

    pub fn delete_entry(&self, id: &str) -> Result<(), Box<dyn std::error::Error>> {
        let filename = format!("{}.json", id);
        let path = self.quarantine_path.join(&filename);
        if path.exists() {
            std::fs::remove_file(&path)?;
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

    pub fn cleanup_old_entries(&self, max_age_days: u32) -> Result<u32, Box<dyn std::error::Error>> {
        let entries = self.list_entries();
        let cutoff = chrono::Utc::now() - chrono::Duration::days(max_age_days as i64);
        let mut removed = 0;

        for entry in entries {
            if entry.quarantine_time < cutoff && matches!(entry.status, QuarantineStatus::Deleted) {
                self.delete_entry(&entry.id)?;
                removed += 1;
            }
        }

        Ok(removed)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn make_test_entry(id: &str) -> QuarantineEntry {
        QuarantineEntry {
            id: id.to_string(),
            process_name: "test.exe".to_string(),
            pid: 1234,
            hash: Some("abc123".to_string()),
            path: Some("/tmp/test.exe".to_string()),
            quarantine_time: chrono::Utc::now(),
            reason: "Test quarantine".to_string(),
            risk_score: 80,
            status: QuarantineStatus::Pending,
            notes: None,
        }
    }

    #[test]
    fn test_quarantine_add_list() {
        let tmp = env::temp_dir().join("test_quarantine_mgr");
        let manager = QuarantineManager::new(tmp.clone());

        let entry = make_test_entry("test-001");
        manager.add_entry(entry).unwrap();

        let entries = manager.list_entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, "test-001");

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn test_quarantine_update_status() {
        let tmp = env::temp_dir().join("test_quarantine_status");
        let manager = QuarantineManager::new(tmp.clone());

        let entry = make_test_entry("test-002");
        manager.add_entry(entry).unwrap();

        manager.update_status("test-002", QuarantineStatus::Reviewed, Some("Reviewed".to_string())).unwrap();

        let updated = manager.get_entry("test-002").unwrap().unwrap();
        assert!(matches!(updated.status, QuarantineStatus::Reviewed));

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn test_quarantine_delete() {
        let tmp = env::temp_dir().join("test_quarantine_delete");
        let manager = QuarantineManager::new(tmp.clone());

        let entry = make_test_entry("test-003");
        manager.add_entry(entry).unwrap();

        manager.delete_entry("test-003").unwrap();
        let result = manager.get_entry("test-003").unwrap();
        assert!(result.is_none());

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn test_quarantine_stats() {
        let tmp = env::temp_dir().join("test_quarantine_stats");
        let manager = QuarantineManager::new(tmp.clone());

        manager.add_entry(make_test_entry("s1")).unwrap();
        manager.add_entry(make_test_entry("s2")).unwrap();

        let stats = manager.get_stats();
        assert_eq!(stats.total, 2);
        assert_eq!(stats.pending, 2);

        std::fs::remove_dir_all(&tmp).ok();
    }
}
