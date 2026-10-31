use crate::error::Result;
use crate::quarantine::store::QuarantineStore;
use crate::quarantine::{QuarantineStats, QuarantineStatus};

pub struct QuarantineCleanup {
    store: QuarantineStore,
    max_age_days: u32,
}

impl QuarantineCleanup {
    pub fn new(store: QuarantineStore, max_age_days: u32) -> Self {
        Self {
            store,
            max_age_days,
        }
    }

    pub fn cleanup(&self) -> Result<CleanupResult> {
        let entries = self.store.list_entries()?;
        let cutoff = chrono::Utc::now() - chrono::Duration::days(self.max_age_days as i64);
        let mut removed = 0u32;
        let mut skipped = 0u32;

        for entry in entries {
            if entry.quarantine_time < cutoff
                && matches!(
                    entry.status,
                    QuarantineStatus::Deleted | QuarantineStatus::Restored
                )
            {
                self.store.delete_entry(&entry.id)?;
                removed += 1;
            } else {
                skipped += 1;
            }
        }

        Ok(CleanupResult {
            entries_removed: removed,
            entries_retained: skipped,
            max_age_days: self.max_age_days,
        })
    }

    pub fn force_cleanup_all_deleted(&self) -> Result<u32> {
        let entries = self.store.list_entries()?;
        let mut removed = 0u32;

        for entry in entries {
            if matches!(entry.status, QuarantineStatus::Deleted) {
                self.store.delete_entry(&entry.id)?;
                removed += 1;
            }
        }

        Ok(removed)
    }
}

#[derive(Debug)]
pub struct CleanupResult {
    pub entries_removed: u32,
    pub entries_retained: u32,
    pub max_age_days: u32,
}
