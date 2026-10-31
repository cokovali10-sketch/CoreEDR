use crate::error::{CoreError, Result};
use std::fs;
use std::path::{Path, PathBuf};

pub struct LogRotation {
    max_size_mb: u64,
    retention_days: u32,
    log_path: PathBuf,
}

impl LogRotation {
    pub fn new(log_path: PathBuf, max_size_mb: u64, retention_days: u32) -> Self {
        Self {
            log_path,
            max_size_mb,
            retention_days,
        }
    }

    pub fn from_config(config: &crate::config::LoggingConfig) -> Self {
        Self::new(
            config.log_path.clone(),
            config.max_log_size_mb,
            config.retention_days,
        )
    }

    pub fn check_and_rotate(&self) -> Result<u32> {
        let mut rotated = 0;

        if self.log_path.exists() {
            let metadata = fs::metadata(&self.log_path).map_err(|e| CoreError::Io(e))?;
            let size_mb = metadata.len() / (1024 * 1024);

            if size_mb >= self.max_size_mb {
                self.rotate_file()?;
                rotated += 1;
            }
        }

        rotated += self.cleanup_old_logs()?;

        Ok(rotated)
    }

    fn rotate_file(&self) -> Result<()> {
        if !self.log_path.exists() {
            return Ok(());
        }

        let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
        let extension = self
            .log_path
            .extension()
            .map(|e| format!(".{}", e.to_string_lossy()))
            .unwrap_or_default();
        let stem = self
            .log_path
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();
        let parent = self.log_path.parent().unwrap_or_else(|| Path::new("."));

        let rotated_name = format!("{}_{timestamp}{}", stem, extension);
        let rotated_path = parent.join(rotated_name);

        fs::rename(&self.log_path, &rotated_path).map_err(|e| CoreError::Io(e))?;

        Ok(())
    }

    fn cleanup_old_logs(&self) -> Result<u32> {
        let parent = match self.log_path.parent() {
            Some(p) => p.to_path_buf(),
            None => return Ok(0),
        };

        let stem = self
            .log_path
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();

        let extension = self
            .log_path
            .extension()
            .map(|e| e.to_string_lossy().to_string())
            .unwrap_or_default();

        let cutoff = chrono::Utc::now() - chrono::Duration::days(self.retention_days as i64);
        let mut removed = 0;

        if let Ok(entries) = fs::read_dir(&parent) {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if name.starts_with(&stem)
                        && name
                            != self
                                .log_path
                                .file_name()
                                .and_then(|n| n.to_str())
                                .unwrap_or("")
                    {
                        if let Ok(metadata) = fs::metadata(&path) {
                            if let Ok(modified) = metadata.modified() {
                                if let Ok(modified_time) =
                                    modified.duration_since(std::time::UNIX_EPOCH)
                                {
                                    let modified_chrono = chrono::DateTime::from_timestamp(
                                        modified_time.as_secs() as i64,
                                        0,
                                    )
                                    .unwrap_or_default();

                                    if modified_chrono < cutoff {
                                        fs::remove_file(&path).ok();
                                        removed += 1;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(removed)
    }

    pub fn get_log_stats(&self) -> LogStats {
        let mut stats = LogStats::default();

        if let Ok(metadata) = fs::metadata(&self.log_path) {
            stats.current_size_bytes = metadata.len();
            stats.current_size_mb = metadata.len() / (1024 * 1024);
            stats.exists = true;
        }

        let parent = self.log_path.parent().unwrap_or_else(|| Path::new("."));
        let stem = self
            .log_path
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();

        if let Ok(entries) = fs::read_dir(parent) {
            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_str() {
                    if name.starts_with(&stem)
                        && name
                            != self
                                .log_path
                                .file_name()
                                .and_then(|n| n.to_str())
                                .unwrap_or("")
                    {
                        stats.rotated_files += 1;
                    }
                }
            }
        }

        stats.max_size_mb = self.max_size_mb;
        stats.retention_days = self.retention_days;

        stats
    }
}

#[derive(Debug, Default)]
pub struct LogStats {
    pub exists: bool,
    pub current_size_bytes: u64,
    pub current_size_mb: u64,
    pub max_size_mb: u64,
    pub retention_days: u32,
    pub rotated_files: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_rotation_creation() {
        let tmp = std::env::temp_dir().join("test_log_rotation");
        let rotation = LogRotation::new(tmp.clone(), 100, 30);
        assert_eq!(rotation.max_size_mb, 100);
        assert_eq!(rotation.retention_days, 30);
    }

    #[test]
    fn test_log_stats() {
        let tmp = std::env::temp_dir().join("test_log_stats.log");
        let rotation = LogRotation::new(tmp.clone(), 50, 7);
        let stats = rotation.get_log_stats();
        assert!(!stats.exists);
        assert_eq!(stats.max_size_mb, 50);
        assert_eq!(stats.retention_days, 7);
    }
}
