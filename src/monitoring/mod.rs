pub mod file_monitor;
pub mod quarantine_watcher;

use crate::error::CoreError;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEvent {
    pub path: PathBuf,
    pub event_type: FileEventType,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub process_id: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FileEventType {
    Created,
    Modified,
    Deleted,
    Renamed,
    Accessed,
}

pub trait FileWatcher: Send + Sync {
    fn start_watching(&mut self, dirs: &[PathBuf]) -> Result<(), CoreError>;
    fn stop_watching(&mut self) -> Result<(), CoreError>;
    fn get_events(&self) -> Vec<FileEvent>;
}
