use crate::error::{CoreError, Result};
use crate::monitoring::{FileEvent, FileEventType};
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub event_type: SecurityEventType,
    pub path: PathBuf,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityEventType {
    FileDeleted,
    FileModified,
    FileCreated,
    TamperingDetected,
}

pub struct QuarantineWatcher {
    watcher: Option<RecommendedWatcher>,
    quarantine_path: PathBuf,
    events: Arc<Mutex<Vec<SecurityEvent>>>,
    is_running: bool,
}

impl QuarantineWatcher {
    pub fn new(quarantine_path: PathBuf) -> Self {
        Self {
            watcher: None,
            quarantine_path,
            events: Arc::new(Mutex::new(Vec::new())),
            is_running: false,
        }
    }

    pub fn start(&mut self) -> Result<()> {
        if self.is_running {
            return Ok(());
        }

        if !self.quarantine_path.exists() {
            std::fs::create_dir_all(&self.quarantine_path)?;
        }

        let events = self.events.clone();
        let quarantine_path = self.quarantine_path.clone();

        let mut watcher = notify::recommended_watcher(move |res: notify::Result<Event>| {
            match res {
                Ok(event) => {
                    Self::handle_event(event, &events, &quarantine_path);
                }
                Err(e) => {
                    eprintln!("Quarantine watch error: {}", e);
                }
            }
        })
        .map_err(|e| CoreError::Internal(format!("Failed to create quarantine watcher: {}", e)))?;

        watcher
            .watch(&self.quarantine_path, RecursiveMode::Recursive)
            .map_err(|e| {
                CoreError::Internal(format!(
                    "Failed to watch quarantine directory {}: {}",
                    self.quarantine_path.display(),
                    e
                ))
            })?;

        self.watcher = Some(watcher);
        self.is_running = true;

        Ok(())
    }

    pub fn stop(&mut self) -> Result<()> {
        if let Some(watcher) = self.watcher.take() {
            drop(watcher);
        }
        self.is_running = false;
        Ok(())
    }

    pub fn get_events(&self) -> Vec<SecurityEvent> {
        self.events
            .lock()
            .map(|events| events.clone())
            .unwrap_or_default()
    }

    pub fn is_watching(&self) -> bool {
        self.is_running
    }

    fn handle_event(
        event: Event,
        events: &Arc<Mutex<Vec<SecurityEvent>>>,
        quarantine_path: &PathBuf,
    ) {
        let paths: Vec<PathBuf> = event.paths;

        if paths.is_empty() {
            return;
        }

        for path in paths {
            let security_event = match event.kind {
                EventKind::Remove(_) => Some(SecurityEvent {
                    timestamp: chrono::Utc::now(),
                    event_type: SecurityEventType::FileDeleted,
                    path: path.clone(),
                    details: format!("Quarantined file deleted: {}", path.display()),
                }),
                EventKind::Modify(_) => Some(SecurityEvent {
                    timestamp: chrono::Utc::now(),
                    event_type: SecurityEventType::TamperingDetected,
                    path: path.clone(),
                    details: format!("Quarantined file modified: {}", path.display()),
                }),
                EventKind::Create(_) => Some(SecurityEvent {
                    timestamp: chrono::Utc::now(),
                    event_type: SecurityEventType::FileCreated,
                    path: path.clone(),
                    details: format!("New file added to quarantine: {}", path.display()),
                }),
                _ => None,
            };

            if let Some(security_event) = security_event {
                if let Ok(mut events) = events.lock() {
                    events.push(security_event);
                }
            }
        }
    }
}
