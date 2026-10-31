use crate::config::MonitoringConfig;
use crate::error::{CoreError, Result};
use crate::monitoring::{FileEvent, FileEventType};
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub struct FileMonitor {
    watcher: Option<RecommendedWatcher>,
    event_tx: Sender<FileEvent>,
    event_rx: Arc<Mutex<Receiver<FileEvent>>>,
    event_buffer: Arc<Mutex<Vec<FileEvent>>>,
    watched_dirs: Vec<PathBuf>,
    ignored_dirs: HashSet<PathBuf>,
    max_buffer_size: usize,
    is_running: bool,
}

impl FileMonitor {
    pub fn new(config: &MonitoringConfig) -> Result<Self> {
        let (tx, rx) = mpsc::channel::<FileEvent>();

        let ignored_dirs: HashSet<PathBuf> = config.ignored_dirs.iter().cloned().collect();

        Ok(Self {
            watcher: None,
            event_tx: tx,
            event_rx: Arc::new(Mutex::new(rx)),
            event_buffer: Arc::new(Mutex::new(Vec::new())),
            watched_dirs: config.monitored_dirs.clone(),
            ignored_dirs,
            max_buffer_size: 10000,
            is_running: false,
        })
    }

    pub fn start(&mut self) -> Result<()> {
        if self.is_running {
            return Ok(());
        }

        let event_tx = self.event_tx.clone();
        let watched_dirs = self.watched_dirs.clone();
        let ignored_dirs = self.ignored_dirs.clone();

        let mut watcher =
            notify::recommended_watcher(move |res: notify::Result<Event>| match res {
                Ok(event) => {
                    if let Some(file_event) = Self::convert_event(event, &ignored_dirs) {
                        let _ = event_tx.send(file_event);
                    }
                }
                Err(e) => {
                    eprintln!("File watch error: {}", e);
                }
            })
            .map_err(|e| CoreError::Internal(format!("Failed to create file watcher: {}", e)))?;

        for dir in &watched_dirs {
            if dir.exists() {
                watcher.watch(dir, RecursiveMode::Recursive).map_err(|e| {
                    CoreError::Internal(format!(
                        "Failed to watch directory {}: {}",
                        dir.display(),
                        e
                    ))
                })?;
            }
        }

        self.watcher = Some(watcher);
        self.is_running = true;

        let event_rx = self.event_rx.clone();
        let event_buffer = self.event_buffer.clone();
        let max_buffer = self.max_buffer_size;

        std::thread::spawn(move || loop {
            let event = {
                let rx = match event_rx.lock() {
                    Ok(rx) => rx,
                    Err(_) => continue,
                };
                rx.recv_timeout(Duration::from_millis(100))
            };
            if let Ok(event) = event {
                if let Ok(mut buffer) = event_buffer.lock() {
                    buffer.push(event);
                    if buffer.len() > max_buffer {
                        let excess = buffer.len() - max_buffer;
                        buffer.drain(0..excess);
                    }
                }
            }
        });

        Ok(())
    }

    pub fn stop(&mut self) -> Result<()> {
        if let Some(watcher) = self.watcher.take() {
            drop(watcher);
        }
        self.is_running = false;
        Ok(())
    }

    pub fn get_events(&self) -> Vec<FileEvent> {
        self.event_buffer
            .lock()
            .map(|buf| buf.clone())
            .unwrap_or_default()
    }

    pub fn is_watching(&self) -> bool {
        self.is_running
    }

    pub fn add_directory(&mut self, dir: PathBuf) -> Result<()> {
        if let Some(ref mut watcher) = self.watcher {
            if dir.exists() {
                watcher.watch(&dir, RecursiveMode::Recursive).map_err(|e| {
                    CoreError::Internal(format!(
                        "Failed to watch directory {}: {}",
                        dir.display(),
                        e
                    ))
                })?;
                self.watched_dirs.push(dir);
            }
        }
        Ok(())
    }

    pub fn clear_buffer(&self) {
        if let Ok(mut buffer) = self.event_buffer.lock() {
            buffer.clear();
        }
    }

    fn convert_event(event: Event, ignored_dirs: &HashSet<PathBuf>) -> Option<FileEvent> {
        let paths: Vec<PathBuf> = event.paths;

        if paths.is_empty() {
            return None;
        }

        let path = paths.into_iter().next()?;

        for ignored in ignored_dirs {
            if path.starts_with(ignored) {
                return None;
            }
        }

        let event_type = match event.kind {
            EventKind::Create(_) => FileEventType::Created,
            EventKind::Modify(_) => FileEventType::Modified,
            EventKind::Remove(_) => FileEventType::Deleted,
            EventKind::Access(_) => FileEventType::Accessed,
            _ => return None,
        };

        Some(FileEvent {
            path,
            event_type,
            timestamp: chrono::Utc::now(),
            process_id: None,
        })
    }
}

pub trait FileWatcherExt {
    fn get_recent_events(&self, count: usize) -> Vec<FileEvent>;
    fn get_events_for_path(&self, path: &Path) -> Vec<FileEvent>;
}

impl FileWatcherExt for FileMonitor {
    fn get_recent_events(&self, count: usize) -> Vec<FileEvent> {
        self.event_buffer
            .lock()
            .map(|buffer| buffer.iter().rev().take(count).cloned().collect())
            .unwrap_or_default()
    }

    fn get_events_for_path(&self, path: &Path) -> Vec<FileEvent> {
        self.event_buffer
            .lock()
            .map(|buffer| {
                buffer
                    .iter()
                    .filter(|e| e.path.starts_with(path))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }
}
