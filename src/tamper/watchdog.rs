use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::error::{CoreError, Result};

pub struct Watchdog {
    heartbeat_path: PathBuf,
    interval: Duration,
    running: Arc<AtomicBool>,
}

impl Watchdog {
    pub fn new() -> Self {
        let heartbeat_dir = std::env::temp_dir().join("coreedr");
        Self {
            heartbeat_path: heartbeat_dir.join("watchdog.heartbeat"),
            interval: Duration::from_secs(10),
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn with_path(path: PathBuf) -> Self {
        Self {
            heartbeat_path: path,
            interval: Duration::from_secs(10),
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn start_watchdog(&self) -> Result<()> {
        if self.running.load(Ordering::Relaxed) {
            return Ok(());
        }

        if let Some(parent) = self.heartbeat_path.parent() {
            fs::create_dir_all(parent)?;
        }

        self.running.store(true, Ordering::Relaxed);

        let running = self.running.clone();
        let heartbeat_path = self.heartbeat_path.clone();
        let interval = self.interval;

        thread::spawn(move || {
            while running.load(Ordering::Relaxed) {
                if let Err(e) = write_heartbeat(&heartbeat_path) {
                    eprintln!("[Watchdog] Failed to write heartbeat: {e}");
                }
                thread::sleep(interval);
            }
        });

        Ok(())
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }

    pub fn write_heartbeat(&self) -> Result<()> {
        write_heartbeat(&self.heartbeat_path)
    }

    pub fn check_health(&self) -> Result<bool> {
        if !self.heartbeat_path.exists() {
            return Ok(false);
        }

        let content = fs::read_to_string(&self.heartbeat_path)?;
        let timestamp: u64 = content
            .trim()
            .parse()
            .map_err(|_| CoreError::Internal("Invalid heartbeat timestamp".to_string()))?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| CoreError::Internal(format!("Time error: {e}")))?
            .as_secs();

        Ok(now.saturating_sub(timestamp) < self.interval.as_secs() * 3)
    }

    pub fn restart_self(&self) -> Result<()> {
        let exe_path = std::env::current_exe()
            .map_err(|e| CoreError::Platform(format!("Failed to get exe path: {e}")))?;

        std::process::Command::new(exe_path)
            .spawn()
            .map_err(|e| CoreError::Platform(format!("Failed to restart: {e}")))?;

        std::process::exit(0);
    }

    pub fn should_restart(&self) -> Result<bool> {
        if !self.heartbeat_path.exists() {
            return Ok(false);
        }

        let content = fs::read_to_string(&self.heartbeat_path)?;
        let timestamp: u64 = content
            .trim()
            .parse()
            .map_err(|_| CoreError::Internal("Invalid heartbeat timestamp".to_string()))?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| CoreError::Internal(format!("Time error: {e}")))?
            .as_secs();

        Ok(now.saturating_sub(timestamp) > self.interval.as_secs() * 3)
    }
}

impl Default for Watchdog {
    fn default() -> Self {
        Self::new()
    }
}

fn write_heartbeat(path: &PathBuf) -> Result<()> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| CoreError::Internal(format!("Time error: {e}")))?
        .as_secs();

    fs::write(path, now.to_string())?;
    Ok(())
}
