pub mod alerts;
pub mod analyzer;
pub mod event_store;
pub mod rules;

use crate::error::CoreError;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BehavioralEvent {
    ProcessSpawn {
        parent_pid: u32,
        child_pid: u32,
        child_name: String,
        timestamp: chrono::DateTime<chrono::Utc>,
    },
    FileAccess {
        pid: u32,
        path: String,
        read: bool,
        write: bool,
        timestamp: chrono::DateTime<chrono::Utc>,
    },
    NetworkConnection {
        pid: u32,
        remote_addr: String,
        remote_port: u16,
        timestamp: chrono::DateTime<chrono::Utc>,
    },
    RegistryAccess {
        pid: u32,
        key: String,
        value: Option<String>,
        timestamp: chrono::DateTime<chrono::Utc>,
    },
    FileModification {
        pid: u32,
        path: String,
        timestamp: chrono::DateTime<chrono::Utc>,
    },
}

impl BehavioralEvent {
    pub fn timestamp(&self) -> chrono::DateTime<chrono::Utc> {
        match self {
            BehavioralEvent::ProcessSpawn { timestamp, .. } => *timestamp,
            BehavioralEvent::FileAccess { timestamp, .. } => *timestamp,
            BehavioralEvent::NetworkConnection { timestamp, .. } => *timestamp,
            BehavioralEvent::RegistryAccess { timestamp, .. } => *timestamp,
            BehavioralEvent::FileModification { timestamp, .. } => *timestamp,
        }
    }

    pub fn pid(&self) -> u32 {
        match self {
            BehavioralEvent::ProcessSpawn { child_pid, .. } => *child_pid,
            BehavioralEvent::FileAccess { pid, .. } => *pid,
            BehavioralEvent::NetworkConnection { pid, .. } => *pid,
            BehavioralEvent::RegistryAccess { pid, .. } => *pid,
            BehavioralEvent::FileModification { pid, .. } => *pid,
        }
    }
}
