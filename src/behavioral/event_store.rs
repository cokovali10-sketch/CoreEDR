use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::error::{CoreError, Result};
use super::BehavioralEvent;

pub struct EventStore {
    events: Mutex<VecDeque<TimestampedEvent>>,
    max_events: usize,
}

struct TimestampedEvent {
    event: BehavioralEvent,
    inserted_at: Instant,
}

impl EventStore {
    pub fn new() -> Self {
        Self::with_capacity(10_000)
    }

    pub fn with_capacity(max_events: usize) -> Self {
        Self {
            events: Mutex::new(VecDeque::with_capacity(max_events)),
            max_events,
        }
    }

    pub fn add_event(&self, event: BehavioralEvent) -> Result<()> {
        let mut events = self.events
            .lock()
            .map_err(|e| CoreError::Internal(format!("Lock poisoned: {e}")))?;

        if events.len() >= self.max_events {
            events.pop_front();
        }

        events.push_back(TimestampedEvent {
            event,
            inserted_at: Instant::now(),
        });

        Ok(())
    }

    pub fn get_events_in_window(&self, seconds: u64) -> Result<Vec<BehavioralEvent>> {
        let events = self.events
            .lock()
            .map_err(|e| CoreError::Internal(format!("Lock poisoned: {e}")))?;

        let cutoff = Instant::now() - Duration::from_secs(seconds);

        Ok(events
            .iter()
            .filter(|te| te.inserted_at >= cutoff)
            .map(|te| te.event.clone())
            .collect())
    }

    pub fn get_events_for_pid(&self, pid: u32) -> Result<Vec<BehavioralEvent>> {
        let events = self.events
            .lock()
            .map_err(|e| CoreError::Internal(format!("Lock poisoned: {e}")))?;

        Ok(events
            .iter()
            .map(|te| &te.event)
            .filter(|e| e.pid() == pid)
            .cloned()
            .collect())
    }

    pub fn get_events_in_window_for_pid(
        &self,
        seconds: u64,
        pid: u32,
    ) -> Result<Vec<BehavioralEvent>> {
        let events = self.events
            .lock()
            .map_err(|e| CoreError::Internal(format!("Lock poisoned: {e}")))?;

        let cutoff = Instant::now() - Duration::from_secs(seconds);

        Ok(events
            .iter()
            .filter(|te| te.inserted_at >= cutoff && te.event.pid() == pid)
            .map(|te| te.event.clone())
            .collect())
    }

    pub fn clear(&self) -> Result<()> {
        let mut events = self.events
            .lock()
            .map_err(|e| CoreError::Internal(format!("Lock poisoned: {e}")))?;
        events.clear();
        Ok(())
    }

    pub fn len(&self) -> Result<usize> {
        let events = self.events
            .lock()
            .map_err(|e| CoreError::Internal(format!("Lock poisoned: {e}")))?;
        Ok(events.len())
    }

    pub fn is_empty(&self) -> Result<bool> {
        let events = self.events
            .lock()
            .map_err(|e| CoreError::Internal(format!("Lock poisoned: {e}")))?;
        Ok(events.is_empty())
    }
}
