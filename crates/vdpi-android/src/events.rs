use serde::Serialize;
use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_EVENTS: usize = 120;

#[derive(Debug, Clone, Serialize)]
pub struct EngineEvent {
    pub ts_ms: u64,
    pub level: &'static str,
    pub tag: &'static str,
    pub message: String,
}

#[derive(Debug, Default)]
pub struct EventRing {
    inner: Mutex<VecDeque<EngineEvent>>,
}

impl EventRing {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&self, level: &'static str, tag: &'static str, message: impl Into<String>) {
        let ts_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        if let Ok(mut guard) = self.inner.lock() {
            if guard.len() >= MAX_EVENTS {
                guard.pop_front();
            }
            guard.push_back(EngineEvent {
                ts_ms,
                level,
                tag,
                message: message.into(),
            });
        }
    }

    pub fn snapshot(&self) -> Vec<EngineEvent> {
        self.inner
            .lock()
            .map(|g| g.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn clear(&self) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_caps_entries_at_max_events() {
        let ring = EventRing::new();
        for i in 0..(MAX_EVENTS + 25) {
            ring.push("info", "tun", format!("event {i}"));
        }
        let snap = ring.snapshot();
        assert_eq!(snap.len(), MAX_EVENTS);
        assert_eq!(snap.first().unwrap().message, "event 25");
        assert_eq!(
            snap.last().unwrap().message,
            format!("event {}", MAX_EVENTS + 24)
        );
    }
}
