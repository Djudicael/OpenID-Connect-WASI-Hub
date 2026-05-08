//! Clock trait for mockable time.

/// A trait for getting the current time.
/// Allows deterministic testing by injecting a mock clock.
pub trait Clock: Send + Sync {
    /// Returns the current Unix timestamp in seconds.
    fn now_secs(&self) -> i64;
}

/// Production clock using the system time.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_secs(&self) -> i64 {
        chrono::Utc::now().timestamp()
    }
}

/// Mock clock for deterministic tests.
pub struct MockClock {
    timestamp: i64,
}

impl MockClock {
    /// Create a new mock clock at a specific timestamp.
    pub fn new(timestamp: i64) -> Self {
        Self { timestamp }
    }

    /// Advance the clock by the given number of seconds.
    pub fn advance(&mut self, secs: i64) {
        self.timestamp += secs;
    }
}

impl Clock for MockClock {
    fn now_secs(&self) -> i64 {
        self.timestamp
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_clock() {
        let mut clock = MockClock::new(1000);
        assert_eq!(clock.now_secs(), 1000);
        clock.advance(500);
        assert_eq!(clock.now_secs(), 1500);
    }
}
