/// Abstract clock for deterministic testing.
pub trait Clock: Send + Sync {
    /// Return the current time as seconds since UNIX epoch.
    fn now(&self) -> u64;
}

/// System clock implementation.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
}

/// Mock clock for tests.
pub struct MockClock {
    seconds: std::sync::atomic::AtomicU64,
}

impl MockClock {
    /// Create a new mock clock at the given time.
    pub fn at(seconds: u64) -> Self {
        Self {
            seconds: std::sync::atomic::AtomicU64::new(seconds),
        }
    }

    /// Advance the clock by the given number of seconds.
    pub fn advance(&self, seconds: u64) {
        self.seconds
            .fetch_add(seconds, std::sync::atomic::Ordering::Relaxed);
    }
}

impl Clock for MockClock {
    fn now(&self) -> u64 {
        self.seconds.load(std::sync::atomic::Ordering::Relaxed)
    }
}
