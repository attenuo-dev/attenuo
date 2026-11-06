//! Where the server and the proxy read the time from for their TTL and window checks.
//!
//! Production code uses [`SystemClock`], which reads the system clock, exactly as calling
//! [`OffsetDateTime::now_utc`] and [`Instant::now`] directly would. Tests use
//! [`ManualClock`] to step past a TTL or a window with [`ManualClock::advance`] instead of
//! sleeping through it.

use std::fmt::Debug;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use time::OffsetDateTime;

/// A source of wall-clock and monotonic time.
pub trait Clock: Send + Sync + Debug {
    /// The current wall-clock time, in UTC.
    fn now_utc(&self) -> OffsetDateTime;
    /// The current monotonic time.
    fn now(&self) -> Instant;
}

/// The system clock: [`OffsetDateTime::now_utc`] and [`Instant::now`].
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_utc(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }

    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// The system clock as a shared [`Clock`], the default wherever a clock can be injected.
pub fn system_clock() -> Arc<dyn Clock> {
    Arc::new(SystemClock)
}

/// For tests: the system clock plus an offset that only [`advance`](Self::advance) changes.
///
/// Time keeps running, so code that measures how long something took still sees it take
/// time; `advance` jumps both readings forward at once, so a TTL or a window can be passed
/// without waiting for it. Never in production: nothing about it is configurable from a
/// config file.
#[derive(Debug, Default)]
pub struct ManualClock {
    offset: Mutex<Duration>,
}

impl ManualClock {
    /// A clock that reads the same as the system clock until it is advanced.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Move the clock forward by `by`.
    pub fn advance(&self, by: Duration) {
        let mut offset = self.offset.lock().unwrap_or_else(|e| e.into_inner());
        *offset += by;
    }

    fn offset(&self) -> Duration {
        *self.offset.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl Clock for ManualClock {
    fn now_utc(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc() + self.offset()
    }

    fn now(&self) -> Instant {
        Instant::now() + self.offset()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_manual_clock_reads_the_system_clock_until_advanced() {
        let clock = ManualClock::new();
        let (wall, mono) = (OffsetDateTime::now_utc(), Instant::now());
        assert!(clock.now_utc() >= wall && clock.now_utc() - wall < time::Duration::minutes(1));
        assert!(clock.now() >= mono && clock.now() - mono < Duration::from_secs(60));
        clock.advance(Duration::from_secs(3600));
        clock.advance(Duration::from_secs(1));
        assert!(clock.now_utc() - wall >= time::Duration::seconds(3601));
        assert!(clock.now() - mono >= Duration::from_secs(3601));
        let system = system_clock();
        assert!(system.now_utc() < clock.now_utc());
        assert!(system.now() < clock.now());
    }
}
