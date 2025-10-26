use std::time::Instant;

/// Abstraction over a time source to improve testability.
pub trait Clock: Send + Sync + 'static {
    /// Returns the current time instant.
    fn now(&self) -> Instant;
}

/// System clock using `Instant::now()`.
#[derive(Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    #[inline]
    fn now(&self) -> Instant {
        Instant::now()
    }
}
