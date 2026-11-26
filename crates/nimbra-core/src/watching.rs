//! Watching for new mail while an app is open: how often to check, and waiting for the
//! server to say something changed in between (IMAP IDLE). Gmail has no way to say so to a
//! mail app: its connection answers at once, and the check waits out the interval.

use std::time::{Duration, Instant};

use crate::mail;

/// The longest one wait on the server lasts, so that whoever waits can stop (the account
/// was switched or left) within it.
pub const SLICE: Duration = Duration::from_secs(30);

/// The fewest seconds between two checks (`Settings.check_every`), and the most.
pub const FASTEST: u32 = 10;
pub const SLOWEST: u32 = 3600;

/// How long to wait between two checks for mail, as set (seconds).
pub fn check_interval(check_every: u32) -> Duration {
    Duration::from_secs(check_every.clamp(FASTEST, SLOWEST) as u64)
}

/// How a wait ended (`wait`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Woke {
    /// The server said something changed: check now.
    Changed,
    /// The time is up: check now.
    TimedOut,
    /// `cancelled` said to stop.
    Cancelled,
}

/// Waits up to `wait` for the server to say something changed, in slices of at most
/// `SLICE`, asking `cancelled` between them. A provider that cannot say (Gmail) makes this
/// a plain wait of the same length, cut short by `cancelled` too. Blocking.
pub fn wait(client: &mail::Client, wait: Duration, cancelled: impl Fn() -> bool) -> Woke {
    let began = Instant::now();
    loop {
        if cancelled() {
            return Woke::Cancelled;
        }
        let left = wait.saturating_sub(began.elapsed());
        if left.is_zero() {
            return Woke::TimedOut;
        }
        let slice = left.min(SLICE);
        let sliced = Instant::now();
        if client.wait_for_change(slice) {
            return Woke::Changed;
        }
        // Answered at once (no IDLE): the slice is waited here, a little at a time.
        let mut rest = slice.saturating_sub(sliced.elapsed());
        while !rest.is_zero() {
            if cancelled() {
                return Woke::Cancelled;
            }
            let step = rest.min(Duration::from_millis(250));
            std::thread::sleep(step);
            rest = rest.saturating_sub(step);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn the_interval_stays_between_ten_seconds_and_an_hour() {
        assert_eq!(check_interval(1), Duration::from_secs(10));
        assert_eq!(check_interval(60), Duration::from_secs(60));
        assert_eq!(check_interval(u32::MAX), Duration::from_secs(3600));
    }

    #[test]
    fn a_wait_ends_on_a_change_on_time_or_when_cancelled() {
        let fake = crate::testing::Fake::new("me@example.com");
        let client: Arc<mail::Client> = fake.clone();
        fake.changed.store(true, Ordering::SeqCst);
        assert_eq!(
            wait(&*client, Duration::from_secs(5), || false),
            Woke::Changed
        );
        let began = Instant::now();
        assert_eq!(
            wait(&*client, Duration::from_millis(300), || false),
            Woke::TimedOut
        );
        assert!(began.elapsed() >= Duration::from_millis(300));
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            stopping.store(true, Ordering::SeqCst);
        });
        let began = Instant::now();
        assert_eq!(
            wait(&*client, Duration::from_secs(20), || stop
                .load(Ordering::SeqCst)),
            Woke::Cancelled
        );
        assert!(began.elapsed() < Duration::from_secs(2));
    }
}
