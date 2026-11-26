//! `Engine`: live updates while the app is in the foreground, as the macOS app watches
//! (`nimbra_core::watching`): IMAP IDLE where the server has it, else the check interval.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use nimbra_core::{mail, watching};

use crate::engine::Engine;
use crate::error::Result;
use crate::types::*;

/// Waits for an account's server to say something changed. One per watch; cancel it from
/// any thread, and a wait under way ends within a moment (IMAP: within the current IDLE
/// slice, at most 30 seconds). Cancelling is for good: a `wait` after `cancel` (or one
/// begun before it) returns `Cancelled` at once, every time. To watch again, ask
/// `Engine::watch` for a new one.
#[derive(uniffi::Object)]
pub struct ChangeWatch {
    client: Arc<mail::Client>,
    cancelled: AtomicBool,
}

#[uniffi::export]
impl ChangeWatch {
    /// Waits up to `seconds` (the check interval from `Engine::check_interval_seconds`).
    /// `Changed`: check now (`check_for_changes`, `refresh_mailbox`); `TimedOut`: the
    /// interval is over, check now too; `Cancelled`: stop. Blocks: call it from a
    /// background task.
    pub fn wait(&self, seconds: u32) -> WatchOutcome {
        match watching::wait(&*self.client, Duration::from_secs(seconds as u64), || {
            self.cancelled.load(Ordering::SeqCst)
        }) {
            watching::Woke::Changed => WatchOutcome::Changed,
            watching::Woke::TimedOut => WatchOutcome::TimedOut,
            watching::Woke::Cancelled => WatchOutcome::Cancelled,
        }
    }

    /// Ends the waiting (the app goes to the background, or the account is left), now and
    /// for every later `wait`. Never blocks.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }
}

#[uniffi::export]
impl Engine {
    /// A watch on the account's server for live updates. Disk and Keychain (it opens the
    /// account; the server is first spoken to by `wait`).
    pub fn watch(&self, account_id: String) -> Result<Arc<ChangeWatch>> {
        let open = self.connect(&account_id)?;
        Ok(Arc::new(ChangeWatch {
            client: open.client.clone(),
            cancelled: AtomicBool::new(false),
        }))
    }

    /// How long to wait between two checks for mail, as set in Preferences (10 seconds to
    /// an hour). Memory only.
    pub fn check_interval_seconds(&self) -> u32 {
        watching::check_interval(self.preferences().check_every_seconds).as_secs() as u32
    }
}
