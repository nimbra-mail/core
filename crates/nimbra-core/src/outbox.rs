//! What waits for the connection, and the decisions about a message on its way out: the
//! offline queue of changes (Done, a star) made while the server could not be reached, the
//! catch-up that makes them and sends what waits once it can, what a failed send means,
//! and what becomes of a message an earlier run left (`sending::Job::left_behind`).
//!
//! The apps own the timers: they retry every `RETRY_EVERY` (or sooner, when the network is
//! back), and hand each message to the server once its undo time (`undo_delay`) is over.

use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::mail;
use crate::sending::{Job, QueuedMail, Stage};
use crate::store::Store;

/// The record each account's offline queue is kept under.
pub const RECORD: &str = "outbox";

/// How long to wait before checking again whether the server can be reached.
pub const RETRY_EVERY: Duration = Duration::from_secs(15);

/// The longest a sent message can still be taken back.
pub const LONGEST_UNDO: Duration = Duration::from_secs(60);

/// Changes and messages made while offline, sent once the server can be reached again.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct Outbox {
    pub changes: Vec<(String, mail::Change)>,
    /// Only as earlier versions saved it: waiting mail has records of its own now (see
    /// `sending`), and these become such records when the store opens.
    #[serde(default)]
    pub mail: Vec<QueuedMail>,
}

/// The offline queue as kept. Blocking (disk).
pub fn load(store: &Store) -> Outbox {
    store.load(RECORD).unwrap_or_default()
}

/// Puts a change that could not be made into the account's offline queue, after what waits
/// there. Blocking (disk).
pub fn queue(store: &Store, thread_id: &str, change: mail::Change) -> anyhow::Result<()> {
    store.update(RECORD, |outbox: &mut Outbox| {
        outbox.changes.push((thread_id.to_string(), change))
    })?;
    Ok(())
}

/// What a catch-up got done.
#[derive(Default)]
pub struct CaughtUp {
    pub changes: usize,
    pub sent: usize,
    /// Not sent by itself: the subject, whether it may have arrived all the same, and
    /// whether Drafts has it.
    pub kept: Vec<(String, bool, bool)>,
}

/// Sends what waited for the connection, in order. Blocking.
pub fn catch_up(
    client: &mail::Client,
    changes: &[(String, mail::Change)],
    queue: &[Arc<Job>],
) -> anyhow::Result<CaughtUp> {
    // Is the server reachable again?
    client.profile()?;
    let mut done = CaughtUp::default();
    for (id, change) in changes {
        match client.change(id, *change) {
            Err(error) if error.is::<mail::Offline>() => return Ok(done),
            // Anything else (the thread is gone, say) is dropped.
            _ => done.changes += 1,
        }
    }
    for job in queue {
        match job.send() {
            None => {}
            Some(Ok(())) => done.sent += 1,
            Some(Err(_)) => {
                let unsure = match job.stage() {
                    Stage::Held => break, // still offline
                    stage => stage == Stage::Unsure,
                };
                done.kept.push((job.subject(), unsure, job.to_drafts()));
            }
        }
    }
    Ok(done)
}

/// The offline queue read from a store, without the `caught_up` changes at its start that
/// were made since it was read, and with what was queued meanwhile after it.
pub fn with_caught_up(
    mut read: Outbox,
    caught_up: usize,
    mut meanwhile: Vec<(String, mail::Change)>,
) -> Outbox {
    read.changes.drain(..caught_up.min(read.changes.len()));
    read.changes.append(&mut meanwhile);
    read
}

/// Takes the changes a catch-up got through out of a kept queue. Whether anything is left.
/// Blocking (disk).
pub fn drop_caught_up(store: &Store, changes: usize) -> anyhow::Result<bool> {
    let mut left = false;
    store.update(RECORD, |outbox: &mut Outbox| {
        outbox.changes.drain(..changes.min(outbox.changes.len()));
        left = !outbox.changes.is_empty();
    })?;
    Ok(left)
}

// ------------------------------------------------------------------ decisions

/// How long a sent message can still be taken back, as set (`Settings.undo_send`, seconds).
pub fn undo_delay(seconds: u32) -> Duration {
    Duration::from_secs(seconds as u64).min(LONGEST_UNDO)
}

/// Why a message may not be sent as it is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NotReady {
    /// An address is not one (the provider's words).
    Recipients(String),
    /// No subject, no text and no files.
    Empty,
    /// The files are over `mail::ATTACHMENT_LIMIT` in total.
    TooLarge,
}

/// Whether a message may be sent as it is.
pub fn ready(outgoing: &mail::Outgoing) -> Result<(), NotReady> {
    if let Err(error) = outgoing.recipients() {
        return Err(NotReady::Recipients(error.to_string()));
    }
    if outgoing.subject.trim().is_empty()
        && outgoing.body.trim().is_empty()
        && outgoing.files.is_empty()
    {
        return Err(NotReady::Empty);
    }
    if outgoing.attachment_size() > mail::ATTACHMENT_LIMIT {
        return Err(NotReady::TooLarge);
    }
    Ok(())
}

/// What a failed send means.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failed {
    /// The server could not be reached and nothing left: it waits in the queue.
    Offline,
    /// A request was out and its answer never came: it may have been sent. Never sent again
    /// by itself: to Drafts, and the user checks Sent.
    Unsure,
    /// The server said no: back to the user (or to Drafts).
    Refused,
}

/// What a failed send means, from its error.
pub fn failed(error: &anyhow::Error) -> Failed {
    if error.is::<mail::MayHaveArrived>() {
        Failed::Unsure
    } else if error.is::<mail::Offline>() {
        Failed::Offline
    } else {
        Failed::Refused
    }
}

/// What to do with a message an earlier run left in the store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PickUp {
    /// It never left: send it.
    Send,
    /// It may already have gone (a request was out): to Drafts, never sent again by itself.
    MaybeSent,
    /// The server refused it: to Drafts.
    Refused,
    /// It was still being written when the app quit: to Drafts.
    Writing,
    /// It was to be sent later, and that was not written down before the app quit: to
    /// Drafts.
    Unscheduled,
    /// It was discarded as the app quit: delete what was saved of it.
    Discard,
    /// Nothing is left of it.
    Forget,
}

/// What to do with a message found in the store (`Job::left_behind`).
pub fn pick_up(stage: Stage) -> PickUp {
    match stage {
        Stage::Held => PickUp::Send,
        Stage::Out | Stage::Unsure => PickUp::MaybeSent,
        Stage::Refused => PickUp::Refused,
        Stage::Writing => PickUp::Writing,
        Stage::Unscheduled => PickUp::Unscheduled,
        Stage::Discarded => PickUp::Discard,
        Stage::Over => PickUp::Forget,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn change(id: &str) -> (String, mail::Change) {
        (id.to_string(), mail::Change::Archive)
    }

    #[test]
    fn the_queue_read_as_the_store_opens_loses_what_was_caught_up_and_keeps_the_rest() {
        let read = Outbox {
            changes: vec![change("a"), change("b"), change("c")],
            ..Outbox::default()
        };
        let merged = with_caught_up(read, 2, vec![change("d")]);
        let ids: Vec<&str> = merged.changes.iter().map(|(id, _)| id.as_str()).collect();
        assert_eq!(ids, ["c", "d"]);
    }

    #[test]
    fn a_queue_handed_to_the_writer_is_on_disk_once_quitting_has_flushed() {
        let (store, release) = Store::temp_held();
        let outbox = Outbox {
            changes: vec![change("a"), change("b")],
            ..Outbox::default()
        };
        store.save_soon(RECORD, outbox.clone());
        drop(release);
        // What a later launch reads, through a store of its own.
        let reader = Store::temp_like(&store);
        assert!(crate::store::flush_store(
            &store,
            std::time::Instant::now() + Duration::from_secs(30)
        ));
        let back: Outbox = reader.load(RECORD).unwrap();
        assert_eq!(back.changes.len(), 2);
    }

    #[test]
    fn changes_made_offline_are_made_once_the_server_is_back() {
        let fake = crate::testing::Fake::new("me@example.com");
        fake.add(crate::testing::Fake::thread("a", &["INBOX"], 1));
        let client: Arc<mail::Client> = fake.clone();
        let store = Store::temp();
        queue(&store, "a", mail::Change::Archive).unwrap();
        queue(&store, "gone", mail::Change::Star).unwrap();
        fake.offline
            .store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(catch_up(&*client, &load(&store).changes, &[]).is_err());
        fake.offline
            .store(false, std::sync::atomic::Ordering::SeqCst);
        let done = catch_up(&*client, &load(&store).changes, &[]).unwrap();
        assert_eq!(done.changes, 2, "one that cannot be made is dropped");
        assert!(!drop_caught_up(&store, done.changes).unwrap());
        assert!(!fake.labels_of("a").contains(&"INBOX".to_string()));
    }

    #[test]
    fn a_send_that_may_have_gone_is_never_sent_again_by_itself() {
        assert_eq!(
            failed(&anyhow::Error::msg(mail::MayHaveArrived)),
            Failed::Unsure
        );
        assert_eq!(failed(&mail::Offline.into()), Failed::Offline);
        assert_eq!(failed(&anyhow::anyhow!("no")), Failed::Refused);
        assert_eq!(pick_up(Stage::Out), PickUp::MaybeSent);
        assert_eq!(pick_up(Stage::Held), PickUp::Send);
        assert_eq!(undo_delay(600), LONGEST_UNDO);
    }

    #[test]
    fn a_message_needs_recipients_and_something_in_it() {
        let mut message = mail::Outgoing {
            to: "ana@example.com".into(),
            ..mail::Outgoing::default()
        };
        assert_eq!(ready(&message), Err(NotReady::Empty));
        message.subject = "Hi".into();
        assert_eq!(ready(&message), Ok(()));
        message.to = "not an address".into();
        assert!(matches!(ready(&message), Err(NotReady::Recipients(_))));
    }
}
