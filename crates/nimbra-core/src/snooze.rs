//! Snooze and reminders: a thread put away until a time (or, for a reminder, until a time
//! unless someone replies), and bringing it back. The macOS app keeps its own list with its
//! rows (`threads.rs` there); `Snoozed` is the list for other front ends (iOS, through
//! `nimbra-ffi`), kept in the account's store under its own name.

use serde::{Deserialize, Serialize};

use crate::mail;
use crate::store::Store;

/// The record the list is kept under. Not the macOS app's ("snoozed"), whose rows differ.
const LIST: &str = "snoozes";

/// A thread put away until later.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Snoozed {
    pub thread_id: String,
    /// When it comes back (or, for a reminder, when to check for a reply).
    pub until_ms: i64,
    /// Only come back if nobody has written since: a reminder.
    pub no_reply: bool,
    /// The time of the thread's latest message when it was put away.
    pub since_ms: i64,
    /// Its row then, to list it under Snoozed or Reminders.
    pub subject: String,
    pub sender: String,
    pub snippet: String,
}

pub fn list(store: &Store) -> Vec<Snoozed> {
    store.load(LIST).unwrap_or_default()
}

/// Adds one, replacing a snooze of the same thread. Blocking.
pub fn add(store: &Store, item: Snoozed) -> anyhow::Result<()> {
    store.update(LIST, |list: &mut Vec<Snoozed>| {
        list.retain(|kept| kept.thread_id != item.thread_id);
        list.push(item);
    })?;
    Ok(())
}

/// Takes a thread's snooze out (cancelled, or it came back). Whether there was one.
/// Blocking.
pub fn remove(store: &Store, thread_id: &str) -> anyhow::Result<bool> {
    let mut found = false;
    store.update(LIST, |list: &mut Vec<Snoozed>| {
        let before = list.len();
        list.retain(|kept| kept.thread_id != thread_id);
        found = list.len() != before;
    })?;
    Ok(found)
}

/// Brings a snoozed thread back if it is still away: into the inbox, unread. Whether it
/// came back. A reminder is not needed once someone wrote, and a snooze is over by itself
/// once a reply put the thread back in the inbox.
pub fn wake(
    client: &mail::Client,
    id: &str,
    since_ms: i64,
    no_reply: bool,
) -> anyhow::Result<bool> {
    let now = client.summary(id, false)?;
    let answered = now.timestamp_ms > since_ms;
    if answered && (no_reply || now.labels.iter().any(|l| l == "INBOX")) {
        return Ok(false);
    }
    client.relabel(id, &["INBOX", "UNREAD"], &[])?;
    Ok(true)
}

/// Brings back every snooze of this account that is due at `now_ms` (`wake`), and takes it
/// off the list: also a reminder that is no longer needed. The threads that came back.
/// One that could not be checked (offline) stays for the next time. Blocking.
pub fn wake_due(store: &Store, client: &mail::Client, now_ms: i64) -> Vec<String> {
    let due: Vec<Snoozed> = list(store)
        .into_iter()
        .filter(|item| item.until_ms <= now_ms)
        .collect();
    let mut woken = Vec::new();
    for item in due {
        match wake(client, &item.thread_id, item.since_ms, item.no_reply) {
            Ok(back) => {
                if remove(store, &item.thread_id).is_err() {
                    eprintln!("nimbra: could not save the snoozed list");
                }
                if back {
                    woken.push(item.thread_id);
                }
            }
            Err(_) => continue,
        }
    }
    woken
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(thread: &str, until_ms: i64) -> Snoozed {
        Snoozed {
            thread_id: thread.into(),
            until_ms,
            no_reply: false,
            since_ms: 1,
            subject: "Hi".into(),
            sender: "Ana".into(),
            snippet: String::new(),
        }
    }

    #[test]
    fn a_thread_is_snoozed_once_and_taken_off_again() {
        let store = Store::temp();
        add(&store, item("t1", 10)).unwrap();
        add(&store, item("t2", 20)).unwrap();
        add(&store, item("t1", 30)).unwrap();
        let kept = list(&store);
        assert_eq!(kept.len(), 2);
        assert_eq!(
            kept.iter().find(|s| s.thread_id == "t1").unwrap().until_ms,
            30
        );
        assert!(remove(&store, "t1").unwrap());
        assert!(!remove(&store, "t1").unwrap());
        assert_eq!(list(&store), vec![item("t2", 20)]);
    }
}
