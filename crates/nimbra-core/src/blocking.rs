//! Blocked senders. Their mail goes straight to the "Blocked" label (or folder), read and
//! out of the inbox, and never notifies; the same label Spark files them under, so an
//! account blocked there carries on. The list is each account's own, kept in its store
//! on this Mac. Mail that arrives while Nimbra is closed is moved on the next look.

use crate::mail::{self, Summary, View};
use crate::store::Store;
use anyhow::Result;
use serde::{Deserialize, Serialize};

/// The label blocked mail goes to.
pub const LABEL: &str = "Blocked";

/// How many threads of the Blocked label teach the list its senders at first.
const SEED_THREADS: usize = 200;

#[derive(Default, Serialize, Deserialize)]
pub struct Blocklist {
    /// Bare addresses, lowercase.
    pub senders: Vec<String>,
    /// Whether the senders already in the Blocked label have been taken in.
    #[serde(default)]
    pub seeded: bool,
}

const KEY: &str = "blocked";

pub fn load(store: &Store) -> Blocklist {
    store.load(KEY).unwrap_or_default()
}

/// Adds (or with `on` false, takes out) a sender. Gives back whether it was a valid address.
pub fn set(store: &Store, address: &str, on: bool) -> Result<bool> {
    let address = address.trim().to_lowercase();
    if !mail::is_address(&address) {
        return Ok(false);
    }
    store.update(KEY, |list: &mut Blocklist| {
        list.senders.retain(|s| *s != address);
        if on {
            list.senders.push(address);
        }
    })?;
    Ok(true)
}

/// Whether `name` is the Blocked label (also when nested, as "Spark/Blocked").
pub fn is_label(name: &str) -> bool {
    let last = name.rsplit('/').next().unwrap_or(name).trim();
    last.eq_ignore_ascii_case(LABEL)
}

/// The Blocked label's id, made if the account has none yet.
pub fn label_id(client: &mail::Client) -> Result<String> {
    if let Some(label) = client.labels()?.into_iter().find(|l| is_label(&l.name)) {
        return Ok(label.id);
    }
    Ok(client.create_label(LABEL)?.id)
}

/// Whether the thread's latest message from someone else is from a blocked sender.
pub fn blocks(senders: &[String], thread: &Summary) -> bool {
    let own = |index: usize| {
        thread
            .message_labels
            .get(index)
            .is_some_and(|labels| labels.iter().any(|l| l == "SENT" || l == "DRAFT"))
    };
    let theirs = thread
        .senders
        .iter()
        .enumerate()
        .rev()
        .find(|(index, _)| !own(*index))
        .map(|(_, sender)| sender);
    theirs.is_some_and(|sender| senders.iter().any(|s| s == sender))
}

/// Blocks a sender: on the account's list from now on, and their threads in the inbox put
/// away in the Blocked label (made when there is none). The label's id and how many threads
/// went there. Blocking (network).
pub fn block(client: &mail::Client, store: &Store, address: &str) -> Result<(String, usize)> {
    if !set(store, address, true)? {
        anyhow::bail!("That sender has no address to block.");
    }
    // Their other threads in the inbox go too.
    let label = label_id(client)?;
    let moved = sweep(client, store);
    Ok((label, moved))
}

/// Moves a thread to the Blocked label: out of the inbox, and read.
pub fn put_away(client: &mail::Client, thread: &str, label: &str) -> Result<()> {
    client.relabel(thread, &[label], &["INBOX", "UNREAD"])
}

/// Of the threads that just got new mail, the ones from blocked senders are moved away;
/// the rest are given back, to notify about. Blocking: runs off the main thread.
pub fn screen(client: &mail::Client, store: &Store, fresh: Vec<String>) -> Vec<String> {
    let list = load(store);
    if list.senders.is_empty() {
        return fresh;
    }
    let mut label = None;
    fresh
        .into_iter()
        .filter(|id| {
            let Ok(thread) = client.summary(id, false) else {
                return true;
            };
            if !blocks(&list.senders, &thread) {
                return true;
            }
            if label.is_none() {
                label = label_id(client).ok();
            }
            // Moved or not, a blocked sender does not notify.
            if let Some(label) = &label
                && put_away(client, id, label).is_err()
            {
                eprintln!("nimbra: could not move a blocked thread");
            }
            false
        })
        .collect()
}

/// Once per session for each account: takes in the senders already in the Blocked label
/// (the first time), then moves what blocked senders left in the inbox meanwhile.
/// Gives back how many threads it moved.
pub fn sweep(client: &mail::Client, store: &Store) -> usize {
    let mut list = load(store);
    if !list.seeded {
        let found = seed(client);
        if let Ok(saved) = store.update(KEY, |kept: &mut Blocklist| {
            for sender in found {
                if !kept.senders.contains(&sender) {
                    kept.senders.push(sender);
                }
            }
            kept.seeded = true;
        }) {
            list = saved;
        }
    }
    if list.senders.is_empty() {
        return 0;
    }
    let Ok((inbox, _)) = client.threads_page(View::Inbox, None, 100, None) else {
        return 0;
    };
    let blocked: Vec<&Summary> = inbox.iter().filter(|t| blocks(&list.senders, t)).collect();
    if blocked.is_empty() {
        return 0;
    }
    let Ok(label) = label_id(client) else {
        return 0;
    };
    blocked
        .iter()
        .filter(|t| put_away(client, &t.id, &label).is_ok())
        .count()
}

/// The senders of the mail already in the Blocked label, if the account has one.
fn seed(client: &mail::Client) -> Vec<String> {
    let Ok(labels) = client.labels() else {
        return Vec::new();
    };
    let Some(label) = labels.into_iter().find(|l| is_label(&l.name)) else {
        return Vec::new();
    };
    let Ok((threads, _)) = client.threads_page(View::Label(0), Some(&label.id), SEED_THREADS, None)
    else {
        return Vec::new();
    };
    let mut senders: Vec<String> = Vec::new();
    for thread in &threads {
        for (sender, labels) in thread.senders.iter().zip(&thread.message_labels) {
            let own = labels.iter().any(|l| l == "SENT" || l == "DRAFT");
            if !own && mail::is_address(sender) && !senders.contains(sender) {
                senders.push(sender.clone());
            }
        }
    }
    senders
}

#[cfg(test)]
mod tests {
    use super::*;

    fn thread(messages: &[(&str, &[&str])]) -> Summary {
        Summary {
            id: "t".into(),
            sender: String::new(),
            sender_address: String::new(),
            brand_domain: None,
            subject: String::new(),
            snippet: String::new(),
            timestamp_ms: 0,
            message_count: messages.len(),
            unread: true,
            starred: false,
            labels: Vec::new(),
            message_labels: messages
                .iter()
                .map(|(_, l)| l.iter().map(|s| s.to_string()).collect())
                .collect(),
            senders: messages.iter().map(|(s, _)| s.to_string()).collect(),
            people: Vec::new(),
        }
    }

    #[test]
    fn the_latest_message_from_someone_else_decides() {
        let blocked = vec!["spam@ads.example".to_string()];
        assert!(blocks(
            &blocked,
            &thread(&[("spam@ads.example", &["INBOX"])])
        ));
        // My own reply after theirs does not unblock it.
        assert!(blocks(
            &blocked,
            &thread(&[
                ("spam@ads.example", &["INBOX"]),
                ("me@home.example", &["SENT"])
            ])
        ));
        // Someone else wrote last.
        assert!(!blocks(
            &blocked,
            &thread(&[("spam@ads.example", &[]), ("ana@work.example", &["INBOX"])])
        ));
        assert!(!blocks(&[], &thread(&[("spam@ads.example", &["INBOX"])])));
    }

    #[test]
    fn the_label_is_found_by_name_also_when_nested() {
        assert!(is_label("Blocked"));
        assert!(is_label("blocked"));
        assert!(is_label("Spark/Blocked"));
        assert!(!is_label("Blocked senders"));
    }
}
