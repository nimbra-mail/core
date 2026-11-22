//! Send later. Each account's store has its list, which is the truth: whoever sends from
//! it takes the message out there and then, whichever account is shown by that time.

use serde::{Deserialize, Serialize};

use crate::gmail;
use crate::store::Store;

const LIST: &str = "scheduled";

/// A message to send later: its saved draft and when.
#[derive(Clone, Serialize, Deserialize)]
pub struct Scheduled {
    pub draft_id: String,
    pub at_ms: i64,
    pub subject: String,
    /// The account the draft is in, when not the one whose store keeps this list.
    #[serde(default)]
    pub account: Option<String>,
}

#[derive(Debug, PartialEq)]
pub enum Outcome {
    Sent,
    /// Its draft is gone: sent already, or deleted.
    Gone,
}

pub fn list(store: &Store) -> Vec<Scheduled> {
    store.load(LIST).unwrap_or_default()
}

pub fn add(store: &Store, item: Scheduled) -> anyhow::Result<()> {
    store.update(LIST, |list: &mut Vec<Scheduled>| {
        list.retain(|kept| kept.draft_id != item.draft_id);
        list.push(item);
    })?;
    Ok(())
}

/// Sends one, unless someone else is on it or has sent it. `None`: nothing came of it.
/// Blocking.
pub fn send(store: &Store, client: &gmail::Client, draft_id: &str) -> Option<Outcome> {
    let name = claim_name(draft_id);
    let _claim = store.claim(&name)?;
    if !list(store).iter().any(|item| item.draft_id == draft_id) {
        store.remove(&name);
        return None;
    }
    let outcome = match client.send_saved_draft(draft_id) {
        Ok(()) => Outcome::Sent,
        Err(error) if gmail::is_gone(&error) => Outcome::Gone,
        // Tried again on a later check. That cannot send it twice: sending uses the draft up.
        Err(_) => return None,
    };
    let taken_out = store.update(LIST, |list: &mut Vec<Scheduled>| {
        list.retain(|item| item.draft_id != draft_id);
    });
    if taken_out.is_err() {
        eprintln!("nimbra: could not save the send-later list");
    }
    store.remove(&name);
    Some(outcome)
}

fn claim_name(draft_id: &str) -> String {
    let id: String = draft_id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .take(48)
        .collect();
    format!("due-{id}")
}
