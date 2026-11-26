//! Send later. Each account's store has its list, which is the truth: whoever sends from
//! it takes the message out there and then, whichever account is shown by that time.

use serde::{Deserialize, Serialize};

use crate::mail;
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

/// The same, handed to the store's writer: on disk before quitting ends. The answer says
/// whether it was written.
pub fn add_soon(
    store: &std::sync::Arc<Store>,
    item: Scheduled,
) -> futures::channel::oneshot::Receiver<anyhow::Result<()>> {
    store.update_soon(LIST, move |list: &mut Vec<Scheduled>| {
        list.retain(|kept| kept.draft_id != item.draft_id);
        list.push(item);
    })
}

/// Takes one off the list without sending it (its draft stays). Blocking.
pub fn remove(store: &Store, draft_id: &str) -> anyhow::Result<()> {
    store.update(LIST, |list: &mut Vec<Scheduled>| {
        list.retain(|kept| kept.draft_id != draft_id);
    })?;
    Ok(())
}

/// Sends one, unless someone else is on it or has sent it. `None`: nothing came of it.
/// Blocking.
pub fn send(store: &Store, client: &mail::Client, draft_id: &str) -> Option<Outcome> {
    let name = claim_name(draft_id);
    let _claim = store.claim(&name)?;
    if !list(store).iter().any(|item| item.draft_id == draft_id) {
        store.remove(&name);
        return None;
    }
    let outcome = match client.send_saved_draft(draft_id) {
        Ok(()) => Outcome::Sent,
        Err(error) if mail::is_gone(&error) => Outcome::Gone,
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

/// The times Send later offers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Later {
    /// An hour from now, on the minute.
    InAnHour,
    /// 18:00 today, before 17:00.
    ThisEvening,
    /// 8:00 tomorrow.
    TomorrowMorning,
    /// 8:00 next Monday, unless that is tomorrow.
    MondayMorning,
}

/// The times Send later offers from `now`, in order.
pub fn later_times(
    now: chrono::DateTime<chrono::Local>,
) -> Vec<(Later, chrono::DateTime<chrono::Local>)> {
    use chrono::{Datelike, Duration as Days, Local, TimeZone, Timelike, Weekday};
    let at = |date: chrono::NaiveDate, hour: u32| {
        Local
            .from_local_datetime(&date.and_hms_opt(hour, 0, 0).unwrap_or_default())
            .single()
    };
    let mut choices = Vec::new();
    choices.push((
        Later::InAnHour,
        (now + Days::hours(1)).with_second(0).unwrap_or(now),
    ));
    if now.hour() < 17
        && let Some(when) = at(now.date_naive(), 18)
    {
        choices.push((Later::ThisEvening, when));
    }
    let tomorrow = now.date_naive() + Days::days(1);
    if let Some(when) = at(tomorrow, 8) {
        choices.push((Later::TomorrowMorning, when));
    }
    let mut monday = now.date_naive() + Days::days(1);
    while monday.weekday() != Weekday::Mon {
        monday += Days::days(1);
    }
    if monday != tomorrow
        && let Some(when) = at(monday, 8)
    {
        choices.push((Later::MondayMorning, when));
    }
    choices
}

/// When the next one is due, if any: when to look again.
pub fn next_due(store: &Store) -> Option<i64> {
    list(store).iter().map(|item| item.at_ms).min()
}

fn claim_name(draft_id: &str) -> String {
    let id: String = draft_id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .take(48)
        .collect();
    format!("due-{id}")
}
