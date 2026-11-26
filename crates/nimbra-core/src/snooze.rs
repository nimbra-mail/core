//! Snooze and reminders: a thread put away until a time (or, for a reminder, until a time
//! unless someone replies), kept with its account in the store (Gmail's API has no snooze),
//! and brought back into the inbox, unread, when the time comes.
//!
//! Both apps keep the same list (`LIST`) and decide the same way; each owns only its
//! timers: `next_due` says when to look again, `wake_kept` brings one back.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Datelike, Duration as Days, Local, NaiveDate, TimeZone, Timelike, Weekday};
use serde::{Deserialize, Serialize};

use crate::listing::Row;
use crate::mail;
use crate::store::Store;

/// The record each account's snoozes are kept under.
pub const LIST: &str = "snoozed";

/// A thread put away until later (snooze), or until later unless someone replies
/// (a reminder).
#[derive(Clone, Serialize, Deserialize)]
pub struct Snooze {
    pub thread_id: String,
    /// When it comes back (or, for a reminder, when to check for a reply).
    pub until_ms: i64,
    /// Only come back if nobody has written since.
    pub no_reply: bool,
    /// The time of the thread's latest message when it was put away.
    pub since_ms: i64,
    /// The row, to list it under Snoozed (without its messages: they are downloaded again
    /// when it is opened, and are not written into the list each time it changes). Its
    /// `account` is set when it was snoozed from a list of several accounts' threads.
    pub mail: Row,
}

impl Snooze {
    /// `row` put away until `until_ms`; `no_reply` makes it a reminder.
    pub fn new(row: &Row, until_ms: i64, no_reply: bool) -> Self {
        Snooze {
            thread_id: row.id.clone().unwrap_or_default(),
            until_ms,
            no_reply,
            since_ms: row.timestamp_ms,
            mail: row.without_content(),
        }
    }
}

/// An account's snoozes, as kept. Blocking (disk).
pub fn list(store: &Store) -> Vec<Snooze> {
    store.load(LIST).unwrap_or_default()
}

/// Adds snoozes to a list, each replacing an earlier one of its thread.
pub fn put(list: &mut Vec<Snooze>, new: &[Snooze]) {
    list.retain(|kept| !new.iter().any(|s| s.thread_id == kept.thread_id));
    list.extend(new.iter().cloned());
}

/// Takes these threads' snoozes out of a list.
pub fn forget(list: &mut Vec<Snooze>, thread_ids: &[String]) {
    list.retain(|s| !thread_ids.contains(&s.thread_id));
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

/// `wake`, and out of the list kept in `store` once it is done with: brought back, not
/// needed any more, or the thread is gone. Only that snooze (by its time), as the list may
/// have changed meanwhile. Whether it came back. Blocking (network).
pub fn wake_kept(store: &Store, client: &mail::Client, item: &Snooze) -> anyhow::Result<bool> {
    let woken = wake(client, &item.thread_id, item.since_ms, item.no_reply);
    if woken.as_ref().map_or_else(mail::is_gone, |_| true)
        && store
            .update(LIST, |list: &mut Vec<Snooze>| {
                list.retain(|s| s.thread_id != item.thread_id || s.until_ms != item.until_ms);
            })
            .is_err()
    {
        eprintln!("nimbra: could not save the snoozed list");
    }
    woken
}

/// The snoozes due by `now_ms`.
pub fn due(list: &[Snooze], now_ms: i64) -> Vec<Snooze> {
    list.iter()
        .filter(|s| s.until_ms <= now_ms)
        .cloned()
        .collect()
}

/// When the next one is due: when to look again (a timer, a background task).
pub fn next_due(list: &[Snooze]) -> Option<i64> {
    list.iter().map(|s| s.until_ms).min()
}

/// The threads of `rows` (an inbox's listing) that a reply brought back while they were
/// snoozed: back in the inbox by themselves (as Gmail does), so their snoozes are over.
pub fn answered<'a>(list: &[Snooze], rows: impl IntoIterator<Item = &'a Row>) -> Vec<String> {
    rows.into_iter()
        .filter(|row| list.iter().any(|s| is_answered(s, row)))
        .filter_map(|row| row.id.clone())
        .collect()
}

/// Whether `row` (its thread now) has a message newer than when `snooze` put it away.
pub fn is_answered(snooze: &Snooze, row: &Row) -> bool {
    row.id.as_deref() == Some(snooze.thread_id.as_str()) && row.timestamp_ms > snooze.since_ms
}

/// The rows Snoozed (or, with `reminders`, Reminders) lists from these snoozes.
pub fn rows<'a>(list: impl IntoIterator<Item = &'a Snooze>, reminders: bool) -> Vec<Row> {
    list.into_iter()
        .filter(|s| s.no_reply == reminders)
        .map(|s| s.mail.clone())
        .collect()
}

/// For an account (by its store): wakes its due snoozes and sends its due scheduled
/// messages. One set from a list of several accounts can be another account's: it goes
/// through that account's connection (`connected`, by id). An account that is not connected
/// is left for later. `working` is called before each change to the server and held while
/// it is made (what quitting waits for). Gives back the snoozes it brought back, to notify
/// about. Blocking (network).
pub fn carry_out_due<G>(
    account: &str,
    store: &Store,
    connected: &HashMap<String, Arc<mail::Client>>,
    working: impl Fn() -> G,
) -> Vec<Snooze> {
    let now = chrono::Utc::now().timestamp_millis();
    let mut back = Vec::new();
    let client_of = |whose: Option<&str>| connected.get(whose.unwrap_or(account));
    for snooze in due(&list(store), now) {
        let Some(client) = client_of(snooze.mail.account.as_deref()) else {
            continue; // that account is not connected: later
        };
        let _working = working();
        if matches!(wake_kept(store, &**client, &snooze), Ok(true)) {
            back.push(snooze);
        }
    }
    for item in crate::scheduled::list(store) {
        if item.at_ms > now {
            continue;
        }
        if let Some(client) = client_of(item.account.as_deref()) {
            let _working = working();
            crate::scheduled::send(store, &**client, &item.draft_id);
        }
    }
    back
}

// ------------------------------------------------------------------ times

/// A local time on a day, if the clock has it (not inside a daylight-saving jump).
pub fn at(date: NaiveDate, hour: u32) -> Option<DateTime<Local>> {
    Local
        .from_local_datetime(&date.and_hms_opt(hour, 0, 0)?)
        .single()
}

/// The times the Snooze menu offers first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Quick {
    /// At 18:00, before 17:00.
    LaterToday,
    /// From 17:00 on.
    InThreeHours,
    /// 9:00.
    Tomorrow,
    /// 18:00.
    TomorrowEvening,
    /// Saturday 9:00, unless it is the weekend.
    ThisWeekend,
    /// Monday 9:00.
    NextWeek,
}

/// The quick times from `now`: later today, tomorrow morning and evening, the weekend,
/// next week. In order, each time once.
pub fn quick_times(now: DateTime<Local>) -> Vec<(Quick, DateTime<Local>)> {
    let today = now.date_naive();
    let tomorrow = today + Days::days(1);
    let mut choices = Vec::new();
    if now.hour() < 17 {
        choices.extend(at(today, 18).map(|w| (Quick::LaterToday, w)));
    } else {
        choices.push((Quick::InThreeHours, now + Days::hours(3)));
    }
    choices.extend(at(tomorrow, 9).map(|w| (Quick::Tomorrow, w)));
    choices.extend(at(tomorrow, 18).map(|w| (Quick::TomorrowEvening, w)));
    // The coming Saturday, unless it is already the weekend.
    if !matches!(now.weekday(), Weekday::Sat | Weekday::Sun) {
        let mut saturday = today + Days::days(1);
        while saturday.weekday() != Weekday::Sat {
            saturday += Days::days(1);
        }
        choices.extend(at(saturday, 9).map(|w| (Quick::ThisWeekend, w)));
    }
    let mut monday = today + Days::days(1);
    while monday.weekday() != Weekday::Mon {
        monday += Days::days(1);
    }
    choices.extend(at(monday, 9).map(|w| (Quick::NextWeek, w)));
    // On a Friday the weekend is tomorrow, on a Sunday next week is: each time once.
    choices.sort_by_key(|(_, when)| when.timestamp_millis());
    choices.dedup_by_key(|(_, when)| when.timestamp_millis());
    choices
}

/// The times a thread's own menu offers, reminders among them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MenuTime {
    LaterToday,
    InThreeHours,
    /// 8:00.
    TomorrowMorning,
    /// Saturday 9:00, from Monday to Thursday.
    ThisWeekend,
    /// Monday 8:00.
    NextWeek,
    /// A reminder: in three days at 9:00, if nobody replied.
    NoReplyInThreeDays,
    /// A reminder: in a week at 9:00, if nobody replied.
    NoReplyInAWeek,
}

impl MenuTime {
    /// A reminder (it comes back only if nobody replied).
    pub fn no_reply(self) -> bool {
        matches!(
            self,
            MenuTime::NoReplyInThreeDays | MenuTime::NoReplyInAWeek
        )
    }
}

/// The times a thread's own menu offers, from `now`.
pub fn menu_times(now: DateTime<Local>) -> Vec<(MenuTime, DateTime<Local>)> {
    let today = now.date_naive();
    let mut choices = Vec::new();
    let mut push = |kind, when: Option<DateTime<Local>>| {
        if let Some(when) = when {
            choices.push((kind, when));
        }
    };
    if now.hour() < 17 {
        push(MenuTime::LaterToday, at(today, 18));
    } else {
        push(MenuTime::InThreeHours, Some(now + Days::hours(3)));
    }
    push(MenuTime::TomorrowMorning, at(today + Days::days(1), 8));
    if !matches!(now.weekday(), Weekday::Fri | Weekday::Sat | Weekday::Sun) {
        let mut saturday = today;
        while saturday.weekday() != Weekday::Sat {
            saturday += Days::days(1);
        }
        push(MenuTime::ThisWeekend, at(saturday, 9));
    }
    let mut monday = today + Days::days(1);
    while monday.weekday() != Weekday::Mon {
        monday += Days::days(1);
    }
    push(MenuTime::NextWeek, at(monday, 8));
    push(MenuTime::NoReplyInThreeDays, at(today + Days::days(3), 9));
    push(MenuTime::NoReplyInAWeek, at(today + Days::days(7), 9));
    choices
}

/// When a day picked in a calendar comes back: at the time chosen for it. None for a time
/// already gone by at `now`.
pub fn day_time(
    date: NaiveDate,
    (hour, minute): (u32, u32),
    now: DateTime<Local>,
) -> Option<DateTime<Local>> {
    let when = Local
        .from_local_datetime(&date.and_hms_opt(hour, minute, 0)?)
        .single()?;
    (when > now).then_some(when)
}

/// The day a calendar starts on: today if the time is still ahead today, else tomorrow.
pub fn first_open_day(time: (u32, u32), now: DateTime<Local>) -> NaiveDate {
    let today = now.date_naive();
    if day_time(today, time, now).is_some() {
        today
    } else {
        today + Days::days(1)
    }
}

/// A time typed in: "4:30 PM", "4:30pm", "16:30", "430p", "4", "noon". Without AM or PM,
/// 1 to 7 is the afternoon (nobody snoozes to 5 in the morning by typing "5"), unless it is
/// written with a leading zero ("07:00").
pub fn parse_time(text: &str) -> Option<(u32, u32)> {
    let s: String = text
        .trim()
        .to_lowercase()
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '.')
        .collect();
    match s.as_str() {
        "noon" => return Some((12, 0)),
        "midnight" => return Some((0, 0)),
        _ => {}
    }
    let (body, half) = if let Some(b) = s.strip_suffix("am").or_else(|| s.strip_suffix('a')) {
        (b, Some(false))
    } else if let Some(b) = s.strip_suffix("pm").or_else(|| s.strip_suffix('p')) {
        (b, Some(true))
    } else {
        (s.as_str(), None)
    };
    if body.is_empty() || !body.chars().all(|c| c.is_ascii_digit() || c == ':') {
        return None;
    }
    let (hour, minute): (&str, &str) = match body.split_once(':') {
        Some(split) => split,
        None if body.len() <= 2 => (body, "0"),
        None if body.len() <= 4 => body.split_at(body.len() - 2),
        None => return None,
    };
    let (h, m): (u32, u32) = (hour.parse().ok()?, minute.parse().ok()?);
    if m > 59 || hour.is_empty() {
        return None;
    }
    let h = match half {
        Some(pm) if (1..=12).contains(&h) => h % 12 + if pm { 12 } else { 0 },
        Some(_) => return None,
        None if (1..=7).contains(&h) && !hour.starts_with('0') => h + 12,
        None if h <= 23 => h,
        None => return None,
    };
    Some((h, m))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::Fake;

    fn row(id: &str, at: i64) -> Row {
        Row {
            id: Some(id.into()),
            subject: "Hi".into(),
            timestamp_ms: at,
            loaded: true,
            body: crate::rich::from_text(vec!["body".into()]).into(),
            ..Row::default()
        }
    }

    #[test]
    fn a_thread_is_snoozed_once_and_kept_without_its_messages() {
        let mut list = Vec::new();
        put(&mut list, &[Snooze::new(&row("t1", 5), 10, false)]);
        put(&mut list, &[Snooze::new(&row("t2", 5), 20, true)]);
        put(&mut list, &[Snooze::new(&row("t1", 5), 30, false)]);
        assert_eq!(list.len(), 2);
        let t1 = list.iter().find(|s| s.thread_id == "t1").unwrap();
        assert_eq!((t1.until_ms, t1.since_ms), (30, 5));
        assert!(!t1.mail.loaded && t1.mail.body.is_empty());
        assert_eq!(next_due(&list), Some(20));
        assert_eq!(rows(&list, true).len(), 1);
        forget(&mut list, &["t1".into()]);
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn a_reply_ends_a_snooze() {
        let list = vec![Snooze::new(&row("t1", 5), 100, false)];
        assert_eq!(answered(&list, &[row("t1", 9), row("t2", 9)]), ["t1"]);
        assert!(answered(&list, &[row("t1", 5)]).is_empty());
    }

    #[test]
    fn a_due_snooze_comes_back_unread_and_leaves_the_list() {
        let fake = Fake::new("me@example.com");
        fake.add(Fake::thread("t1", &[], 5));
        let client: Arc<mail::Client> = fake.clone();
        let store = Store::temp();
        store
            .update(LIST, |l: &mut Vec<Snooze>| {
                put(l, &[Snooze::new(&row("t1", 5), 1, false)])
            })
            .unwrap();
        let connected: HashMap<String, Arc<mail::Client>> = [("a".to_string(), client)].into();
        let back = carry_out_due("a", &store, &connected, || ());
        assert_eq!(back.len(), 1);
        assert!(list(&store).is_empty());
        let labels = fake.labels_of("t1");
        assert!(labels.contains(&"INBOX".into()) && labels.contains(&"UNREAD".into()));
    }

    #[test]
    fn a_reminder_answered_meanwhile_is_not_needed() {
        let fake = Fake::new("me@example.com");
        fake.add(Fake::thread("t1", &[], 9));
        let client: Arc<mail::Client> = fake.clone();
        assert!(!wake(&*client, "t1", 5, true).unwrap());
        assert!(fake.labels_of("t1").is_empty());
    }

    #[test]
    fn the_quick_times_are_ahead_and_in_order() {
        let now = Local::now();
        let times = quick_times(now);
        assert!(times.len() >= 4);
        assert!(
            times
                .iter()
                .all(|(_, w)| w.timestamp_millis() > now.timestamp_millis())
        );
        assert!(times.windows(2).all(|w| w[0].1 <= w[1].1));
        assert!(menu_times(now).iter().any(|(kind, _)| kind.no_reply()));
    }

    #[test]
    fn a_day_gone_by_cannot_be_picked() {
        let now = Local::now();
        let today = now.date_naive();
        assert!(day_time(today - Days::days(1), (9, 0), now).is_none());
        let tomorrow = day_time(today + Days::days(1), (15, 0), now).unwrap();
        assert_eq!((tomorrow.hour(), tomorrow.minute()), (15, 0));
        // Today at a time already gone.
        assert!(day_time(today, (0, 0), now).is_none());
    }

    #[test]
    fn any_time_can_be_typed() {
        assert_eq!(parse_time("4:30 PM"), Some((16, 30)));
        assert_eq!(parse_time("4:30pm"), Some((16, 30)));
        assert_eq!(parse_time(" 9:15 a.m. "), Some((9, 15)));
        assert_eq!(parse_time("16:45"), Some((16, 45)));
        assert_eq!(parse_time("430p"), Some((16, 30)));
        assert_eq!(parse_time("1015"), Some((10, 15)));
        assert_eq!(parse_time("12am"), Some((0, 0)));
        assert_eq!(parse_time("12 pm"), Some((12, 0)));
        assert_eq!(parse_time("noon"), Some((12, 0)));
        // Without AM or PM, 1 to 7 is the afternoon; a leading zero is the morning.
        assert_eq!(parse_time("5"), Some((17, 0)));
        assert_eq!(parse_time("07:00"), Some((7, 0)));
        assert_eq!(parse_time("8:20"), Some((8, 20)));
        for bad in ["", "25:00", "4:60", "13pm", "soon", "4:3:0", "12345"] {
            assert_eq!(parse_time(bad), None, "{bad}");
        }
    }
}
