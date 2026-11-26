//! What tells the user about mail, as the apps decide it: which new mail notifies
//! (blocked senders' never do: it is put away first), how much of it is named, the badge's
//! number, and when an opened thread counts as read. The apps show the notifications.

use std::collections::HashMap;
use std::time::Duration;

use crate::mail::{self, Summary};
use crate::settings::MarkRead;
use crate::store::Store;

/// New mail named in notifications of its own; the rest are summed up in one.
pub const NAMED: usize = 3;

/// How long a thread stays open before it counts as read, with `MarkRead::Delay`.
pub const MARK_READ_DELAY: Duration = Duration::from_secs(2);

/// What to tell about new mail (`new_mail`).
pub struct NewMail {
    /// The threads that arrived, without blocked senders' (which were put away).
    pub fresh: Vec<String>,
    /// The first few of them, with sender and subject, each its own notification.
    pub named: Vec<Summary>,
    /// How many more arrived ("N more new messages").
    pub more: usize,
}

/// New unread threads in an inbox (`Changes::new_unread_inbox`): blocked senders' mail is
/// moved away first and never notifies; the first `NAMED` are named. Blocking (network).
pub fn new_mail(client: &mail::Client, store: Option<&Store>, fresh: Vec<String>) -> NewMail {
    let fresh = match store {
        Some(store) => crate::blocking::screen(client, store, fresh),
        None => fresh,
    };
    let named: Vec<Summary> = fresh
        .iter()
        .take(NAMED)
        .filter_map(|id| client.summary(id, false).ok())
        .collect();
    let more = fresh.len().saturating_sub(named.len());
    NewMail { fresh, named, more }
}

/// When an opened thread counts as read: at once, after `MARK_READ_DELAY`, or only when
/// the user says so (`None`).
pub fn mark_read_after(choice: MarkRead) -> Option<Duration> {
    match choice {
        MarkRead::Open => Some(Duration::ZERO),
        MarkRead::Delay => Some(MARK_READ_DELAY),
        MarkRead::Never => None,
    }
}

/// The shown account's inbox count (None while it is not connected) and each other
/// connected account's. The shown account is never counted twice, whatever its id ("" for
/// the first one).
pub fn inbox_badge(
    shown: &str,
    shown_unread: Option<u32>,
    account_unread: &HashMap<String, u32>,
    connected: impl Fn(&str) -> bool,
) -> u32 {
    account_unread
        .iter()
        .filter(|(id, _)| id.as_str() != shown && connected(id))
        .fold(shown_unread.unwrap_or(0), |sum, (_, unread)| {
            sum.saturating_add(*unread)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn unread(pairs: &[(&str, u32)]) -> HashMap<String, u32> {
        pairs.iter().map(|(id, n)| (id.to_string(), *n)).collect()
    }

    #[test]
    fn the_badge_sums_every_connected_inbox() {
        let others = unread(&[("b", 3), ("c", 4)]);
        assert_eq!(inbox_badge("", Some(2), &others, |_| true), 9);
    }

    #[test]
    fn the_first_account_is_counted_once_and_as_another_account() {
        // The first account's id is "": shown, its own entry is not added again.
        let all = unread(&[("", 5), ("b", 3)]);
        assert_eq!(inbox_badge("", Some(5), &all, |_| true), 8);
        // Another account shown: the first one counts like any other.
        assert_eq!(inbox_badge("b", Some(3), &all, |_| true), 8);
    }

    #[test]
    fn signed_out_accounts_do_not_count() {
        let others = unread(&[("b", 3), ("c", 4)]);
        assert_eq!(inbox_badge("a", None, &others, |id| id == "c"), 4);
        assert_eq!(inbox_badge("a", None, &HashMap::new(), |_| true), 0);
    }

    #[test]
    fn the_badge_does_not_overflow() {
        let others = unread(&[("b", u32::MAX)]);
        assert_eq!(inbox_badge("a", Some(1), &others, |_| true), u32::MAX);
    }

    #[test]
    fn blocked_senders_never_notify_and_only_a_few_are_named() {
        let fake = crate::testing::Fake::new("me@example.com");
        let client: Arc<mail::Client> = fake.clone();
        let store = Store::temp();
        for i in 0..5 {
            fake.add(crate::testing::Fake::thread(
                &format!("t{i}"),
                &["INBOX", "UNREAD"],
                i,
            ));
        }
        crate::blocking::set(&store, "t4@example.com", true).unwrap();
        let ids: Vec<String> = (0..5).map(|i| format!("t{i}")).collect();
        let news = new_mail(&*client, Some(&store), ids);
        assert_eq!(
            news.fresh.len(),
            4,
            "the blocked sender's thread was put away"
        );
        assert_eq!(news.named.len(), NAMED);
        assert_eq!(news.more, 1);
        assert_eq!(mark_read_after(MarkRead::Delay), Some(MARK_READ_DELAY));
        assert_eq!(mark_read_after(MarkRead::Never), None);
    }
}
