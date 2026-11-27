//! Nimbra's mail engine for Swift, through UniFFI: the same engine the macOS app runs
//! (`nimbra-core`), behind an API made for a SwiftUI client.
//!
//! - `Engine` (in `engine.rs`): accounts and sign-in, mailboxes, threads, actions, snooze,
//!   blocking, drafts, sending, contacts, signatures and preferences. Every method blocks:
//!   call them off the main actor.
//! - `SecretStore`: the app's Keychain, which the engine keeps every secret in.
//! - The free functions below need no account and do not touch the network.

uniffi::setup_scaffolding!();

mod composing;
mod dns;
mod engine;
mod error;
mod links;
mod mailboxes;
mod secrets;
mod sending;
mod types;
mod watching;

pub use composing::{message_html, split_draft_html, text_to_html};
pub use dns::{DnsError, DnsResolver, MxRecord, use_dns_resolver};
pub use engine::Engine;
pub use error::NimbraError;
pub use links::{MailtoDraft, Unsubscribe, fetch_remote_image, parse_mailto, unsubscribe_action};
pub use secrets::{SecretError, SecretStore};
pub use sending::{OutgoingSend, send_later_times};
pub use types::*;
pub use watching::ChangeWatch;

use nimbra_core::{discover, mail, mime};

/// The engine's version. Memory only.
#[uniffi::export]
pub fn core_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Parses one raw RFC 5322 message (a `.eml`): its people, body as text blocks and HTML,
/// and attachments (whose ids are their position, for this message only). `None` when it
/// is not a message. Memory only.
#[uniffi::export]
pub fn parse_message(raw: Vec<u8>) -> Option<MailMessage> {
    mime::message(&raw, "local").map(|message| MailMessage::from(&message))
}

/// The servers of a well-known provider for this address, without the network. `None`
/// when it is not one (then `Engine::discover_servers` asks around). Memory only.
#[uniffi::export]
pub fn known_servers(email: String) -> Option<Discovery> {
    discover::known(&email).map(Discovery::from)
}

/// The action that undoes `action`, if there is one (Undo after Done is Move to Inbox).
/// Memory only.
#[uniffi::export]
pub fn undo_action(action: ThreadAction) -> Option<ThreadAction> {
    action.change().inverse().map(ThreadAction::from_change)
}

/// The times the Snooze menu offers from now: the quick times, then the two reminders.
/// Memory only.
#[uniffi::export]
pub fn snooze_times() -> Vec<SnoozeTime> {
    use nimbra_core::snooze::{self, MenuTime, Quick};
    let now = chrono::Local::now();
    let mut times: Vec<SnoozeTime> = snooze::quick_times(now)
        .into_iter()
        .map(|(kind, when)| SnoozeTime {
            kind: match kind {
                Quick::LaterToday => SnoozeKind::LaterToday,
                Quick::InThreeHours => SnoozeKind::InThreeHours,
                Quick::Tomorrow => SnoozeKind::Tomorrow,
                Quick::TomorrowEvening => SnoozeKind::TomorrowEvening,
                Quick::ThisWeekend => SnoozeKind::ThisWeekend,
                Quick::NextWeek => SnoozeKind::NextWeek,
            },
            until_ms: when.timestamp_millis(),
            only_if_no_reply: false,
        })
        .collect();
    times.extend(
        snooze::menu_times(now)
            .into_iter()
            .filter(|(kind, _)| kind.no_reply())
            .map(|(kind, when)| SnoozeTime {
                kind: if kind == MenuTime::NoReplyInThreeDays {
                    SnoozeKind::NoReplyInThreeDays
                } else {
                    SnoozeKind::NoReplyInAWeek
                },
                until_ms: when.timestamp_millis(),
                only_if_no_reply: true,
            }),
    );
    times
}

/// A time typed in ("4:30 PM", "16:30", "430p", "noon"), as the Mac reads it: without AM
/// or PM, 1 to 7 is the afternoon. `None` when it is not a time. Memory only.
#[uniffi::export]
pub fn parse_time(text: String) -> Option<TimeOfDay> {
    nimbra_core::snooze::parse_time(&text).map(|(hour, minute)| TimeOfDay { hour, minute })
}

/// When a day picked in a calendar comes back, at a time of day, in the device's time
/// zone. `None` for a time already gone by (or not on the clock that day). Memory only.
#[uniffi::export]
pub fn day_time(year: i32, month: u32, day: u32, time: TimeOfDay) -> Option<i64> {
    let date = chrono::NaiveDate::from_ymd_opt(year, month, day)?;
    nimbra_core::snooze::day_time(date, (time.hour, time.minute), chrono::Local::now())
        .map(|when| when.timestamp_millis())
}

/// How long to wait before each `Engine::learn_contacts` step, so learning addresses never
/// competes with the mail being read. Memory only.
#[uniffi::export]
pub fn contact_scan_pause_seconds() -> u32 {
    nimbra_core::contacts::SCAN_PAUSE.as_secs() as u32
}

/// Whether this is one email address, as the engine checks it. Memory only.
#[uniffi::export]
pub fn is_email_address(text: String) -> bool {
    mail::is_address(text.trim())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &[u8] = b"From: Ana Lima <ana@example.com>\r\n\
To: Ben <ben@example.org>\r\n\
Subject: Lunch\r\n\
Date: Tue, 3 Nov 2026 10:00:00 +0000\r\n\
Message-ID: <lunch-1@example.com>\r\n\
MIME-Version: 1.0\r\n\
Content-Type: text/plain; charset=utf-8\r\n\
\r\n\
Friday at noon?\r\n";

    #[test]
    fn a_message_is_parsed_into_people_and_text() {
        let message = parse_message(SAMPLE.to_vec()).unwrap();
        assert_eq!(message.from.address, "ana@example.com");
        assert_eq!(message.to[0].address, "ben@example.org");
        assert_eq!(message.message_id, "<lunch-1@example.com>");
        assert!(message.text.contains("Friday at noon?"), "{}", message.text);
    }

    #[test]
    fn known_providers_are_found_offline() {
        match known_servers("someone@gmail.com".into()) {
            Some(Discovery::Google { servers }) => {
                assert_eq!(servers.username, "someone@gmail.com");
                assert_eq!(servers.imap.host, "imap.gmail.com");
                assert_eq!(servers.smtp.host, "smtp.gmail.com");
            }
            other => panic!("{other:?}"),
        }
        match known_servers("someone@outlook.com".into()) {
            Some(Discovery::NeedsOAuth { provider }) => assert_eq!(provider, "Microsoft"),
            other => panic!("{other:?}"),
        }
        assert_eq!(known_servers("someone@example.invalid".into()), None);
    }

    #[test]
    fn snooze_times_are_ahead_and_typed_times_read_as_on_the_mac() {
        let now = chrono::Utc::now().timestamp_millis();
        let times = snooze_times();
        assert!(times.len() >= 6);
        assert!(times.iter().all(|t| t.until_ms > now));
        assert_eq!(times.iter().filter(|t| t.only_if_no_reply).count(), 2);
        assert_eq!(
            parse_time("430p".into()),
            Some(TimeOfDay {
                hour: 16,
                minute: 30
            })
        );
        assert_eq!(parse_time("soon".into()), None);
        assert_eq!(day_time(2000, 1, 1, TimeOfDay { hour: 9, minute: 0 }), None);
    }

    #[test]
    fn a_signature_is_sent_apart_and_found_again() {
        let html = message_html(
            "<div>Hi</div>".into(),
            Some("<b>Luan</b>".into()),
            Some("On Tue, Ana wrote:\n> old".into()),
        );
        let parts = split_draft_html(html);
        assert_eq!(parts.signature.as_deref(), Some("<b>Luan</b>"));
        assert!(parts.written.contains("Hi") && !parts.written.contains("old"));
        assert_eq!(text_to_html("a<b".into()), "<div>a&lt;b</div>");
    }

    #[test]
    fn undo_reverses_done_and_star() {
        assert_eq!(
            undo_action(ThreadAction::Done),
            Some(ThreadAction::MoveToInbox)
        );
        assert_eq!(undo_action(ThreadAction::Star), Some(ThreadAction::Unstar));
        assert_eq!(undo_action(ThreadAction::MarkRead), None);
    }
}
