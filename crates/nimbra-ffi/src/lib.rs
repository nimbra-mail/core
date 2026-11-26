//! Nimbra's mail engine for Swift, through UniFFI: the same engine the macOS app runs
//! (`nimbra-core`), behind an API made for a SwiftUI client.
//!
//! - `Engine` (in `engine.rs`): accounts and sign-in, mailboxes, threads, actions, snooze,
//!   blocking, drafts, sending, contacts, signatures and preferences. Every method blocks:
//!   call them off the main actor.
//! - `SecretStore`: the app's Keychain, which the engine keeps every secret in.
//! - The free functions below need no account and do not touch the network.

uniffi::setup_scaffolding!();

mod engine;
mod error;
mod secrets;
mod types;

pub use engine::{Engine, OutgoingSend};
pub use error::NimbraError;
pub use secrets::{SecretError, SecretStore};
pub use types::*;

use nimbra_core::{discover, mail, mime};

/// The engine's version.
#[uniffi::export]
pub fn core_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Parses one raw RFC 5322 message (a `.eml`): its people, body as text blocks and HTML,
/// and attachments (whose ids are their position, for this message only). `None` when it
/// is not a message.
#[uniffi::export]
pub fn parse_message(raw: Vec<u8>) -> Option<MailMessage> {
    mime::message(&raw, "local").map(|message| MailMessage::from(&message))
}

/// The servers of a well-known provider for this address, without the network. `None`
/// when it is not one (then `Engine::discover_servers` asks around).
#[uniffi::export]
pub fn known_servers(email: String) -> Option<Discovery> {
    discover::known(&email).map(Discovery::from)
}

/// The action that undoes `action`, if there is one (Undo after Done is Move to Inbox).
#[uniffi::export]
pub fn undo_action(action: ThreadAction) -> Option<ThreadAction> {
    action.change().inverse().map(ThreadAction::from_change)
}

/// Whether this is one email address, as the engine checks it.
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
            Some(Discovery::NeedsOAuth { provider }) => assert_eq!(provider, "Google"),
            other => panic!("{other:?}"),
        }
        assert_eq!(known_servers("someone@example.invalid".into()), None);
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
