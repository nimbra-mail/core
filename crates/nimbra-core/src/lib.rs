//! Nimbra's mail engine, without any UI. The macOS app (GPUI) and the iOS app (through
//! `nimbra-ffi`) both run it.
//!
//! - `mail`: the model every provider gives (threads, messages, labels, changes, errors,
//!   building a message to send) and the `Provider` interface.
//! - `gmail`, `microsoft`, `imap_mail`, `smtp`, `tls`: the providers and their protocols;
//!   `oauth`: a sign-in that comes back to an app's own redirect (iOS).
//! - `accounts`: each account's kind, its sign-in from the Keychain, its connection, and
//!   what removing it deletes.
//! - `servers`, `discover`, `dns`: an account's servers, found from its address (`dns` can
//!   be answered by the app: iOS).
//! - `mime`, `rich`: raw mail into the model, and HTML or text as styled blocks.
//! - `store`: the encrypted on-disk store. `listing`: mailboxes as kept in it (rows, sync
//!   from the change feed, All inboxes, the Split Inbox, labels).
//! - `composing`: the HTML sent, a draft's signature, what a reply or forward starts with.
//! - `notifying`, `watching`: which new mail notifies, the badge, mark-read timing; live
//!   updates (IMAP IDLE, the check interval).
//! - `sending`, `outbox`, `scheduled`, `snooze`, `leaving`: a message from Send until the
//!   server has it, the offline queue and the decisions about a send, send later, snooze and
//!   reminders, and what quitting has to finish.
//! - `contacts`, `blocking`, `signature`, `signature_images`, `settings`, `mailto`,
//!   `signin_page`: address suggestions, blocked senders, signatures, preferences, email
//!   links and the page a desktop sign-in ends on.
//! - `paths`: where the files go, for a front end other than the Mac app.
//! - `testing` (with `test-support`): a mail server in memory, for tests.

pub mod accounts;
pub mod blocking;
pub mod composing;
pub mod contacts;
pub mod discover;
pub mod dns;
pub mod gmail;
pub mod imap_mail;
pub mod leaving;
pub mod listing;
pub mod mail;
pub mod mailto;
pub mod microsoft;
pub mod mime;
pub mod notifying;
pub mod oauth;
pub mod outbox;
pub mod paths;
pub mod rich;
pub mod scheduled;
pub mod sending;
pub mod servers;
pub mod settings;
pub mod signature;
pub mod signature_images;
pub mod signin_page;
pub mod smtp;
pub mod snooze;
pub mod store;
#[cfg(any(test, feature = "test-support"))]
pub mod testing;
pub mod tls;
pub mod watching;
