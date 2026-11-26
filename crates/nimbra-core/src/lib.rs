//! Nimbra's mail engine, without any UI. The macOS app (GPUI) and the iOS app (through
//! `nimbra-ffi`) both run it.
//!
//! - `mail`: the model every provider gives (threads, messages, labels, changes, errors,
//!   building a message to send) and the `Provider` interface.
//! - `gmail`, `microsoft`, `imap_mail`, `smtp`, `tls`: the providers and their protocols;
//!   `oauth`: a sign-in that comes back to an app's own redirect (iOS).
//! - `servers`, `discover`, `dns`: an account's servers, found from its address.
//! - `mime`, `rich`: raw mail into the model, and HTML or text as styled blocks.
//! - `store`: the encrypted on-disk store.
//! - `sending`, `scheduled`, `snooze`: a message from Send until the server has it, send
//!   later, and snooze and reminders.
//! - `contacts`, `blocking`, `signature`, `signature_images`, `settings`, `mailto`,
//!   `signin_page`: address suggestions, blocked senders, signatures, preferences, email
//!   links and the page a desktop sign-in ends on.
//! - `paths`: where the files go, for a front end other than the Mac app.

pub mod blocking;
pub mod contacts;
pub mod discover;
pub mod dns;
pub mod gmail;
pub mod imap_mail;
pub mod mail;
pub mod mailto;
pub mod microsoft;
pub mod mime;
pub mod oauth;
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
pub mod tls;
