//! The one error Swift sees. Core errors are made to be shown: they never carry a token,
//! a password or a secret, and this keeps it that way (nothing is added to them).

use nimbra_core::{gmail, mail};

#[derive(Debug, uniffi::Error)]
pub enum NimbraError {
    /// The account's sign-in is gone (revoked, expired): sign in again.
    SignedOut { account: String },
    /// No connection to the server.
    Offline,
    /// The thread, message, draft or label is gone.
    NotFound,
    /// The change feed is too old: list the mailbox afresh.
    HistoryExpired,
    /// Deleting for good needs one more permission from Google.
    NeedsFullAccess,
    /// The Keychain (or the store's key in it) could not be read. Never "signed out".
    Keychain { message: String },
    /// What was asked is not valid (an address, a server, an unknown account).
    Invalid { message: String },
    /// Anything else, in words that can be shown.
    Failed { message: String },
}

impl std::fmt::Display for NimbraError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NimbraError::SignedOut { .. } => f.write_str("Signed out. Please sign in again."),
            NimbraError::Offline => f.write_str("You’re offline."),
            NimbraError::NotFound => f.write_str("It is not there any more."),
            NimbraError::HistoryExpired => f.write_str("The mailbox has to be listed again."),
            NimbraError::NeedsFullAccess => {
                f.write_str("Deleting permanently needs one more permission from Google.")
            }
            NimbraError::Keychain { message }
            | NimbraError::Invalid { message }
            | NimbraError::Failed { message } => f.write_str(message),
        }
    }
}

impl std::error::Error for NimbraError {}

impl NimbraError {
    pub(crate) fn invalid(message: impl Into<String>) -> Self {
        NimbraError::Invalid {
            message: message.into(),
        }
    }
}

impl From<anyhow::Error> for NimbraError {
    fn from(error: anyhow::Error) -> Self {
        if let Some(out) = error.downcast_ref::<mail::SignedOut>() {
            return NimbraError::SignedOut {
                account: out.account.clone(),
            };
        }
        if error.is::<mail::Offline>() {
            return NimbraError::Offline;
        }
        if error.is::<mail::HistoryExpired>() {
            return NimbraError::HistoryExpired;
        }
        if error.is::<gmail::NeedsFullAccess>() {
            return NimbraError::NeedsFullAccess;
        }
        if mail::is_gone(&error) {
            return NimbraError::NotFound;
        }
        let message = format!("{error:#}");
        if error.chain().any(|cause| cause.is::<keyring::Error>()) {
            return NimbraError::Keychain { message };
        }
        NimbraError::Failed { message }
    }
}

pub type Result<T> = std::result::Result<T, NimbraError>;
