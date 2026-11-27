//! The one error Swift sees. Core errors are made to be shown: they never carry a token,
//! a password or a secret, and this keeps it that way (nothing is added to them).

use nimbra_core::{gmail, mail, smtp};

#[derive(Debug, uniffi::Error)]
pub enum NimbraError {
    /// A sign-in or password was not taken. `account_id` is the account on this device
    /// whose sign-in is gone (revoked, expired, the password changed): sign in to it again
    /// (`begin_google_sign_in` or `begin_microsoft_sign_in` with its id, or
    /// `update_imap_password`). `None` when it is not yet any account's: the address being
    /// added (`add_imap_account`, a new account's `finish_*_sign_in`) did not take it, and
    /// nothing was kept. Never an email address.
    SignedOut { account_id: Option<String> },
    /// As `SignedOut`, and the password was the Google account's own: with 2-Step
    /// Verification on, Gmail takes only an app password (or Continue with Google).
    NeedsAppPassword { account_id: Option<String> },
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
            NimbraError::NeedsAppPassword { .. } => {
                f.write_str("Google needs an app password here, not the account’s own password.")
            }
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

    /// A refused sign-in for an account that is already here (signing in to it again):
    /// it names that account.
    pub(crate) fn for_account(self, account_id: &str) -> Self {
        match self {
            NimbraError::SignedOut { account_id: None } => NimbraError::SignedOut {
                account_id: Some(account_id.to_string()),
            },
            NimbraError::NeedsAppPassword { account_id: None } => NimbraError::NeedsAppPassword {
                account_id: Some(account_id.to_string()),
            },
            other => other,
        }
    }
}

impl From<anyhow::Error> for NimbraError {
    fn from(error: anyhow::Error) -> Self {
        // Empty while a sign-in is not yet any account's (`mail::SignedOut`). Only checking a
        // password gives `smtp::AuthFailed` bare (`smtp::check_login`): a connection's
        // sending turns it into `SignedOut` for its account.
        let refused = match error.downcast_ref::<mail::SignedOut>() {
            Some(out) => Some(Some(out.account.clone()).filter(|id| !id.is_empty())),
            None => error.is::<smtp::AuthFailed>().then_some(None),
        };
        if let Some(account_id) = refused {
            return if error.is::<mail::NeedsAppPassword>() {
                NimbraError::NeedsAppPassword { account_id }
            } else {
                NimbraError::SignedOut { account_id }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_out_names_an_account_id_or_none() {
        let theirs = anyhow::Error::from(mail::SignedOut {
            account: "a1b2".into(),
        });
        assert!(matches!(
            NimbraError::from(theirs),
            NimbraError::SignedOut { account_id: Some(id) } if id == "a1b2"
        ));
        // A password checked while adding an account: no account yet.
        let adding = anyhow::Error::from(mail::SignedOut {
            account: String::new(),
        });
        assert!(matches!(
            NimbraError::from(adding),
            NimbraError::SignedOut { account_id: None }
        ));
        let smtp = anyhow::Error::from(smtp::AuthFailed);
        let refused = NimbraError::from(smtp);
        assert!(matches!(
            refused,
            NimbraError::SignedOut { account_id: None }
        ));
        assert!(matches!(
            refused.for_account("c3"),
            NimbraError::SignedOut { account_id: Some(id) } if id == "c3"
        ));
        assert!(matches!(
            NimbraError::Offline.for_account("c3"),
            NimbraError::Offline
        ));
    }

    #[test]
    fn a_google_password_where_an_app_password_is_needed_says_so_from_either_server() {
        let imap = anyhow::Error::from(mail::SignedOut {
            account: String::new(),
        })
        .context(mail::NeedsAppPassword);
        let smtp = anyhow::Error::from(smtp::AuthFailed).context(mail::NeedsAppPassword);
        for error in [imap, smtp] {
            let refused = NimbraError::from(error);
            assert!(matches!(
                refused,
                NimbraError::NeedsAppPassword { account_id: None }
            ));
            assert!(matches!(
                refused.for_account("c3"),
                NimbraError::NeedsAppPassword { account_id: Some(id) } if id == "c3"
            ));
        }
        let theirs = anyhow::Error::from(mail::SignedOut {
            account: "a1b2".into(),
        })
        .context(mail::NeedsAppPassword);
        assert!(matches!(
            NimbraError::from(theirs),
            NimbraError::NeedsAppPassword { account_id: Some(id) } if id == "a1b2"
        ));
    }
}
