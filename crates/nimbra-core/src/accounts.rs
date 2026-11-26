//! The accounts on a device: which kind each is, its sign-in from the Keychain, its
//! connection, and what signing out or removing it deletes. Kept in `settings.accounts`.

use std::sync::Arc;

use anyhow::Result;

use crate::imap_mail::Credential;
use crate::settings::{AccountRef, Settings};
use crate::{contacts, gmail, mail, microsoft, servers, store};

/// The account signs in with Microsoft (its servers are Microsoft's).
pub fn is_microsoft(account: &AccountRef) -> bool {
    account.servers.is_some() && account.oauth.as_deref() == Some(microsoft::PROVIDER)
}

/// How an account with its own servers signs in, read from the keychain (blocking): its
/// Microsoft sign-in when `microsoft` is given, else its password. `None` when there is none.
pub fn stored_credential(
    id: &str,
    microsoft: Option<&microsoft::Config>,
) -> Result<Option<Credential>> {
    Ok(match microsoft {
        Some(config) => microsoft::stored_refresh_token(id)?.map(|token| {
            Credential::Microsoft(Arc::new(microsoft::Tokens::new(
                config.clone(),
                token,
                id.to_string(),
            )))
        }),
        None => servers::stored_password(id)?.map(Credential::Password),
    })
}

/// The connection to an account with its own servers, from its saved password or
/// sign-in: `None` when there is none (yet, or any more), or it has no servers.
pub fn imap_connection(
    account: &AccountRef,
    credential: Option<Credential>,
) -> Option<Arc<mail::Client>> {
    let servers = account.servers.clone()?;
    Some(contacts::wrap(
        crate::imap_mail::Client::new(
            account.id.clone(),
            account.email.clone(),
            servers,
            credential?,
        ),
        &account.email,
    ))
}

/// Checks that both of an account's servers take this password, as adding an account
/// does: IMAP, then SMTP. A refused password is `mail::SignedOut` (not yet any account's)
/// from IMAP and `smtp::AuthFailed` from SMTP. Blocking (network).
pub fn check_password(servers: &servers::Servers, password: &str) -> Result<()> {
    crate::imap_mail::check_login(servers, Credential::Password(password.to_string()))?;
    crate::smtp::check_login(
        &servers.smtp,
        &servers.username,
        &servers::Secret::Password(password.to_string()),
    )
}

/// The connection to a Gmail account from its saved sign-in.
pub fn gmail_connection(
    config: gmail::Config,
    token: String,
    account: &AccountRef,
) -> Arc<mail::Client> {
    contacts::wrap(
        gmail::Client::new(config, token, account.id.clone()),
        &account.email,
    )
}

/// Deletes what the device keeps of an account: its sign-ins and password in the Keychain
/// and its encrypted store. Nothing on the server changes. Blocking (Keychain, disk).
pub fn forget_secrets_and_mail(id: &str) {
    gmail::forget_refresh_token(id);
    servers::forget_password(id);
    microsoft::forget_refresh_token(id);
    store::wipe(id);
}

/// Takes an account out of the settings: its entry, its signatures, and its place as the
/// default account.
pub fn remove(settings: &mut Settings, id: &str) {
    settings.accounts.retain(|a| a.id != id);
    settings.forget_signatures(id);
    if settings.default_account.as_deref() == Some(id) {
        settings.default_account = None;
    }
}

/// Another account with this address than `id`: a second sign-in to an account already
/// here, which is dropped for the one there is.
pub fn duplicate_of<'a>(settings: &'a Settings, email: &str, id: &str) -> Option<&'a AccountRef> {
    settings
        .accounts
        .iter()
        .find(|a| a.email.eq_ignore_ascii_case(email) && a.id != id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account(id: &str, email: &str) -> AccountRef {
        AccountRef {
            id: id.into(),
            email: email.into(),
            servers: None,
            oauth: None,
        }
    }

    #[test]
    fn removing_an_account_takes_its_signatures_and_default_with_it() {
        let mut settings = Settings {
            accounts: vec![
                account("a1", "a@example.com"),
                account("b1", "b@example.com"),
            ],
            default_account: Some("b1".into()),
            ..Settings::default()
        };
        let id = settings.add_signature("b1").unwrap();
        assert!(settings.signature(&id).is_some());
        remove(&mut settings, "b1");
        assert_eq!(settings.accounts.len(), 1);
        assert!(settings.signature(&id).is_none());
        assert_eq!(settings.default_account, None);
    }

    #[test]
    fn a_second_sign_in_to_the_same_address_is_a_duplicate() {
        let settings = Settings {
            accounts: vec![
                account("a1", "Ana@example.com"),
                account("new", "ana@example.com"),
            ],
            ..Settings::default()
        };
        assert_eq!(
            duplicate_of(&settings, "ana@example.com", "new").map(|a| a.id.as_str()),
            Some("a1")
        );
        assert!(duplicate_of(&settings, "ana@example.com", "a1").is_some_and(|a| a.id == "new"));
        assert!(duplicate_of(&settings, "zed@example.com", "a1").is_none());
    }
}
