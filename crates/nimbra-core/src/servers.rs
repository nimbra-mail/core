//! Where an account that is not Gmail gets its mail: the IMAP and SMTP servers it uses, and
//! its password, which is kept in the system keychain (never in the settings file). A
//! Microsoft account has no password here: its sign-in is in `microsoft.rs`.
//!
//! Security notes:
//! - Both servers are only ever reached over TLS: from the first byte (`Tls`), or after
//!   STARTTLS (`StartTls`), which is required: a server that does not offer it is refused,
//!   never spoken to in plain text.
//! - Host names are checked before use, so a typed or discovered one cannot carry anything
//!   else into a connection or a command.

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};

use crate::mail::is_account_id;

const KEYCHAIN_SERVICE: &str = "nimbra";
const KEYCHAIN_USER: &str = "mail-password";

/// How a connection is made secure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Security {
    /// TLS from the start (IMAP 993, SMTP 465).
    Tls,
    /// A plain connection made secure with STARTTLS before anything else is said (IMAP
    /// 143, SMTP 587).
    StartTls,
}

/// One server: host, port and how it is secured.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Server {
    pub host: String,
    pub port: u16,
    pub security: Security,
}

impl Server {
    pub fn new(host: &str, port: u16, security: Security) -> Self {
        Server {
            host: host.trim().trim_end_matches('.').to_ascii_lowercase(),
            port,
            security,
        }
    }

    /// Refuses a host that is not a plain DNS name (or IP address) and port 0.
    pub fn check(&self) -> Result<()> {
        if self.port == 0 {
            bail!("“{}” needs a port.", self.host);
        }
        if !is_host(&self.host) {
            bail!(
                "“{}” is not a server name.",
                crate::mail::sanitize(&self.host)
            );
        }
        Ok(())
    }
}

/// An account's servers and the name it signs in with (usually its address).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Servers {
    pub username: String,
    pub imap: Server,
    pub smtp: Server,
}

impl Servers {
    pub fn check(&self) -> Result<()> {
        if self.username.trim().is_empty() || self.username.chars().any(char::is_control) {
            bail!("The user name is empty or not valid.");
        }
        self.imap.check()?;
        self.smtp.check()
    }
}

/// What one sign-in to a server sends: a password, or an OAuth access token (XOAUTH2).
pub enum Secret {
    Password(String),
    Bearer(String),
}

/// The XOAUTH2 sign-in string (before base64): `user=…^Aauth=Bearer …^A^A`. Neither part
/// may hold a control character or a space, so neither can end the string early.
pub fn xoauth2(user: &str, token: &str) -> Result<String> {
    let plain = |s: &str| !s.is_empty() && !s.chars().any(|c| c.is_control() || c == ' ');
    if !plain(user) || !plain(token) {
        bail!("The user name or sign-in is not valid.");
    }
    Ok(format!("user={user}\x01auth=Bearer {token}\x01\x01"))
}

/// Letters, digits, hyphens and dots, as a DNS name is; or an IP address.
pub fn is_host(host: &str) -> bool {
    if host.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
}

fn keychain(account: &str) -> Result<keyring::Entry> {
    if account.is_empty() || !is_account_id(account) {
        bail!("unexpected account id");
    }
    keyring::Entry::new(KEYCHAIN_SERVICE, &format!("{KEYCHAIN_USER}-{account}"))
        .context("opening the system keychain")
}

/// The account's saved password: `None` when there is none. A keychain that cannot be read
/// (denied, locked) is an error, which is not the same as having none.
pub fn stored_password(account: &str) -> Result<Option<String>> {
    match keychain(account)?.get_password() {
        Ok(password) => Ok(Some(password)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(error) => Err(error).context("reading the password from the system keychain"),
    }
}

pub fn store_password(account: &str, password: &str) -> Result<()> {
    keychain(account)?
        .set_password(password)
        .context("saving the password to the system keychain")
}

pub fn forget_password(account: &str) {
    if let Ok(entry) = keychain(account) {
        let _ = entry.delete_credential();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_plain_host_names_are_servers() {
        for host in [
            "imap.zoho.eu",
            "mail.example.co.uk",
            "127.0.0.1",
            "::1",
            "a-b.c",
        ] {
            assert!(is_host(host), "{host}");
        }
        for host in [
            "",
            "imap.zoho.eu\r\nA1 LOGOUT",
            "mail example.com",
            "-bad.com",
            "bad-.com",
            "a..b",
            "ex ample",
            "host:993",
            "user@host",
        ] {
            assert!(!is_host(host), "{host:?}");
        }
    }

    #[test]
    fn the_xoauth2_string_is_exact_and_refuses_odd_parts() {
        assert_eq!(
            xoauth2("ana@outlook.com", "EwB.abc-_+/=").unwrap(),
            "user=ana@outlook.com\x01auth=Bearer EwB.abc-_+/=\x01\x01"
        );
        for (user, token) in [
            ("", "t"),
            ("a@b.c", ""),
            ("a@b.c\x01auth=Bearer x", "t"),
            ("a@b.c", "t\x01\x01"),
            ("a@b.c", "t\r\nA1 LOGOUT"),
            ("a b@c.d", "t"),
        ] {
            assert!(xoauth2(user, token).is_err(), "{user:?} {token:?}");
        }
    }

    #[test]
    fn a_server_is_kept_as_its_plain_lowercase_name() {
        let server = Server::new(" IMAP.Zoho.com. ", 993, Security::Tls);
        assert_eq!(server.host, "imap.zoho.com");
        assert!(server.check().is_ok());
        assert!(
            Server::new("imap.zoho.com", 0, Security::Tls)
                .check()
                .is_err()
        );
    }
}
