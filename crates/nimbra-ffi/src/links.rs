//! Links in mail, as the macOS app follows them: email links (RFC 6068), unsubscribing
//! from a list, and a message's remote images when the user asks for them.

use nimbra_core::{mail, mailto, rich};

use crate::error::{NimbraError, Result};

/// What an email link fills a new message with.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct MailtoDraft {
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub bcc: Vec<String>,
    pub subject: String,
    pub body: String,
}

/// How to leave a mailing list (`MailMessage.unsubscribe`).
#[derive(Clone, Debug, PartialEq, uniffi::Enum)]
pub enum Unsubscribe {
    /// Open it in the browser, where the list asks for confirmation.
    Web { url: String },
    /// Send exactly this message, from the account the mail came to, without a signature:
    /// a program reads it.
    Mail {
        to: String,
        subject: String,
        body: String,
    },
}

/// A `mailto:` link as a new message, or `None` when it is not one. Memory only.
#[uniffi::export]
pub fn parse_mailto(link: String) -> Option<MailtoDraft> {
    let found = mailto::parse(&link)?;
    Some(MailtoDraft {
        to: found.to,
        cc: found.cc,
        bcc: found.bcc,
        subject: found.subject,
        body: found.body,
    })
}

/// What a list's unsubscribe link asks for, or `None` when it is not valid. A `mailto:`
/// link gives one address, a subject and a plain body: never a Cc or a Bcc. Memory only.
#[uniffi::export]
pub fn unsubscribe_action(link: String) -> Option<Unsubscribe> {
    let link = link.trim();
    if link.to_ascii_lowercase().starts_with("https://") {
        return Some(Unsubscribe::Web {
            url: link.to_string(),
        });
    }
    let found = mail::unsubscribe_mail(link)?;
    Some(Unsubscribe::Mail {
        to: found.to,
        subject: found.subject,
        body: found.body,
    })
}

/// Downloads one of a message's remote images, when the user asked for them: https on a
/// public host only (checked at every redirect, so a message cannot probe the local
/// network), size-capped, with a timeout, its format read from the bytes. Network.
#[uniffi::export]
pub fn fetch_remote_image(url: String) -> Result<Vec<u8>> {
    rich::fetch_image(&url)
        .map(|(_, bytes)| bytes)
        .map_err(|error| NimbraError::invalid(format!("{error:#}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn links_are_read_as_on_the_mac() {
        let draft =
            parse_mailto("mailto:ana@example.com?subject=Hi&cc=ben@example.com".into()).unwrap();
        assert_eq!(draft.to, ["ana@example.com"]);
        assert_eq!(draft.subject, "Hi");
        assert_eq!(
            unsubscribe_action("https://example.com/leave".into()),
            Some(Unsubscribe::Web {
                url: "https://example.com/leave".into()
            })
        );
        match unsubscribe_action("mailto:leave@example.com?subject=out&cc=x@example.com".into()) {
            Some(Unsubscribe::Mail { to, subject, .. }) => {
                assert_eq!(
                    (to.as_str(), subject.as_str()),
                    ("leave@example.com", "out")
                );
            }
            other => panic!("{other:?}"),
        }
        assert!(unsubscribe_action("javascript:alert(1)".into()).is_none());
        assert!(fetch_remote_image("http://127.0.0.1/x.png".into()).is_err());
    }
}
