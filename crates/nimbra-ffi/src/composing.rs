//! `Engine`: what a message being written starts with, and the HTML sent, as the macOS
//! app builds them (`nimbra_core::composing`).

use nimbra_core::composing::{self, Answer};
use nimbra_core::listing;

use crate::engine::Engine;
use crate::error::{NimbraError, Result};
use crate::types::*;

#[uniffi::export]
impl Engine {
    /// What a reply, reply-all or forward of a thread's latest message starts with: its
    /// subject, who it goes to (never the account itself, each once), the earlier message
    /// quoted (a reply only when Quote replies is on), the files a forward carries, and the
    /// account's default signature. `date_text` is that message's date as the app writes
    /// it (it goes into "On …, … wrote:"). From the device when the thread is kept with its
    /// messages, else fetched (network) and kept.
    pub fn start_answer(
        &self,
        account_id: String,
        thread_id: String,
        kind: AnswerKind,
        date_text: String,
    ) -> Result<DraftStart> {
        let open = self.connect(&account_id)?;
        let row = match listing::kept_thread(&open.store, &thread_id) {
            Some(row) => row,
            None => {
                let mut row = match listing::find_kept(&open.store, &thread_id) {
                    Some(row) => row,
                    None => listing::Row::from_summary(open.client.summary(&thread_id, false)?),
                };
                let messages = open.client.thread(&thread_id)?;
                row.fill(messages);
                row
            }
        };
        let email = self
            .account(&account_id)?
            .map(|a| a.email)
            .ok_or_else(|| NimbraError::invalid("There is no such account."))?;
        let sender = row.header.from.label().to_string();
        let answered = composing::answer(
            match kind {
                AnswerKind::Reply => Answer::Reply,
                AnswerKind::ReplyAll => Answer::ReplyAll,
                AnswerKind::Forward => Answer::Forward,
            },
            &composing::Source {
                subject: &row.subject,
                sender: &sender,
                header: &row.header,
                body: &row.body,
                reply_to: row.reply.as_ref().map(|(_, reply)| reply.clone()),
                fallback_to: None,
                fallback_all: &[],
            },
            &email,
            date_text.trim(),
            self.preferences().quote_replies,
        );
        let signature = self
            .signatures(account_id)
            .into_iter()
            .find(|s| s.is_default);
        Ok(DraftStart {
            subject: answered.subject,
            to: answered.to,
            quoted: answered.quoted,
            kept: answered.kept.iter().map(AttachmentInfo::from).collect(),
            reply: answered.reply.map(|reply| ReplyRef {
                thread_id: reply.thread_id,
                message_id: reply.message_id,
            }),
            signature,
        })
    }
}

/// The HTML part of an outgoing message, as the Mac sends it: what was written, the
/// signature (already cleaned: a `SignatureInfo`'s HTML) in its own block, then the quoted
/// earlier message (as text) in the usual quote block.
#[uniffi::export]
pub fn message_html(written: String, signature: Option<String>, quoted: Option<String>) -> String {
    composing::message_html(&written, signature.as_deref(), quoted.as_deref())
}

/// A saved draft's HTML taken apart again: what was written (without the quote) and the
/// signature it was saved with. `None` for what was written when the HTML has no quote
/// block: then all of it was written.
#[uniffi::export]
pub fn split_draft_html(html: String) -> DraftParts {
    let own = composing::own_html(&html);
    let (written, signature) = composing::split_signature(own.as_deref().unwrap_or(&html));
    DraftParts { written, signature }
}

/// Text as the editor's HTML: escaped, a `<div>` per line.
#[uniffi::export]
pub fn text_to_html(text: String) -> String {
    nimbra_core::rich::text_to_html(&text)
}
