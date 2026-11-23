//! The mail model the app works with, whichever provider an account is with: threads,
//! messages, people, labels and the changes made to them, the errors a connection can end
//! in, and building a message to send (RFC 5322 with MIME).
//!
//! A provider's module (`gmail.rs`) turns its own answers into these.

use anyhow::{Result, anyhow, bail};
use base64::Engine as _;
use serde::{Deserialize, Serialize};

/// Gmail refuses messages over 25 MB of attachments.
pub const ATTACHMENT_LIMIT: u64 = 25 * 1024 * 1024;

/// The change feed cannot be used from the given point (too old, or too much changed).
#[derive(Debug)]
pub struct HistoryExpired;

impl std::fmt::Display for HistoryExpired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("mailbox history is too old to sync from")
    }
}

impl std::error::Error for HistoryExpired {}

/// What changed since a point in the change feed.
#[derive(Default, Debug)]
pub struct Changes {
    /// The point to sync from next time.
    pub latest: String,
    /// Threads with any change: new or deleted messages, or labels added or removed.
    pub threads: Vec<String>,
    /// Threads that received a new unread message in the inbox (for notifications).
    pub new_unread_inbox: Vec<String>,
}

impl View {
    /// Whether a thread with these labels belongs in this mailbox. `None` for mailboxes
    /// that are a search rather than a label (Done, Snoozed, search results), which are
    /// always fetched afresh.
    pub fn holds(&self, labels: &[String], label_id: Option<&str>) -> Option<bool> {
        let has = |l: &str| labels.iter().any(|x| x == l);
        Some(match self {
            // Mixes accounts: always listed afresh.
            View::AllInboxes => return None,
            View::Inbox => has("INBOX"),
            View::Primary => has("INBOX") && has("CATEGORY_PERSONAL"),
            View::Updates => has("INBOX") && has("CATEGORY_UPDATES"),
            View::Promotions => has("INBOX") && has("CATEGORY_PROMOTIONS"),
            View::Social => has("INBOX") && has("CATEGORY_SOCIAL"),
            View::Starred => has("STARRED"),
            View::Drafts => has("DRAFT"),
            View::Sent => has("SENT"),
            View::Label(_) => has(label_id?),
            View::Important => has("IMPORTANT"),
            View::Spam => has("SPAM"),
            View::Trash => has("TRASH"),
            View::Snoozed | View::Done | View::Search | View::AllMail => return None,
        })
    }

    /// Whether the change feed can keep this mailbox up to date. Done and All Mail are
    /// searches, but ones that can be answered from a thread's labels.
    pub fn syncs(&self, label_id: Option<&str>) -> bool {
        matches!(self, View::Done | View::AllMail) || self.holds(&[], label_id).is_some()
    }

    /// Whether a changed thread is in this mailbox.
    pub fn takes(&self, thread: &Summary, label_id: Option<&str>) -> bool {
        // Gmail searches message by message: one that qualifies brings its thread.
        let none_of = |out: &[&str]| {
            thread
                .message_labels
                .iter()
                .any(|labels| !labels.iter().any(|label| out.contains(&label.as_str())))
        };
        match self {
            View::Done => none_of(&["INBOX", "SENT", "DRAFT", "CHAT", "SPAM", "TRASH"]),
            View::AllMail => none_of(&["SPAM", "TRASH"]),
            view => view.holds(&thread.labels, label_id) == Some(true),
        }
    }
}

/// Returned when Google no longer accepts the stored sign-in (revoked, or the weekly
/// expiry of an app in Testing mode). The app reacts by asking the user to sign in again.
#[derive(Debug)]
pub struct SignedOut {
    /// Whose sign-in: several accounts are connected at once, and only the one named may
    /// be signed out for it. Empty while a sign-in is not yet any account's.
    pub account: String,
}

impl std::fmt::Display for SignedOut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Your sign-in has expired")
    }
}

impl std::error::Error for SignedOut {}

/// Gmail (or Google's sign-in) could not be reached at all: no network, most likely.
#[derive(Debug)]
pub struct Offline;

impl std::fmt::Display for Offline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("You’re offline. Nimbra will catch up when the connection is back.")
    }
}

impl std::error::Error for Offline {}

/// The connection failed once a request may already have reached Gmail, so it may have
/// been carried out: a send like this is never made again by itself.
#[derive(Debug)]
pub struct MayHaveArrived;

impl std::fmt::Display for MayHaveArrived {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Gmail’s answer did not arrive. Check your connection.")
    }
}

/// An error Gmail answered with.
#[derive(Debug)]
pub(crate) struct Answered {
    pub(crate) code: u16,
    pub(crate) text: String,
}

impl std::fmt::Display for Answered {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Gmail error {}: {}", self.code, self.text)
    }
}

impl std::error::Error for Answered {}

/// Whether what was asked for is not in Gmail (sent or deleted, say).
pub fn is_gone(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<Answered>()
        .is_some_and(|e| e.code == 404)
}

/// For the step that sends: Gmail failing (5xx, or giving up on waiting) does not say that
/// the message was not sent.
pub(crate) fn while_sending(error: anyhow::Error) -> anyhow::Error {
    match error.downcast_ref::<Answered>() {
        Some(answer) if answer.code >= 500 || answer.code == 408 => error.context(MayHaveArrived),
        _ => error,
    }
}

/// For the steps before the one that sends: whatever became of them, nothing was sent.
pub(crate) fn before_sending(error: anyhow::Error) -> anyhow::Error {
    if error.is::<MayHaveArrived>() {
        return Offline.into();
    }
    error
}

/// Account ids: empty for the first account (stored as it always was), or a short random
/// hex id for each account added after it.
pub fn is_account_id(id: &str) -> bool {
    id.len() <= 16 && id.chars().all(|c| c.is_ascii_hexdigit())
}

/// A new id for an account being added.
pub fn new_account_id() -> Result<String> {
    random_hex(6)
}

/// A saved draft, opened for editing.
pub struct Draft {
    pub id: String,
    pub to: String,
    pub cc: String,
    pub bcc: String,
    /// Files already attached to the draft.
    pub attachments: Vec<Attachment>,
    pub subject: String,
    /// The part the user wrote (including any signature).
    pub body: String,
    /// The earlier message it quotes or forwards, kept collapsed in the composer.
    pub quoted: Option<String>,
    /// The draft's HTML, when it was written with formatting.
    pub html: Option<String>,
    pub reply: Option<ReplyTo>,
}

/// Splits a draft's text into what the user wrote and the quoted earlier message.
pub(crate) fn split_quote(text: &str) -> (String, Option<String>) {
    let lines: Vec<&str> = text.lines().collect();
    let start = lines.iter().position(|line| {
        let line = line.trim();
        line.starts_with('>')
            || (line.starts_with("On ") && line.ends_with("wrote:"))
            || line.contains("Forwarded message")
            || line.starts_with("-----Original Message")
    });
    let join = |part: &[&str]| part.join("\n").trim_end().to_string();
    match start {
        Some(start) => (
            join(&lines[..start]),
            Some(join(&lines[start..])).filter(|q| !q.is_empty()),
        ),
        None => (join(&lines), None),
    }
}

/// A message the user wrote.
#[derive(Clone, Default, serde::Serialize, Deserialize)]
pub struct Outgoing {
    pub to: String,
    pub cc: String,
    pub bcc: String,
    pub subject: String,
    pub body: String,
    /// The same message as HTML, when it was written with formatting.
    pub html: Option<String>,
    /// Files picked in the composer.
    pub files: Vec<OutgoingFile>,
    /// Attachments already on the draft being edited; downloaded again when it is saved.
    pub kept: Vec<Attachment>,
    pub reply: Option<ReplyTo>,
}

/// A file to attach, read into memory.
#[derive(Clone, serde::Serialize, Deserialize)]
pub struct OutgoingFile {
    pub name: String,
    pub mime: String,
    pub bytes: Vec<u8>,
}

/// Every address in a To, Cc or Bcc field, each validated.
pub fn addresses(list: &str) -> Result<Vec<String>> {
    let addresses: Vec<String> = list
        .split([',', ';'])
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(address_of)
        .collect();
    for address in &addresses {
        if !is_address(address) {
            bail!("“{}” is not a valid email address.", sanitize(address));
        }
    }
    Ok(addresses)
}

/// A content type for a file name, from its extension.
pub fn mime_for(name: &str) -> &'static str {
    let ext = name.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    match ext.as_str() {
        "pdf" => "application/pdf",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "heic" => "image/heic",
        "svg" => "image/svg+xml",
        "txt" | "md" => "text/plain",
        "csv" => "text/csv",
        "html" | "htm" => "text/html",
        "zip" => "application/zip",
        "json" => "application/json",
        "doc" => "application/msword",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xls" => "application/vnd.ms-excel",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "ppt" => "application/vnd.ms-powerpoint",
        "pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "key" => "application/x-iwork-keynote-sffkey",
        "pages" => "application/x-iwork-pages-sffpages",
        "numbers" => "application/x-iwork-numbers-sffnumbers",
        "mp4" => "video/mp4",
        "mov" => "video/quicktime",
        "mp3" => "audio/mpeg",
        "ics" => "text/calendar",
        _ => "application/octet-stream",
    }
}

pub(crate) fn random_hex(bytes: usize) -> Result<String> {
    let mut buffer = vec![0u8; bytes];
    getrandom::getrandom(&mut buffer).map_err(|e| anyhow!("no secure random source: {e}"))?;
    Ok(buffer.iter().map(|b| format!("{b:02x}")).collect())
}

/// Appends `data` base64-encoded in 76-character lines.
pub(crate) fn push_base64(message: &mut String, data: &[u8]) {
    use base64::engine::general_purpose::STANDARD;
    let encoded = STANDARD.encode(data);
    for line in encoded.as_bytes().chunks(76) {
        message.push_str(std::str::from_utf8(line).unwrap_or_default());
        message.push_str("\r\n");
    }
}

/// RFC 2231 file name parameter value: percent-encoded UTF-8.
pub(crate) fn encode_filename(name: &str) -> String {
    name.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

#[derive(Clone, serde::Serialize, Deserialize)]
pub struct ReplyTo {
    pub thread_id: String,
    /// Message-ID of the message being answered.
    pub message_id: String,
}

impl Outgoing {
    /// To, Cc and Bcc, validated. Rejects anything that is not a plain address, which also
    /// rules out smuggling extra headers in through these fields.
    pub fn recipients(&self) -> Result<(Vec<String>, Vec<String>, Vec<String>)> {
        let (to, cc, bcc) = (
            addresses(&self.to)?,
            addresses(&self.cc)?,
            addresses(&self.bcc)?,
        );
        if to.is_empty() && cc.is_empty() && bcc.is_empty() {
            bail!("Add at least one recipient.");
        }
        Ok((to, cc, bcc))
    }

    /// Total size of the attached files.
    pub fn attachment_size(&self) -> u64 {
        self.files.iter().map(|f| f.bytes.len() as u64).sum::<u64>()
            + self.kept.iter().map(|a| a.size).sum::<u64>()
    }

    /// Builds the RFC 5322 message, with `extra` files (the kept ones, downloaded).
    /// Gmail fills in From and Date. A draft may still have no (or unfinished)
    /// recipients; a message being sent may not.
    pub(crate) fn to_rfc822(&self, draft: bool, extra: &[OutgoingFile]) -> Result<Vec<u8>> {
        use base64::engine::general_purpose::STANDARD;
        let (to, cc, bcc) = match self.recipients() {
            Ok(lists) => lists,
            Err(_) if draft => {
                let valid = |list: &str| -> Vec<String> {
                    list.split([',', ';'])
                        .map(|p| address_of(p.trim()))
                        .filter(|a| is_address(a))
                        .collect()
                };
                (valid(&self.to), valid(&self.cc), valid(&self.bcc))
            }
            Err(error) => return Err(error),
        };
        let files: Vec<&OutgoingFile> = self.files.iter().chain(extra).collect();
        let size: u64 = files.iter().map(|f| f.bytes.len() as u64).sum();
        if size > ATTACHMENT_LIMIT {
            bail!("Attachments are over Gmail’s 25 MB limit.");
        }
        let mut message = String::new();
        for (name, list) in [("To", &to), ("Cc", &cc), ("Bcc", &bcc)] {
            if !list.is_empty() {
                message.push_str(&format!("{name}: {}\r\n", list.join(", ")));
            }
        }
        // Encoded-word form keeps the header ASCII and free of line breaks whatever was typed.
        message.push_str(&format!(
            "Subject: =?UTF-8?B?{}?=\r\n",
            STANDARD.encode(clean_header(&self.subject))
        ));
        if let Some(reply) = &self.reply
            && is_message_id(&reply.message_id)
        {
            message.push_str(&format!("In-Reply-To: {}\r\n", reply.message_id));
            message.push_str(&format!("References: {}\r\n", reply.message_id));
        }
        message.push_str("MIME-Version: 1.0\r\n");
        let text = self.body.replace("\r\n", "\n").replace('\n', "\r\n");
        let body_part = |message: &mut String| -> Result<()> {
            match &self.html {
                Some(html) => {
                    let boundary = format!("alt-{}", random_hex(12)?);
                    message.push_str(&format!(
                        "Content-Type: multipart/alternative; boundary=\"{boundary}\"\r\n\r\n"
                    ));
                    message.push_str(&format!("--{boundary}\r\n"));
                    message.push_str("Content-Type: text/plain; charset=UTF-8\r\n");
                    message.push_str("Content-Transfer-Encoding: base64\r\n\r\n");
                    push_base64(message, text.as_bytes());
                    message.push_str(&format!("--{boundary}\r\n"));
                    message.push_str("Content-Type: text/html; charset=UTF-8\r\n");
                    message.push_str("Content-Transfer-Encoding: base64\r\n\r\n");
                    push_base64(message, html.as_bytes());
                    message.push_str(&format!("--{boundary}--\r\n"));
                }
                None => {
                    message.push_str("Content-Type: text/plain; charset=UTF-8\r\n");
                    message.push_str("Content-Transfer-Encoding: base64\r\n\r\n");
                    push_base64(message, text.as_bytes());
                }
            }
            Ok(())
        };
        if files.is_empty() {
            body_part(&mut message)?;
        } else {
            let boundary = format!("mixed-{}", random_hex(12)?);
            message.push_str(&format!(
                "Content-Type: multipart/mixed; boundary=\"{boundary}\"\r\n\r\n"
            ));
            message.push_str(&format!("--{boundary}\r\n"));
            body_part(&mut message)?;
            for file in files {
                let name = safe_file_name(&file.name);
                // A content type that came from outside is only kept if it looks like one.
                let mime = if file.mime.len() < 100
                    && file.mime.contains('/')
                    && file
                        .mime
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || "/.+-".contains(c))
                {
                    file.mime.as_str()
                } else {
                    "application/octet-stream"
                };
                let encoded = encode_filename(&name);
                message.push_str(&format!("--{boundary}\r\n"));
                message.push_str(&format!("Content-Type: {mime}; name*=UTF-8''{encoded}\r\n"));
                message.push_str(&format!(
                    "Content-Disposition: attachment; filename*=UTF-8''{encoded}\r\n"
                ));
                message.push_str("Content-Transfer-Encoding: base64\r\n\r\n");
                push_base64(&mut message, &file.bytes);
            }
            message.push_str(&format!("--{boundary}--\r\n"));
        }
        Ok(message.into_bytes())
    }
}

impl Outgoing {
    /// The message as it is sent over SMTP or saved over IMAP, where nothing fills in the
    /// headers Gmail adds: From, Date and Message-ID come first. Bcc stays only in a draft:
    /// in a sent message it would show every recipient who was meant to be hidden.
    pub(crate) fn to_rfc822_from(
        &self,
        from: &str,
        message_id: &str,
        draft: bool,
        extra: &[OutgoingFile],
    ) -> Result<Vec<u8>> {
        if !is_address(from) || !is_message_id(message_id) {
            bail!("unexpected sender or message id");
        }
        let body = self.to_rfc822(draft, extra)?;
        let mut message = format!(
            "From: {from}\r\nDate: {}\r\nMessage-ID: {message_id}\r\n",
            chrono::Local::now().to_rfc2822()
        )
        .into_bytes();
        if draft {
            message.extend_from_slice(&body);
        } else {
            message.extend_from_slice(&without_bcc(&body));
        }
        Ok(message)
    }
}

/// A new Message-ID for a message sent from `from` (its domain after the random part).
pub(crate) fn new_message_id(from: &str) -> Result<String> {
    let domain = from.rsplit_once('@').map_or("nimbra.invalid", |(_, d)| d);
    Ok(format!("<{}@{domain}>", random_hex(16)?))
}

/// The message without its Bcc header (only the header block is looked at).
pub(crate) fn without_bcc(message: &[u8]) -> Vec<u8> {
    let end = message
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or(message.len(), |at| at + 2);
    let (head, body) = message.split_at(end);
    let mut out = Vec::with_capacity(message.len());
    let mut skipping = false;
    for line in head.split_inclusive(|&b| b == b'\n') {
        let folded = line.first().is_some_and(|b| *b == b' ' || *b == b'\t');
        if !folded {
            skipping = line.len() >= 4 && line[..4].eq_ignore_ascii_case(b"bcc:");
        }
        if !skipping {
            out.extend_from_slice(line);
        }
    }
    out.extend_from_slice(body);
    out
}

/// Collapses a typed header value to one line without control characters.
pub(crate) fn clean_header(value: &str) -> String {
    value
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// `Name <a@b.co>` or `a@b.co` to `a@b.co`.
/// A sender or recipient: display name (may be empty) and address.
#[derive(Clone, Debug, Default, PartialEq, serde::Serialize, Deserialize)]
pub struct Person {
    pub name: String,
    pub address: String,
}

impl Person {
    /// The name if there is one, else the address.
    pub fn label(&self) -> &str {
        if self.name.is_empty() {
            &self.address
        } else {
            &self.name
        }
    }
}

/// A file attached to a message.
#[derive(Clone, Debug, PartialEq, serde::Serialize, Deserialize)]
pub struct Attachment {
    /// Gmail's id of the message it belongs to.
    pub message_id: String,
    pub attachment_id: String,
    pub name: String,
    pub mime: String,
    pub size: u64,
}

pub(crate) fn person(value: &str) -> Person {
    let address = address_of(value);
    let name = value
        .split('<')
        .next()
        .unwrap_or("")
        .trim()
        .trim_matches('"')
        .trim()
        .to_string();
    let name = if name == address { String::new() } else { name };
    Person {
        name: decode_entities(&name),
        address,
    }
}

/// Splits an address list on commas that are not inside quotes, keeping valid addresses.
pub(crate) fn people(list: &str) -> Vec<Person> {
    let mut parts = Vec::new();
    let (mut start, mut quoted) = (0, false);
    for (i, c) in list.char_indices() {
        match c {
            '"' => quoted = !quoted,
            ',' if !quoted => {
                parts.push(&list[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(&list[start..]);
    parts
        .into_iter()
        .filter(|p| !p.trim().is_empty())
        .map(person)
        .filter(|p| is_address(&p.address))
        .collect()
}

/// A file name that is safe to create in a folder: no path separators, no leading dots,
/// no control characters, and not too long.
pub fn safe_file_name(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_control() || "/\\:".contains(c) {
                '_'
            } else {
                c
            }
        })
        .collect();
    let cleaned = cleaned.trim().trim_start_matches('.').trim();
    let cleaned: String = cleaned.chars().take(120).collect();
    if cleaned.is_empty() {
        "attachment".to_string()
    } else {
        cleaned
    }
}

/// The message a `mailto:` unsubscribe link asks for.
pub struct UnsubscribeMail {
    pub to: String,
    pub subject: String,
    pub body: String,
}

/// Reads a `mailto:` unsubscribe link (RFC 6068). The sender wrote it, so only one address,
/// a subject and a plain-text body are taken from it: never a Cc or a Bcc.
pub fn unsubscribe_mail(link: &str) -> Option<UnsubscribeMail> {
    let url = url::Url::parse(link)
        .ok()
        .filter(|u| u.scheme() == "mailto")?;
    // In a mailto a plus is a plus, not a space as in a form.
    let decode = |query: String| -> Vec<(String, String)> {
        url::form_urlencoded::parse(query.replace('+', "%2B").as_bytes())
            .map(|(key, value)| (key.to_ascii_lowercase(), value.into_owned()))
            .collect()
    };
    let to = decode(format!("to={}", url.path())).into_iter().next()?.1;
    if to.contains([',', ';', '<', '>']) || !is_address(&to) {
        return None;
    }
    let fields = decode(url.query().unwrap_or("").to_string());
    let field = |name: &str| fields.iter().find(|(key, _)| key == name).map(|(_, v)| v);
    let subject: String = field("subject")
        .map_or("unsubscribe", String::as_str)
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(300)
        .collect();
    let body: String = field("body")
        .map_or("", String::as_str)
        .chars()
        .filter(|c| !c.is_control() || *c == '\n')
        .take(2000)
        .collect();
    Some(UnsubscribeMail {
        to,
        subject: if subject.trim().is_empty() {
            "unsubscribe".into()
        } else {
            subject
        },
        body,
    })
}

/// The best way out of a mailing list: an https link if offered, else a mailto address.
pub(crate) fn unsubscribe_link(header: &str) -> Option<String> {
    // Each is in angle brackets (RFC 2369): commas may be inside one, and so may the
    // whitespace of a folded header, which is not part of it. Some senders omit them.
    let links: Vec<String> = if header.contains('<') {
        header
            .split('<')
            .skip(1)
            .filter_map(|part| part.split_once('>'))
            .map(|(link, _)| link.split_ascii_whitespace().collect())
            .collect()
    } else {
        header.split(',').map(|p| p.trim().to_string()).collect()
    };
    links
        .iter()
        .find(|l| l.to_ascii_lowercase().starts_with("https://"))
        .or_else(|| {
            links
                .iter()
                .find(|l| l.to_ascii_lowercase().starts_with("mailto:"))
        })
        .filter(|l| l.len() <= 2000 && !l.chars().any(|c| c.is_whitespace() || c.is_control()))
        .map(|l| l.to_string())
}

pub(crate) fn address_of(value: &str) -> String {
    let value = value.trim();
    match (value.rfind('<'), value.rfind('>')) {
        (Some(open), Some(close)) if open < close => value[open + 1..close].trim().to_string(),
        _ => value.to_string(),
    }
}

/// A deliberately strict address check: one `@`, a dotted domain, and only characters
/// that cannot break out of a header.
pub(crate) fn is_address(address: &str) -> bool {
    let Some((local, domain)) = address.split_once('@') else {
        return false;
    };
    let ok = |part: &str, extra: &str| {
        !part.is_empty()
            && part
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || extra.contains(c))
    };
    address.len() <= 254
        && ok(local, ".!#$%&'*+/=?^_`{|}~-")
        && ok(domain, ".-")
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
}

pub(crate) fn is_message_id(value: &str) -> bool {
    value.len() <= 998
        && value.starts_with('<')
        && value.ends_with('>')
        && value.chars().all(|c| c.is_ascii_graphic())
}

/// The mailboxes the sidebar can show.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum View {
    /// Every signed-in account's inbox, merged (listed account by account as `Inbox`).
    AllInboxes,
    Inbox,
    /// Gmail's inbox categories.
    Primary,
    Updates,
    Promotions,
    Social,
    /// One of the user's own labels, by position in the fetched label list.
    Label(usize),
    /// Results of a search; the query travels alongside.
    Search,
    Starred,
    Snoozed,
    Drafts,
    Sent,
    Done,
    /// Everything except Spam and Trash.
    AllMail,
    Important,
    Spam,
    Trash,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, Deserialize)]
pub enum Change {
    Archive,
    Unarchive,
    Trash,
    Untrash,
    Star,
    Unstar,
    MarkRead,
    MarkUnread,
    Spam,
    NotSpam,
}

impl Change {
    /// The change that reverses this one, for undo.
    pub fn inverse(self) -> Option<Change> {
        match self {
            Change::Archive => Some(Change::Unarchive),
            Change::Unarchive => Some(Change::Archive),
            Change::Trash => Some(Change::Untrash),
            Change::Untrash => Some(Change::Trash),
            Change::Star => Some(Change::Unstar),
            Change::Unstar => Some(Change::Star),
            Change::MarkRead | Change::MarkUnread => None,
            Change::Spam => Some(Change::NotSpam),
            Change::NotSpam => Some(Change::Spam),
        }
    }
}

#[derive(Clone, serde::Serialize, Deserialize)]
pub struct Label {
    pub id: String,
    pub name: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Summary {
    pub id: String,
    pub sender: String,
    pub subject: String,
    pub snippet: String,
    pub timestamp_ms: i64,
    pub message_count: usize,
    pub unread: bool,
    pub starred: bool,
    /// Every label on any message in the thread, to tell which mailboxes it belongs to.
    pub labels: Vec<String>,
    /// Each message's own, for the mailboxes that are searches (`View::takes`).
    pub message_labels: Vec<Vec<String>>,
}

pub struct Message {
    pub from: Person,
    pub to: Vec<Person>,
    pub cc: Vec<Person>,
    pub reply_to: Option<Person>,
    pub attachments: Vec<Attachment>,
    /// Where to unsubscribe (`https:` or `mailto:`), from the List-Unsubscribe header.
    pub unsubscribe: Option<String>,
    /// The sender's bare email address, for replying.
    pub address: String,
    /// The RFC 5322 Message-ID header, for threading a reply.
    pub message_id: String,
    /// Everyone else the message was addressed to (To and Cc), for reply-all.
    pub others: Vec<String>,
    pub sender: String,
    pub snippet: String,
    pub timestamp_ms: i64,
    pub blocks: Vec<crate::rich::Block>,
    /// The original HTML body, if the message has one, for "Show original".
    pub html: Option<String>,
}

/// `"Mira Kovač" <mira@example.com>` becomes `Mira Kovač`; a bare address stays as is.
pub(crate) fn sender_name(from: &str) -> String {
    let name = from
        .split('<')
        .next()
        .unwrap_or("")
        .trim()
        .trim_matches('"')
        .trim();
    let name = if name.is_empty() {
        from.trim().trim_matches(['<', '>'])
    } else {
        name
    };
    if name.is_empty() {
        "Unknown sender".to_string()
    } else {
        name.to_string()
    }
}

/// Gmail snippets are HTML-escaped.
pub(crate) fn decode_entities(text: &str) -> String {
    text.replace("&#39;", "’")
        .replace("&quot;", "\"")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&nbsp;", " ")
        .replace("&amp;", "&")
        .replace(['\u{200c}', '\u{200b}', '\u{feff}', '\u{34f}'], "")
        .trim()
        .to_string()
}

/// Splits a message into paragraphs and drops the quoted reply chain.
pub(crate) fn paragraphs(text: &str) -> Vec<String> {
    let text: String = text.chars().take(MAX_BODY_CHARS).collect();
    let mut out = Vec::new();
    let mut current = String::new();
    for line in text.lines() {
        let line = line.trim_end();
        let trimmed = line.trim_start();
        if trimmed.starts_with('>') {
            continue;
        }
        // "On Tue, ... wrote:" introduces the quoted history; stop there.
        if trimmed.starts_with("On ") && trimmed.ends_with("wrote:") {
            break;
        }
        if trimmed.is_empty() {
            if !current.is_empty() {
                out.push(std::mem::take(&mut current));
            }
        } else {
            if !current.is_empty() {
                current.push('\n');
            }
            current.push_str(line);
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}
/// Cap on how much of one message is rendered.
pub(crate) const MAX_BODY_CHARS: usize = 20_000;

/// Keeps short, printable ASCII only, for text that came from outside and is shown in the UI.
pub(crate) fn sanitize(text: &str) -> String {
    text.chars()
        .filter(|c| c.is_ascii_alphanumeric() || " _-.".contains(*c))
        .take(80)
        .collect()
}

/// The account's profile photo.
pub enum Photo {
    /// Theirs.
    Image(Vec<u8>),
    /// What Google gives every app, which can be a letter it drew: the People API, which
    /// tells the two apart, could not be asked.
    Unchecked(Vec<u8>),
    /// The account has none (that Nimbra can see).
    NoPhoto,
    /// This sign-in does not include the profile (signed in before Nimbra asked for it).
    NotAllowed,
}

/// A connection to one account's mail, whichever provider it is with. Blocking: the app
/// calls it from background threads. Ids (threads, messages, drafts, labels) are the
/// provider's, and only ever handed back to the connection that gave them.
pub trait Provider: Send + Sync {
    /// The account's address, and the point in its change feed now.
    fn profile(&self) -> Result<(String, String)>;
    /// The account's own photo, where the provider has one.
    fn profile_photo(&self) -> Result<Photo> {
        Ok(Photo::NoPhoto)
    }
    /// Changes asked for so far, so that what was listed before one is known to be old.
    fn writes(&self) -> u64;
    /// Forgets the list rows kept in memory.
    fn forget_rows(&self);
    /// Takes up the rows kept in the account's store, and keeps them there from now on.
    fn keep_rows_in(&self, store: &std::sync::Arc<crate::store::Store>);
    /// What changed since a point in the change feed.
    fn history(&self, start: &str) -> Result<Changes>;
    /// A page of a mailbox's threads, newest first, and where the next page starts.
    fn threads_page(
        &self,
        view: View,
        label_id: Option<&str>,
        limit: usize,
        page: Option<&str>,
    ) -> Result<(Vec<Summary>, Option<String>)>;
    /// Where the page after the first `count` threads starts.
    fn page_after(
        &self,
        view: View,
        label_id: Option<&str>,
        count: usize,
    ) -> Result<Option<String>>;
    /// One thread's row. `recipient`: name the recipient rather than the sender (Sent).
    fn summary(&self, id: &str, recipient: bool) -> Result<Summary>;
    /// A thread's messages, oldest first.
    fn thread(&self, id: &str) -> Result<Vec<Message>>;
    /// An attachment's content.
    fn download(&self, message_id: &str, attachment_id: &str) -> Result<Vec<u8>>;
    /// Archives, trashes, stars, marks read… a thread.
    fn change(&self, id: &str, change: Change) -> Result<()>;
    /// The draft in a thread (Drafts lists threads).
    fn draft_for_thread(&self, thread_id: &str) -> Result<Draft>;
    /// Saves a draft, new or over `id`; returns its id.
    fn save_draft(&self, id: Option<&str>, outgoing: &Outgoing) -> Result<String>;
    /// Saves the edits over a draft and sends it.
    fn send_draft(&self, id: &str, outgoing: &Outgoing) -> Result<()>;
    /// Keeps a message that was not sent as a draft (over `id`, or new if that is gone).
    fn keep_as_draft(&self, id: Option<&str>, outgoing: &Outgoing) -> Result<String>;
    /// Sends a draft as it is saved.
    fn send_saved_draft(&self, id: &str) -> Result<()>;
    fn delete_draft(&self, id: &str) -> Result<()>;
    fn send_message(&self, outgoing: &Outgoing) -> Result<()>;
    /// Deletes a thread for good.
    fn delete_thread(&self, id: &str) -> Result<()>;
    fn labels(&self) -> Result<Vec<Label>>;
    fn create_label(&self, name: &str) -> Result<Label>;
    fn rename_label(&self, id: &str, name: &str) -> Result<()>;
    fn delete_label(&self, id: &str) -> Result<()>;
    fn add_label(&self, id: &str, label_id: &str) -> Result<()>;
    fn remove_label(&self, id: &str, label_id: &str) -> Result<()>;
    /// Adds and removes labels in one change (a move: add the label, leave the inbox).
    fn relabel(&self, id: &str, add: &[&str], remove: &[&str]) -> Result<()>;
    /// Unread and total threads for these label ids (for the sidebar).
    fn counts(&self, label_ids: &[String]) -> std::collections::HashMap<String, (u32, u32)>;
}

/// The connection the app holds for an account.
pub type Client = dyn Provider;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sent_message_has_its_own_headers_and_no_bcc() {
        let mail = Outgoing {
            to: "ana@example.com".into(),
            bcc: "hidden@example.com".into(),
            subject: "Hi".into(),
            body: "Hello".into(),
            ..Default::default()
        };
        let id = new_message_id("me@example.org").unwrap();
        let sent = String::from_utf8(
            mail.to_rfc822_from("me@example.org", &id, false, &[])
                .unwrap(),
        )
        .unwrap();
        assert!(sent.starts_with("From: me@example.org\r\nDate: "));
        assert!(sent.contains(&format!("Message-ID: {id}\r\n")));
        assert!(id.ends_with("@example.org>"));
        assert!(sent.contains("To: ana@example.com\r\n"));
        assert!(!sent.contains("hidden@example.com"));
        let draft = String::from_utf8(
            mail.to_rfc822_from("me@example.org", &id, true, &[])
                .unwrap(),
        )
        .unwrap();
        assert!(draft.contains("Bcc: hidden@example.com\r\n"));
    }

    #[test]
    fn only_the_bcc_header_goes() {
        let raw =
            b"To: a@b.co\r\nBcc: c@d.co,\r\n e@f.co\r\nSubject: x\r\n\r\nBcc: kept in the body\r\n";
        let out = String::from_utf8(without_bcc(raw)).unwrap();
        assert_eq!(
            out,
            "To: a@b.co\r\nSubject: x\r\n\r\nBcc: kept in the body\r\n"
        );
    }
}
