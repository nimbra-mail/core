//! Raw RFC 5322 mail, as IMAP hands it over, turned into the app's model the same way
//! `gmail.rs` turns Gmail's JSON into it.
//!
//! Security notes:
//! - Every byte here came from a stranger. Nothing panics, bodies are capped and file
//!   names are made safe before anything else sees them.
//! - HTML only ever goes to `html` (shown in the locked-down web view) or through the
//!   converters to text and blocks. Nothing is fetched.

use base64::Engine as _;
use mail_parser::{Addr, Address, HeaderValue, MessageParser, MessagePart, MimeHeaders, PartType};

use crate::mail::{
    self, Attachment, Draft, INLINE_IMAGE_BUDGET, MAX_BODY_CHARS, MAX_HTML_BYTES, Message, Person,
    ReplyTo, clean_header, inline_image, is_address, is_message_id, paragraphs, prefix,
    safe_file_name, split_quote, unsubscribe_link,
};

type Parsed<'a> = mail_parser::Message<'a>;

const SNIPPET_CHARS: usize = 200;
/// A list row needs the first and the latest few, not a whole long chain.
const MAX_REFERENCES: usize = 200;

/// The headers a thread and its list row are built from.
pub struct Headers {
    /// In angle brackets; empty when missing or malformed.
    pub message_id: String,
    pub in_reply_to: Option<String>,
    /// Oldest first, each in angle brackets.
    pub references: Vec<String>,
    pub from: Person,
    pub to: Vec<Person>,
    pub cc: Vec<Person>,
    pub subject: String,
    pub timestamp_ms: i64,
    /// The topmost Authentication-Results, the receiving server's (`mail::dmarc_domain`).
    pub authentication: String,
}

/// One whole message. `message_key` is the backend's id for it, carried by its attachments.
pub fn message(raw: &[u8], message_key: &str) -> Option<Message> {
    let parsed = parse(raw)?;
    let from = from_of(&parsed);
    let to = people_of(parsed.all_to());
    let cc = people_of(parsed.all_cc());
    let blocks = body_blocks(&parsed);
    let mut html = html_of(&parsed);
    // Images embedded in the message itself are inlined as data URLs, so the original
    // view can show them without any network access.
    if let Some(html) = html.as_mut()
        && html.contains("cid:")
    {
        inline_images(html, &parsed);
    }
    Some(Message {
        sender: sender_of(&from),
        address: from.address.clone(),
        from,
        others: to.iter().chain(&cc).map(|p| p.address.clone()).collect(),
        to,
        cc,
        reply_to: people_of(parsed.reply_to()).into_iter().next(),
        attachments: attachments(&parsed, message_key),
        unsubscribe: parsed
            .header_raw("List-Unsubscribe")
            .and_then(unsubscribe_link),
        message_id: ids(parsed.header("Message-ID"))
            .into_iter()
            .next()
            .unwrap_or_default(),
        // HTML is read through the blocks: the text converter marks up bold and links.
        snippet: match first_plain(&parsed) {
            Some(text) => preview(text),
            None => preview(&blocks_text(&blocks)),
        },
        timestamp_ms: timestamp_ms(&parsed),
        blocks,
        html,
    })
}

/// The decoded bytes of one attachment, by the id `message` gave it.
pub fn attachment(raw: &[u8], attachment_id: &str) -> Option<Vec<u8>> {
    if attachment_id.is_empty()
        || attachment_id.len() > 9
        || !attachment_id.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let index: usize = attachment_id.parse().ok()?;
    let parsed = parse(raw)?;
    let part = parsed.parts.get(index)?;
    is_attachment(part).then(|| part.contents().to_vec())
}

/// A saved draft, ready for editing.
pub fn draft(raw: &[u8], draft_id: &str, message_key: &str, thread_id: &str) -> Option<Draft> {
    let parsed = parse(raw)?;
    let (body, quoted) = split_quote(&body_text(&parsed));
    let in_reply_to = ids(parsed.header("In-Reply-To")).into_iter().next();
    Some(Draft {
        id: draft_id.to_string(),
        to: address_text(parsed.all_to()),
        cc: address_text(parsed.all_cc()),
        bcc: address_text(parsed.all_bcc()),
        attachments: attachments(&parsed, message_key),
        subject: parsed.subject().map(clean_header).unwrap_or_default(),
        body,
        quoted,
        html: html_of(&parsed),
        reply: in_reply_to.map(|message_id| ReplyTo {
            thread_id: thread_id.to_string(),
            message_id,
        }),
    })
}

/// Reads a header block alone (what `BODY.PEEK[HEADER.FIELDS (...)]` returns).
pub fn headers(raw_header_bytes: &[u8]) -> Option<Headers> {
    let parsed = MessageParser::default().parse_headers(raw_header_bytes)?;
    if parsed.parts.first()?.headers.is_empty() {
        return None;
    }
    let mut references = ids(parsed.header("References"));
    if references.len() > MAX_REFERENCES {
        // The first names the thread's root; the last are the closest.
        let tail = references.split_off(references.len() - (MAX_REFERENCES - 1));
        references.truncate(1);
        references.extend(tail);
    }
    Some(Headers {
        message_id: ids(parsed.header("Message-ID"))
            .into_iter()
            .next()
            .unwrap_or_default(),
        in_reply_to: ids(parsed.header("In-Reply-To")).into_iter().next(),
        references,
        from: from_of(&parsed),
        to: people_of(parsed.all_to()),
        cc: people_of(parsed.all_cc()),
        subject: parsed.subject().map(clean_header).unwrap_or_default(),
        timestamp_ms: timestamp_ms(&parsed),
        // The first in the block, the topmost: `header_raw` would give the last one, which
        // the sender could have written.
        authentication: parsed
            .headers()
            .iter()
            .find(|h| h.name().eq_ignore_ascii_case("Authentication-Results"))
            .and_then(|h| {
                parsed
                    .raw_message()
                    .get(h.offset_start as usize..h.offset_end as usize)
            })
            .map(|raw| String::from_utf8_lossy(raw).trim().to_string())
            .unwrap_or_default(),
    })
}

/// A short preview from the start of a message, which may be cut off anywhere.
pub fn snippet(partial_raw: &[u8]) -> String {
    let Some(parsed) = parse(partial_raw) else {
        return String::new();
    };
    // The parser leaves a part it never saw the end of undecoded, and out of its body
    // lists, so the parts are walked here: the first plain text, else the first HTML.
    let mut html = None;
    for part in &parsed.parts {
        if is_attachment(part) {
            continue;
        }
        let Some(text) = cut_text(part) else {
            continue;
        };
        if matches!(part.body, PartType::Html(_)) || part.is_content_type("text", "html") {
            html.get_or_insert(text);
        } else if part.content_type().is_none() || part.is_content_type("text", "plain") {
            return preview(&text);
        }
    }
    html.map(|html| {
        // A tag cut in half would show as text.
        let html = prefix(&html, MAX_HTML_BYTES);
        let html = match html.rfind('<') {
            Some(at) if !html.get(at..).unwrap_or_default().contains('>') => {
                html.get(..at).unwrap_or_default()
            }
            _ => html,
        };
        preview(&blocks_text(&crate::rich::from_html(html)))
    })
    .unwrap_or_default()
}

/// A text part's text, decoding it here when the cut left it raw.
fn cut_text(part: &MessagePart) -> Option<String> {
    let (PartType::Text(text) | PartType::Html(text)) = &part.body else {
        return None;
    };
    if !part.is_encoding_problem {
        return Some(text.to_string());
    }
    let raw = text.as_bytes();
    let encoding = part
        .content_transfer_encoding()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let bytes = match encoding.as_str() {
        "quoted-printable" => {
            // An escape cut in half would fail the whole part.
            let end = raw
                .iter()
                .rposition(|&b| b == b'=')
                .filter(|&at| raw.len() - at < 3)
                .unwrap_or(raw.len());
            mail_parser::decoders::quoted_printable::quoted_printable_decode(raw.get(..end)?)?
        }
        "base64" => {
            // Group by group, so padding mid-stream or a cut group only ends it early.
            let clean: Vec<u8> = raw
                .iter()
                .copied()
                .filter(|b| !b.is_ascii_whitespace())
                .collect();
            let mut bytes = Vec::with_capacity(clean.len() / 4 * 3);
            for group in clean.as_chunks::<4>().0 {
                match base64::engine::general_purpose::STANDARD.decode(group) {
                    Ok(decoded) => bytes.extend(decoded),
                    Err(_) => break,
                }
            }
            bytes
        }
        _ => raw.to_vec(),
    };
    let decoder = part
        .content_type()
        .and_then(|ct| ct.attribute("charset"))
        .and_then(|charset| {
            mail_parser::decoders::charsets::map::charset_decoder(charset.as_bytes())
        });
    let text = match decoder {
        Some(decode) => decode(&bytes),
        None => String::from_utf8_lossy(&bytes).into_owned(),
    };
    // A character cut in half at the end.
    Some(text.trim_end_matches('\u{fffd}').to_string())
}

// ------------------------------------------------------------------ parsing

fn parse(raw: &[u8]) -> Option<Parsed<'_>> {
    // The parser's header accessors index the first part, so make sure there is one.
    MessageParser::default()
        .parse(raw)
        .filter(|parsed| !parsed.parts.is_empty())
}

/// Message-IDs in a header, each in angle brackets; malformed ones are dropped.
fn ids(value: Option<&HeaderValue>) -> Vec<String> {
    value
        .and_then(HeaderValue::as_text_list)
        .unwrap_or_default()
        .iter()
        .map(|id| id.trim().trim_start_matches('<').trim_end_matches('>'))
        .filter(|id| !id.is_empty())
        .map(|id| format!("<{id}>"))
        .filter(|id| is_message_id(id))
        .collect()
}

fn timestamp_ms(parsed: &Parsed) -> i64 {
    parsed
        .date()
        .filter(|date| date.is_valid())
        .map(|date| date.to_timestamp().saturating_mul(1000))
        .unwrap_or(0)
}

fn person_of(addr: &Addr) -> Person {
    let address = addr.address().map(clean_header).unwrap_or_default();
    let name = addr
        .name()
        .map(|name| clean_header(name).trim_matches('"').trim().to_string())
        .unwrap_or_default();
    let name = if name == address { String::new() } else { name };
    Person { name, address }
}

/// Everyone in some address headers who has a valid address.
fn people_of<'a>(lists: impl IntoIterator<Item = &'a Address<'a>>) -> Vec<Person> {
    lists
        .into_iter()
        .flat_map(Address::iter)
        .map(person_of)
        .filter(|p| is_address(&p.address))
        .collect()
}

/// The sender as written, even when its address is not one the app could answer.
fn from_of(parsed: &Parsed) -> Person {
    parsed
        .from()
        .and_then(Address::first)
        .map(person_of)
        .unwrap_or_default()
}

/// What `mail::sender_name` gives for a From header.
fn sender_of(from: &Person) -> String {
    match from.label() {
        "" => "Unknown sender".to_string(),
        label => label.to_string(),
    }
}

/// An address list as the composer's fields take it. A name that could split the list
/// or break the address is left out.
fn address_text<'a>(lists: impl IntoIterator<Item = &'a Address<'a>>) -> String {
    people_of(lists)
        .into_iter()
        .map(|p| {
            if p.name.is_empty() || p.name.contains([',', ';', '<', '>', '"']) {
                p.address
            } else {
                format!("{} <{}>", p.name, p.address)
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// The first HTML body, unless it is too large for the web view.
fn html_of(parsed: &Parsed) -> Option<String> {
    first_html(parsed)
        .filter(|html| html.len() <= MAX_HTML_BYTES)
        .map(str::to_string)
}

fn first_html<'a>(parsed: &'a Parsed) -> Option<&'a str> {
    parsed
        .html_body
        .iter()
        .filter_map(|&id| parsed.parts.get(id as usize))
        .find_map(|part| match &part.body {
            PartType::Html(html) => Some(html.as_ref()),
            _ => None,
        })
}

/// Prefers the plain-text alternative; otherwise converts HTML to text.
fn body_text(parsed: &Parsed) -> String {
    match first_plain(parsed) {
        Some(text) => text.to_string(),
        None => first_html(parsed).map(html_to_text).unwrap_or_default(),
    }
}

fn first_plain<'a>(parsed: &'a Parsed) -> Option<&'a str> {
    parsed
        .text_body
        .iter()
        .filter_map(|&id| parsed.parts.get(id as usize))
        .find_map(|part| match &part.body {
            PartType::Text(text) => Some(text.as_ref()),
            _ => None,
        })
}

fn html_to_text(html: &str) -> String {
    html2text::from_read(prefix(html, MAX_HTML_BYTES).as_bytes(), 10_000).unwrap_or_default()
}

/// The message as styled blocks: the HTML alternative when it has one (it carries
/// the formatting), otherwise the plain text.
fn body_blocks(parsed: &Parsed) -> Vec<crate::rich::Block> {
    if let Some(html) = first_html(parsed) {
        let blocks = crate::rich::from_html(prefix(html, MAX_HTML_BYTES));
        if !blocks.is_empty() {
            return blocks;
        }
    }
    crate::rich::from_text(paragraphs(&body_text(parsed)))
}

fn blocks_text(blocks: &[crate::rich::Block]) -> String {
    blocks
        .iter()
        .map(|block| block.text.as_str())
        .collect::<Vec<_>>()
        .join("\n")
}

/// About 200 characters of text on one line, without invisible padding.
fn preview(text: &str) -> String {
    let start: String = text.chars().take(MAX_BODY_CHARS).collect();
    start
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .filter(|c| !c.is_control() && !['\u{200c}', '\u{200b}', '\u{feff}', '\u{34f}'].contains(c))
        .take(SNIPPET_CHARS)
        .collect::<String>()
        .trim()
        .to_string()
}

// ------------------------------------------------------------------ attachments

/// A real attachment has a file name. Images embedded in the body (inline, with a
/// Content-ID) are left out, as `gmail.rs` decides.
fn is_attachment(part: &MessagePart) -> bool {
    if matches!(part.body, PartType::Multipart(_)) {
        return false;
    }
    if part
        .attachment_name()
        .is_none_or(|name| name.trim().is_empty())
    {
        return false;
    }
    let inline = part
        .content_disposition()
        .is_some_and(|d| d.ctype().eq_ignore_ascii_case("inline"));
    !(inline && part.content_id().is_some())
}

/// A part's content type, when it looks like one; else one guessed from the file name.
fn mime_of(part: &MessagePart, name: &str) -> String {
    let declared = part.content_type().map(|ct| {
        let subtype = ct.subtype().unwrap_or_default();
        format!("{}/{subtype}", ct.ctype()).to_ascii_lowercase()
    });
    match declared {
        Some(mime)
            if mime.len() < 100
                && !mime.ends_with('/')
                && mime
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "/.+-".contains(c)) =>
        {
            mime
        }
        _ => mail::mime_for(name).to_string(),
    }
}

/// One entry per attachment; its id is the part's place in the parser's part list.
fn attachments(parsed: &Parsed, message_key: &str) -> Vec<Attachment> {
    parsed
        .parts
        .iter()
        .enumerate()
        .filter(|(_, part)| is_attachment(part))
        .map(|(index, part)| {
            let name = safe_file_name(part.attachment_name().unwrap_or_default());
            Attachment {
                message_id: message_key.to_string(),
                attachment_id: index.to_string(),
                mime: mime_of(part, &name),
                name,
                size: part.len() as u64,
            }
        })
        .collect()
}

/// Replaces `cid:` image links in `html` with the image data from the message's parts.
fn inline_images(html: &mut String, parsed: &Parsed) {
    let mut budget = INLINE_IMAGE_BUDGET;
    for part in &parsed.parts {
        let Some(cid) = part
            .content_id()
            .map(|v| v.trim().trim_matches(['<', '>']).to_string())
            .filter(|cid| !cid.is_empty())
        else {
            continue;
        };
        let mime = mime_of(part, "");
        if !matches!(
            mime.as_str(),
            "image/png" | "image/jpeg" | "image/gif" | "image/webp"
        ) {
            continue;
        }
        if !html.contains(&format!("cid:{cid}")) {
            continue;
        }
        let bytes = match &part.body {
            PartType::Binary(bytes) | PartType::InlineBinary(bytes) => bytes.as_ref(),
            _ => continue,
        };
        if !inline_image(html, &cid, &mime, bytes, &mut budget) {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_topmost_authentication_results_is_kept() {
        let raw = b"Authentication-Results: mx.example.net; dmarc=pass header.from=shop.com\r\nAuthentication-Results: evil.example; dmarc=pass header.from=bank.com\r\nFrom: Shop <hi@shop.com>\r\nSubject: Hi\r\n\r\n";
        let headers = headers(raw).unwrap();
        assert_eq!(
            headers.authentication,
            "mx.example.net; dmarc=pass header.from=shop.com"
        );
        assert_eq!(
            crate::mail::dmarc_domain(&headers.authentication, &headers.from.address),
            Some("shop.com".into())
        );
    }

    fn crlf(text: &str) -> Vec<u8> {
        text.replace('\n', "\r\n").into_bytes()
    }

    #[test]
    fn plain_text_message() {
        let raw = crlf(
            "From: \"Ana Lima\" <ana@example.com>\n\
             To: Luan <luan@example.com>, bob@example.com, not-an-address\n\
             Cc: Cy <cy@example.org>\n\
             Reply-To: lists@example.com\n\
             Subject: Trip\n\
             Date: Tue, 14 Nov 2023 22:13:20 +0000\n\
             Message-ID: <abc.123@example.com>\n\
             List-Unsubscribe: <mailto:leave@example.com>, <https://example.com/u?x=1>\n\
             \n\
             Hi there,\n\
             \n\
             See   you\tsoon.\n\
             \n\
             On Mon, Nov 13 Luan wrote:\n\
             > earlier\n",
        );
        let m = message(&raw, "42").unwrap();
        assert_eq!(m.from.name, "Ana Lima");
        assert_eq!(
            (m.address.as_str(), m.sender.as_str()),
            ("ana@example.com", "Ana Lima")
        );
        assert_eq!(m.to.len(), 2);
        assert_eq!(m.to[0].name, "Luan");
        assert_eq!(
            m.to[1],
            Person {
                name: String::new(),
                address: "bob@example.com".into()
            }
        );
        assert_eq!(
            m.others,
            ["luan@example.com", "bob@example.com", "cy@example.org"]
        );
        assert_eq!(m.reply_to.unwrap().address, "lists@example.com");
        assert_eq!(m.message_id, "<abc.123@example.com>");
        assert_eq!(m.timestamp_ms, 1_700_000_000_000);
        assert_eq!(m.unsubscribe.as_deref(), Some("https://example.com/u?x=1"));
        assert!(m.snippet.starts_with("Hi there, See you soon. On Mon"));
        assert!(m.html.is_none() && m.attachments.is_empty());
        let texts: Vec<&str> = m.blocks.iter().map(|b| b.text.as_str()).collect();
        assert!(texts.iter().any(|t| t.contains("See   you")));
        assert!(!texts.iter().any(|t| t.contains("earlier")));
    }

    #[test]
    fn multipart_alternative_prefers_html_blocks_and_plain_snippet() {
        let raw = crlf(
            "From: ana@example.com\n\
             Subject: Alt\n\
             MIME-Version: 1.0\n\
             Content-Type: multipart/alternative; boundary=\"b1\"\n\
             \n\
             --b1\n\
             Content-Type: text/plain; charset=utf-8\n\
             \n\
             Plain version\n\
             --b1\n\
             Content-Type: text/html; charset=utf-8\n\
             Content-Transfer-Encoding: base64\n\
             \n\
             PHA+PGI+Qm9sZDwvYj4gdmVyc2lvbjwvcD4=\n\
             --b1--\n",
        );
        let m = message(&raw, "7").unwrap();
        assert_eq!(m.sender, "ana@example.com");
        assert_eq!(m.snippet, "Plain version");
        assert_eq!(m.html.as_deref(), Some("<p><b>Bold</b> version</p>"));
        assert_eq!(
            m.blocks.first().map(|b| b.text.as_str()),
            Some("Bold version")
        );
        assert!(m.blocks[0].spans.iter().any(|s| s.bold));
        assert_eq!(m.timestamp_ms, 0);
        assert!(m.message_id.is_empty());
    }

    const MIXED: &str = "From: ana@example.com\n\
         Subject: Files\n\
         Content-Type: multipart/mixed; boundary=\"mix\"\n\
         \n\
         --mix\n\
         Content-Type: text/html; charset=utf-8\n\
         \n\
         <p>Logo: <img src=\"cid:logo1\"></p>\n\
         --mix\n\
         Content-Type: image/png\n\
         Content-ID: <logo1>\n\
         Content-Disposition: inline; filename=\"logo.png\"\n\
         Content-Transfer-Encoding: base64\n\
         \n\
         iVBORw0K\n\
         --mix\n\
         Content-Type: application/pdf; name=\"x.pdf\"\n\
         Content-Disposition: attachment; filename=\"../../Plan Q4.pdf\"\n\
         Content-Transfer-Encoding: base64\n\
         \n\
         JVBERi0xLjQKaGVsbG8=\n\
         --mix--\n";

    #[test]
    fn mixed_message_lists_real_attachments_and_inlines_images() {
        let raw = crlf(MIXED);
        let m = message(&raw, "uid-9").unwrap();
        assert_eq!(m.attachments.len(), 1);
        let a = &m.attachments[0];
        assert_eq!(a.message_id, "uid-9");
        assert_eq!(a.name, "_.._Plan Q4.pdf");
        assert_eq!((a.mime.as_str(), a.size), ("application/pdf", 14));
        assert_eq!(
            attachment(&raw, &a.attachment_id).as_deref(),
            Some(&b"%PDF-1.4\nhello"[..])
        );
        // The inline image is not an attachment, and is drawn from the message itself.
        let html = m.html.unwrap();
        assert!(html.contains("data:image/png;base64,iVBORw0K") && !html.contains("cid:"));
        let logo = m.attachments[0].attachment_id.parse::<usize>().unwrap() - 1;
        assert_eq!(attachment(&raw, &logo.to_string()), None);
        // Ids that are not a plain index of an attachment part get nothing.
        for id in ["", "0", "1", "-2", "+2", " 2", "99", "99999999999999", "2a"] {
            assert_eq!(attachment(&raw, id), None, "{id:?}");
        }
    }

    #[test]
    fn one_image_linked_many_times_does_not_multiply_the_html() {
        let image = base64::engine::general_purpose::STANDARD.encode(vec![0u8; 100_000]);
        let raw = crlf(&format!(
            "From: ana@example.com\n\
             Content-Type: multipart/related; boundary=\"rel\"\n\
             \n\
             --rel\n\
             Content-Type: text/html; charset=utf-8\n\
             \n\
             <p>{}</p>\n\
             --rel\n\
             Content-Type: image/png\n\
             Content-ID: <a>\n\
             Content-Transfer-Encoding: base64\n\
             \n\
             {image}\n\
             --rel--\n",
            "<img src=\"cid:a\">".repeat(200)
        ));
        let html = message(&raw, "uid-1").unwrap().html.unwrap();
        assert!(
            html.len() <= MAX_HTML_BYTES + INLINE_IMAGE_BUDGET,
            "{} bytes",
            html.len()
        );
    }

    #[test]
    fn encoded_words_are_decoded() {
        let raw = crlf(
            "From: =?UTF-8?B?TWlyYSBLb3ZhxI0=?= <mira@example.com>\n\
             To: =?utf-8?Q?Jos=C3=A9_P=C3=A9rez?= <jose@example.com>\n\
             Subject: =?UTF-8?Q?Caf=C3=A9_?= =?UTF-8?B?4piV?=\n\
             \n\
             x\n",
        );
        let m = message(&raw, "1").unwrap();
        assert_eq!(m.sender, "Mira Kovač");
        assert_eq!(m.to[0].name, "José Pérez");
        assert_eq!(headers(&raw).unwrap().subject, "Café ☕");
    }

    #[test]
    fn draft_with_bcc_and_reply() {
        let raw = crlf(
            "From: me@example.com\n\
             To: \"Doe, Jane\" <jane@example.com>, Bo <bo@example.com>\n\
             Bcc: secret@example.com\n\
             Subject: Re: Plan\n\
             In-Reply-To: <orig.1@example.com>\n\
             \n\
             Sounds good.\n\
             \n\
             On Tue, Nov 18 Jane wrote:\n\
             > the plan\n",
        );
        let d = draft(&raw, "d1", "uid-3", "t9").unwrap();
        assert_eq!(d.id, "d1");
        assert_eq!(d.to, "jane@example.com, Bo <bo@example.com>");
        assert_eq!((d.cc.as_str(), d.bcc.as_str()), ("", "secret@example.com"));
        assert_eq!(d.subject, "Re: Plan");
        assert_eq!(d.body, "Sounds good.");
        assert!(d.quoted.unwrap().contains("> the plan"));
        let reply = d.reply.unwrap();
        assert_eq!(
            (reply.thread_id.as_str(), reply.message_id.as_str()),
            ("t9", "<orig.1@example.com>")
        );
        assert!(mail::addresses(&d.to).is_ok());

        let bad = crlf("To: a@example.com\nIn-Reply-To: not an id\n\nhi\n");
        assert!(draft(&bad, "d2", "k", "t").unwrap().reply.is_none());
    }

    #[test]
    fn header_block_with_folded_references() {
        let raw = crlf(
            "Message-ID: <m3@example.com>\n\
             In-Reply-To: <m2@example.com>\n\
             References: <m1@example.com>\n\
             \t<m2@example.com>\n \
             <bad id@x>\n\
             From: Ana <ana@example.com>\n\
             To: luan@example.com\n\
             Subject: Long\n\
             \tsubject\n\
             Date: Tue, 14 Nov 2023 23:13:20 +0100\n\
             \n",
        );
        let h = headers(&raw).unwrap();
        assert_eq!(h.message_id, "<m3@example.com>");
        assert_eq!(h.in_reply_to.as_deref(), Some("<m2@example.com>"));
        assert!(h.references.starts_with(&[
            "<m1@example.com>".to_string(),
            "<m2@example.com>".to_string()
        ]));
        assert!(h.references.iter().all(|r| is_message_id(r)));
        assert_eq!((h.from.name.as_str(), h.to.len()), ("Ana", 1));
        assert_eq!(h.subject, "Long subject");
        assert_eq!(h.timestamp_ms, 1_700_000_000_000);
    }

    #[test]
    fn snippet_from_a_cut_off_message() {
        let raw = crlf(
            "From: a@example.com\n\
             Content-Type: multipart/alternative; boundary=\"zz\"\n\
             \n\
             --zz\n\
             Content-Type: text/plain; charset=utf-8\n\
             Content-Transfer-Encoding: quoted-printable\n\
             \n\
             Hello =E2=80=94 this is the start of a long\n\
             message that goes on and o",
        );
        assert_eq!(
            snippet(&raw),
            "Hello — this is the start of a long message that goes on and o"
        );
        // Cut inside a base64 HTML part, nested in a mixed message.
        let html = crlf(
            "Content-Type: multipart/mixed; boundary=\"a\"\n\
             \n\
             --a\n\
             Content-Type: multipart/alternative; boundary=\"b\"\n\
             \n\
             --b\n\
             Content-Type: text/html; charset=utf-8\n\
             Content-Transfer-Encoding: base64\n\
             \n\
             PHA+PGI+Qm9sZDwvYj4gdmVyc2lvbjwvcD4=\n\
             PHA+PGI+QW5vdGhlcjwvYj4",
        );
        assert_eq!(snippet(&html), "Bold version Another");
        // Cut inside the headers: nothing to show.
        assert_eq!(snippet(b"From: a@example.com\r\nSubj"), "");
        let long = format!("Subject: x\r\n\r\n{}", "word ".repeat(500));
        assert_eq!(snippet(long.as_bytes()).chars().count(), SNIPPET_CHARS - 1);
    }

    #[test]
    fn malformed_input_never_panics() {
        let garbage: Vec<u8> = (0..4096u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
            .collect();
        let samples: Vec<&[u8]> = vec![
            b"",
            b"\r\n\r\n",
            b"no headers here at all",
            &garbage,
            b"Content-Type: multipart/mixed; boundary=\"\"\r\n\r\n--\r\n--",
            b"Content-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\nContent-Type: message/rfc822\r\n\r\n--x",
            b"From: =?UTF-8?B?////?= <\x00@\xff>\r\nDate: 99 Foo 99999 99:99:99\r\n\r\n\xff\xfe",
        ];
        for raw in samples {
            if let Some(m) = message(raw, "k") {
                assert!(m.snippet.chars().count() <= SNIPPET_CHARS);
                assert!(m.timestamp_ms >= 0);
            }
            let _ = draft(raw, "d", "k", "t");
            let _ = headers(raw);
            for id in ["0", "1", "2", "3"] {
                let _ = attachment(raw, id);
            }
            assert!(snippet(raw).chars().count() <= SNIPPET_CHARS);
        }
        assert!(message(b"", "k").is_none() && headers(b"").is_none());
        assert_eq!(snippet(b""), "");
        assert!(attachment(b"", "0").is_none());
    }
}
