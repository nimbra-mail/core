//! What a message being written is made of: the HTML part sent (what was written, the
//! signature apart, then the quoted earlier message), finding the signature again in a
//! draft, and what a reply or a forward starts with. The apps own the editor; both build
//! what is sent here.

use crate::listing::Header;
use crate::mail::{Attachment, ReplyTo};
use crate::rich::{Block, escape};

/// The class of the block a signature is sent in, which is how a draft's signature is told
/// from what was written when it is opened again.
const SIGNATURE_CLASS: &str = "nimbra-signature";

/// The HTML part of an outgoing message: what was written, the signature (already
/// `signature::clean`), then the quoted earlier message (kept as text) in Gmail's usual
/// quote block.
pub fn message_html(written: &str, signature: Option<&str>, quoted: Option<&str>) -> String {
    let signature = signature
        .filter(|s| !s.trim().is_empty())
        .map(|s| format!("<br><div class=\"{SIGNATURE_CLASS}\">{s}</div>"))
        .unwrap_or_default();
    let mut html = format!("<div dir=\"ltr\">{written}{signature}</div>");
    if let Some(quoted) = quoted.filter(|q| !q.trim().is_empty()) {
        let mut lines = quoted.lines().peekable();
        html.push_str("<br><div class=\"nimbra-quote\">");
        // A reply: "On …, … wrote:" then the quoted lines (without their "> ").
        if let Some(intro) = lines.next_if(|l| l.trim_end().ends_with("wrote:")) {
            html.push_str(&format!("<div>{}</div>", escape(intro)));
            html.push_str(
                "<blockquote style=\"margin:0 0 0 .8ex;border-left:1px solid #ccc;padding-left:1ex\">",
            );
            for line in lines {
                let line = line
                    .strip_prefix("> ")
                    .or(line.strip_prefix('>'))
                    .unwrap_or(line);
                html.push_str(&escape(line));
                html.push_str("<br>");
            }
            html.push_str("</blockquote>");
        } else {
            for line in lines {
                html.push_str(&escape(line));
                html.push_str("<br>");
            }
        }
        html.push_str("</div>");
    }
    html
}

/// The part of a saved draft's HTML the user wrote: everything before the quote block.
pub fn own_html(html: &str) -> Option<String> {
    let marker = [
        "class=\"gmail_quote",
        "class=\"nimbra-quote",
        "class=gmail_quote",
    ]
    .iter()
    .filter_map(|m| html.find(m))
    .min()?;
    let start = html[..marker].rfind('<')?;
    Some(html[..start].to_string())
}

/// A draft's own part split into what was written and the signature it was saved with
/// (`message_html`). A draft from before signatures were kept apart has its signature in
/// what was written, and stays as it is.
pub fn split_signature(own: &str) -> (String, Option<String>) {
    let mut fragment = scraper::Html::parse_fragment(own);
    let found = fragment
        .root_element()
        .descendants()
        .filter_map(scraper::ElementRef::wrap)
        .find(|e| e.value().classes().any(|c| c == SIGNATURE_CLASS))
        .map(|e| {
            // The line break `message_html` puts before it goes with it.
            let before = e
                .prev_sibling()
                .and_then(scraper::ElementRef::wrap)
                .filter(|b| b.value().name() == "br")
                .map(|b| b.id());
            (e.id(), e.inner_html(), before)
        });
    let Some((id, signature, before)) = found else {
        return (own.to_string(), None);
    };
    for id in std::iter::once(id).chain(before) {
        if let Some(mut node) = fragment.tree.get_mut(id) {
            node.detach();
        }
    }
    (fragment.root_element().inner_html(), Some(signature))
}

/// What a new message answers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer {
    Reply,
    ReplyAll,
    Forward,
}

/// The message a reply or forward is about.
pub struct Source<'a> {
    pub subject: &'a str,
    pub sender: &'a str,
    pub header: &'a Header,
    pub body: &'a [Block],
    pub reply_to: Option<ReplyTo>,
    /// For sample data, which has no real headers.
    pub fallback_to: Option<String>,
    pub fallback_all: &'a [String],
}

/// What a reply or forward starts with.
#[derive(Clone, Default)]
pub struct Answered {
    pub subject: String,
    /// The addresses it goes to (none for a forward).
    pub to: Vec<String>,
    /// The earlier message, as text, folded under what is written and added when sent.
    pub quoted: Option<String>,
    /// The files that go along (a forward's).
    pub kept: Vec<Attachment>,
    pub reply: Option<ReplyTo>,
}

/// What a reply, reply-all or forward of `source` starts with. `me` is the address it is
/// sent from (never answered to itself); `when` is the earlier message's date as the app
/// writes it (empty when unknown); `quote_replies`: a reply quotes the message it answers.
pub fn answer(
    kind: Answer,
    source: &Source,
    me: &str,
    when: &str,
    quote_replies: bool,
) -> Answered {
    let prefix = if kind == Answer::Forward {
        "Fwd: "
    } else {
        "Re: "
    };
    let subject = if source
        .subject
        .to_lowercase()
        .starts_with(&prefix.trim().to_lowercase())
    {
        source.subject.to_string()
    } else {
        format!("{prefix}{}", source.subject)
    };
    let header = source.header;
    let from = if header.from.address.is_empty() {
        source.sender.to_string()
    } else if header.from.name.is_empty() {
        header.from.address.clone()
    } else {
        format!("{} <{}>", header.from.name, header.from.address)
    };
    let body: Vec<String> = source
        .body
        .iter()
        .flat_map(|block| {
            block
                .text
                .lines()
                .map(str::to_string)
                .chain([String::new()])
        })
        .take(2000)
        .collect();
    if kind == Answer::Forward {
        let to = header
            .to
            .iter()
            .map(|p| p.address.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        let mut quoted = vec![
            "---------- Forwarded message ----------".to_string(),
            format!("From: {from}"),
        ];
        if !when.is_empty() {
            quoted.push(format!("Date: {when}"));
        }
        quoted.push(format!("Subject: {}", source.subject));
        if !to.is_empty() {
            quoted.push(format!("To: {to}"));
        }
        quoted.push(String::new());
        quoted.extend(body);
        return Answered {
            subject,
            to: Vec::new(),
            quoted: Some(quoted.join("\n").trim_end().to_string()),
            kept: header.attachments.clone(),
            reply: None,
        };
    }
    let address = if header.from.address.is_empty() {
        source.fallback_to.clone()
    } else {
        Some(header.reply_address().to_string())
    };
    let mut to = Vec::new();
    if let Some(address) = address {
        to.push(address);
        if kind == Answer::ReplyAll {
            let others = if header.from.address.is_empty() {
                source.fallback_all.to_vec()
            } else {
                header.everyone()
            };
            for other in others {
                let mine = other.eq_ignore_ascii_case(me);
                if !mine && !to.iter().any(|known| known.eq_ignore_ascii_case(&other)) {
                    to.push(other);
                }
            }
        }
    }
    let intro = if when.is_empty() {
        format!("{from} wrote:")
    } else {
        format!("On {when}, {from} wrote:")
    };
    let quoted: Vec<String> = std::iter::once(intro)
        .chain(body.iter().map(|line| format!("> {line}")))
        .collect();
    Answered {
        subject,
        to,
        quoted: quote_replies.then(|| quoted.join("\n").trim_end().to_string()),
        kept: Vec::new(),
        reply: source.reply_to.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mail::Person;

    #[test]
    fn outgoing_html_escapes_and_quotes() {
        assert_eq!(
            crate::rich::text_to_html("a<b>\n\nc"),
            "<div>a&lt;b&gt;</div><div><br></div><div>c</div>"
        );
        let html = message_html(
            "<div>Hi</div>",
            None,
            Some("On Tue, Ana <a@x.co> wrote:\n> old <tag>\n> more"),
        );
        assert!(html.starts_with("<div dir=\"ltr\"><div>Hi</div></div>"));
        assert!(html.contains("On Tue, Ana &lt;a@x.co&gt; wrote:"));
        assert!(html.contains("<blockquote") && html.contains("old &lt;tag&gt;<br>more<br>"));
        assert_eq!(message_html("x", None, None), "<div dir=\"ltr\">x</div>");
        assert_eq!(
            message_html("x", Some("  "), None),
            "<div dir=\"ltr\">x</div>"
        );
    }

    #[test]
    fn a_drafts_own_part_stops_at_the_quote() {
        let html = "<div dir=\"ltr\"><b>Hi</b></div><br><div class=\"gmail_quote\">old</div>";
        assert_eq!(
            own_html(html).as_deref(),
            Some("<div dir=\"ltr\"><b>Hi</b></div><br>")
        );
        assert_eq!(own_html("<div>no quote</div>"), None);
    }

    #[test]
    fn a_signature_is_sent_apart_and_found_again_in_a_draft() {
        let html = message_html(
            "<div>Hi</div><div><br></div>",
            Some("<div><b>Luan</b></div>"),
            Some("On Tue, Ana wrote:\n> old"),
        );
        assert!(html.starts_with(
            "<div dir=\"ltr\"><div>Hi</div><div><br></div><br><div class=\"nimbra-signature\"><div><b>Luan</b></div></div></div>"
        ));
        let own = own_html(&html).unwrap();
        let (written, signature) = split_signature(&own);
        assert_eq!(signature.as_deref(), Some("<div><b>Luan</b></div>"));
        assert_eq!(
            written,
            "<div dir=\"ltr\"><div>Hi</div><div><br></div></div><br>"
        );
        // Older drafts keep their signature in what was written.
        let old = "<div dir=\"ltr\"><div>Hi</div><div class=\"sig\">Luan</div></div>";
        assert_eq!(split_signature(old), (old.to_string(), None));
    }

    fn header() -> Header {
        let person = |name: &str, address: &str| Person {
            name: name.into(),
            address: address.into(),
        };
        Header {
            from: person("Ana", "ana@example.com"),
            to: vec![
                person("", "me@example.com"),
                person("Ben", "ben@example.com"),
            ],
            cc: vec![person("", "ANA@example.com"), person("", "cy@example.com")],
            ..Header::default()
        }
    }

    #[test]
    fn a_reply_all_goes_to_everyone_but_me_once() {
        let header = header();
        let body = crate::rich::from_text(vec!["Lunch?".into()]);
        let source = Source {
            subject: "Lunch",
            sender: "Ana",
            header: &header,
            body: &body,
            reply_to: None,
            fallback_to: None,
            fallback_all: &[],
        };
        let all = answer(Answer::ReplyAll, &source, "Me@example.com", "Tue", true);
        assert_eq!(all.subject, "Re: Lunch");
        assert_eq!(
            all.to,
            ["ana@example.com", "ben@example.com", "cy@example.com"]
        );
        assert!(
            all.quoted
                .unwrap()
                .starts_with("On Tue, Ana <ana@example.com> wrote:\n> Lunch?")
        );
        let reply = answer(Answer::Reply, &source, "me@example.com", "", false);
        assert_eq!(reply.to, ["ana@example.com"]);
        assert!(reply.quoted.is_none(), "replies are quoted only when asked");
        let again = Source {
            subject: "RE: Lunch",
            ..source
        };
        assert_eq!(
            answer(Answer::Reply, &again, "", "", true).subject,
            "RE: Lunch"
        );
    }

    #[test]
    fn a_forward_carries_the_message_and_its_files() {
        let mut header = header();
        header.attachments.push(Attachment {
            message_id: "m".into(),
            attachment_id: "a".into(),
            name: "plan.pdf".into(),
            mime: "application/pdf".into(),
            size: 3,
        });
        let body = crate::rich::from_text(vec!["See attached.".into()]);
        let source = Source {
            subject: "Plan",
            sender: "Ana",
            header: &header,
            body: &body,
            reply_to: None,
            fallback_to: None,
            fallback_all: &[],
        };
        let forward = answer(Answer::Forward, &source, "me@example.com", "Tue", true);
        assert_eq!(forward.subject, "Fwd: Plan");
        assert!(forward.to.is_empty());
        let quoted = forward.quoted.unwrap();
        assert!(quoted.starts_with("---------- Forwarded message ----------\nFrom: Ana <ana@example.com>\nDate: Tue\nSubject: Plan"));
        assert_eq!(forward.kept.len(), 1);
    }
}
