//! Turns an email body into a flat list of styled blocks the UI can draw natively.
//!
//! This is deliberately not a browser: scripts, styles, forms and embedded frames are
//! dropped, hidden preheader text is skipped, layout tables are flattened into reading
//! order, and remote images are only described here, never fetched. Fetching happens
//! separately, on request, through [`fetch_image`].

use std::io::Read as _;
use std::ops::Range;
use std::time::Duration;

use anyhow::{Result, bail};
use scraper::{ElementRef, Html, Node};

const MAX_BLOCKS: usize = 600;
const MAX_CHARS: usize = 60_000;
const MAX_IMAGE_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Block {
    pub kind: Kind,
    /// Nesting depth inside quoted text.
    pub quote: u8,
    pub text: String,
    /// Styled runs, in order and never overlapping.
    pub spans: Vec<Span>,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum Kind {
    Paragraph,
    Heading(u8),
    Item { marker: String, depth: u8 },
    Code,
    Rule,
    Image { src: String, alt: String },
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Span {
    pub range: Range<usize>,
    pub bold: bool,
    pub italic: bool,
    pub code: bool,
    /// Destination, already limited to http, https and mailto.
    pub link: Option<String>,
}

impl Block {
    fn plain(kind: Kind, text: String) -> Self {
        Block {
            kind,
            quote: 0,
            text,
            spans: Vec::new(),
        }
    }
}

/// Remote images referenced by these blocks, in order, without duplicates.
pub fn image_sources(blocks: &[Block]) -> Vec<String> {
    let mut sources = Vec::new();
    for block in blocks {
        if let Kind::Image { src, .. } = &block.kind
            && !sources.contains(src)
        {
            sources.push(src.clone());
        }
    }
    sources
}

// ------------------------------------------------------------------ plain text

/// Plain-text mail: one block per paragraph, with bare URLs made clickable.
pub fn from_text(paragraphs: Vec<String>) -> Vec<Block> {
    paragraphs
        .into_iter()
        .take(MAX_BLOCKS)
        .map(|text| {
            let spans = find_urls(&text)
                .into_iter()
                .map(|range| Span {
                    link: Some(text[range.clone()].to_string()),
                    range,
                    bold: false,
                    italic: false,
                    code: false,
                })
                .collect();
            Block {
                spans,
                ..Block::plain(Kind::Paragraph, text)
            }
        })
        .collect()
}

fn find_urls(text: &str) -> Vec<Range<usize>> {
    let mut found = Vec::new();
    let mut from = 0;
    while let Some(offset) = text[from..].find("http") {
        let start = from + offset;
        let rest = &text[start..];
        if !(rest.starts_with("https://") || rest.starts_with("http://")) {
            from = start + 4;
            continue;
        }
        let len = rest
            .find(|c: char| c.is_whitespace() || "<>\"".contains(c))
            .unwrap_or(rest.len());
        // Sentence punctuation right after a URL is not part of it.
        let url = rest[..len].trim_end_matches(['.', ',', ')', ']', ';', ':', '!', '?', '\'']);
        if url.len() > "https://".len() {
            found.push(start..start + url.len());
        }
        from = start + len.max(4);
    }
    found
}

// ------------------------------------------------------------------ html

pub fn from_html(html: &str) -> Vec<Block> {
    let document = Html::parse_document(html);
    let mut builder = Builder::default();
    builder.walk(document.root_element());
    builder.flush();
    builder.blocks
}

/// What is left to do, the next step last. A stack, not recursion: a message can nest
/// elements deeper than a thread's stack can follow.
enum Step<'a> {
    Text(&'a str),
    Element(ElementRef<'a>),
    Leave(Leave),
}

/// What closing an element undoes.
enum Leave {
    Link(Option<String>),
    Styled(fn(&mut Builder) -> &mut u32),
    Heading,
    Quote(u8),
    Pre,
    List,
    Item,
    Block,
}

#[derive(Default)]
struct Builder {
    blocks: Vec<Block>,
    text: String,
    spans: Vec<Span>,
    chars: usize,
    bold: u32,
    italic: u32,
    code: u32,
    link: Option<String>,
    quote: u8,
    heading: Option<u8>,
    preformatted: bool,
    /// One entry per open list: `Some(n)` is the next number of an ordered list.
    lists: Vec<Option<u32>>,
    /// Marker waiting for the first text of the current list item.
    marker: Option<String>,
}

const SKIPPED: &[&str] = &[
    "script", "style", "head", "title", "meta", "link", "svg", "noscript", "template", "iframe",
    "object", "embed", "form", "input", "button", "select", "textarea", "video", "audio",
];

const BLOCKS: &[&str] = &[
    "p",
    "div",
    "section",
    "article",
    "header",
    "footer",
    "main",
    "aside",
    "table",
    "tbody",
    "thead",
    "tfoot",
    "tr",
    "td",
    "th",
    "ul",
    "ol",
    "li",
    "blockquote",
    "pre",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "center",
    "address",
    "figure",
    "figcaption",
    "dl",
    "dt",
    "dd",
];

impl Builder {
    fn full(&self) -> bool {
        self.blocks.len() >= MAX_BLOCKS || self.chars >= MAX_CHARS
    }

    fn walk(&mut self, root: ElementRef) {
        let mut steps = Vec::new();
        push_children(&mut steps, root);
        while let Some(step) = steps.pop() {
            match step {
                Step::Leave(leave) => self.leave(leave),
                _ if self.full() => {}
                Step::Text(text) => self.push_text(text),
                Step::Element(element) => self.element(element, &mut steps),
            }
        }
    }

    fn element<'a>(&mut self, element: ElementRef<'a>, steps: &mut Vec<Step<'a>>) {
        let value = element.value();
        let name = value.name();
        if SKIPPED.contains(&name) || is_hidden(value.attr("style")) {
            return;
        }
        // Gmail wraps the quoted earlier messages in these; the thread view shows them
        // as their own messages instead.
        if value
            .classes()
            .any(|c| c == "gmail_quote" || c == "gmail_extra")
        {
            return;
        }
        let leave = match name {
            "br" => {
                if !self.text.is_empty() {
                    self.text.push('\n');
                }
                return;
            }
            "hr" => {
                self.flush();
                self.blocks.push(Block {
                    quote: self.quote,
                    ..Block::plain(Kind::Rule, String::new())
                });
                return;
            }
            "img" => {
                self.image(element);
                return;
            }
            "b" | "strong" => self.styled(|b| &mut b.bold),
            "i" | "em" => self.styled(|b| &mut b.italic),
            "code" | "tt" | "kbd" => self.styled(|b| &mut b.code),
            "a" => {
                let previous = self.link.take();
                self.link = value.attr("href").and_then(safe_link).or(previous.clone());
                Leave::Link(previous)
            }
            _ if BLOCKS.contains(&name) => self.block(name),
            _ => {
                push_children(steps, element);
                return;
            }
        };
        steps.push(Step::Leave(leave));
        push_children(steps, element);
    }

    fn styled(&mut self, counter: fn(&mut Self) -> &mut u32) -> Leave {
        *counter(self) += 1;
        Leave::Styled(counter)
    }

    fn block(&mut self, name: &str) -> Leave {
        self.flush();
        match name {
            "h1" | "h2" | "h3" | "h4" | "h5" | "h6" => {
                self.heading = Some(name.as_bytes()[1] - b'0');
                Leave::Heading
            }
            "blockquote" => {
                let outer = self.quote;
                self.quote = outer.saturating_add(1);
                Leave::Quote(outer)
            }
            "pre" => {
                self.preformatted = true;
                Leave::Pre
            }
            "ul" | "ol" => {
                self.lists.push((name == "ol").then_some(1));
                Leave::List
            }
            "li" => {
                self.marker = Some(match self.lists.last_mut() {
                    Some(Some(number)) => {
                        *number += 1;
                        format!("{}.", *number - 1)
                    }
                    _ => "•".to_string(),
                });
                Leave::Item
            }
            _ => Leave::Block,
        }
    }

    fn leave(&mut self, leave: Leave) {
        match leave {
            Leave::Link(outer) => self.link = outer,
            Leave::Styled(counter) => *counter(self) -= 1,
            Leave::Heading => {
                self.flush();
                self.heading = None;
            }
            Leave::Quote(outer) => {
                self.flush();
                self.quote = outer;
            }
            Leave::Pre => {
                self.flush();
                self.preformatted = false;
            }
            Leave::List => {
                self.flush();
                self.lists.pop();
            }
            Leave::Item => {
                self.flush();
                self.marker = None;
            }
            Leave::Block => self.flush(),
        }
    }

    fn image(&mut self, element: ElementRef) {
        let value = element.value();
        let Some(src) = value.attr("src").filter(|src| is_remote_image(src)) else {
            return;
        };
        // 1x1 and similar are tracking pixels, not content.
        let tiny = |attr: &str| {
            value
                .attr(attr)
                .and_then(|v| v.trim_end_matches("px").parse::<u32>().ok())
                .is_some_and(|v| v <= 3)
        };
        if tiny("width") || tiny("height") {
            return;
        }
        self.flush();
        self.blocks.push(Block {
            quote: self.quote,
            ..Block::plain(
                Kind::Image {
                    src: src.to_string(),
                    alt: clean(value.attr("alt").unwrap_or("")),
                },
                String::new(),
            )
        });
    }

    fn push_text(&mut self, raw: &str) {
        let start = self.text.len();
        if self.preformatted {
            self.text.push_str(raw);
        } else {
            for c in raw.chars() {
                if matches!(
                    c,
                    '\u{200b}' | '\u{200c}' | '\u{200d}' | '\u{feff}' | '\u{34f}' | '\u{ad}'
                ) {
                    continue;
                }
                if c.is_whitespace() || c == '\u{a0}' {
                    if !self.text.is_empty() && !self.text.ends_with([' ', '\n']) {
                        self.text.push(' ');
                    }
                } else {
                    self.text.push(c);
                }
            }
        }
        let end = self.text.len();
        self.chars += end - start;
        if end > start && (self.bold > 0 || self.italic > 0 || self.code > 0 || self.link.is_some())
        {
            self.spans.push(Span {
                range: start..end,
                bold: self.bold > 0,
                italic: self.italic > 0,
                code: self.code > 0,
                link: self.link.clone(),
            });
        }
    }

    /// Ends the current block, if it has any text.
    fn flush(&mut self) {
        let mut text = std::mem::take(&mut self.text);
        let mut spans = std::mem::take(&mut self.spans);
        text.truncate(text.trim_end().len());
        if text.is_empty() {
            return;
        }
        for span in &mut spans {
            span.range.end = span.range.end.min(text.len());
        }
        spans.retain(|span| span.range.start < span.range.end);
        let kind = if self.preformatted {
            Kind::Code
        } else if let Some(level) = self.heading {
            Kind::Heading(level)
        } else if let Some(marker) = self.marker.take() {
            Kind::Item {
                marker,
                depth: u8::try_from(self.lists.len().saturating_sub(1)).unwrap_or(u8::MAX),
            }
        } else {
            Kind::Paragraph
        };
        self.blocks.push(Block {
            kind,
            quote: self.quote,
            text,
            spans,
        });
    }
}

/// An element's text and elements, queued so the first comes off the stack first.
fn push_children<'a>(steps: &mut Vec<Step<'a>>, element: ElementRef<'a>) {
    let first = steps.len();
    for child in element.children() {
        match child.value() {
            Node::Text(text) => steps.push(Step::Text(text)),
            Node::Element(_) => steps.extend(ElementRef::wrap(child).map(Step::Element)),
            _ => {}
        }
    }
    steps[first..].reverse();
}

fn is_hidden(style: Option<&str>) -> bool {
    let Some(style) = style else {
        return false;
    };
    let style: String = style.chars().filter(|c| !c.is_whitespace()).collect();
    let style = style.to_ascii_lowercase();
    style.contains("display:none") || style.contains("visibility:hidden")
}

/// Only schemes that are safe to hand to the system: no `javascript:`, `file:`, `data:`.
fn safe_link(href: &str) -> Option<String> {
    let href = href.trim();
    let lower = href.to_ascii_lowercase();
    (lower.starts_with("https://") || lower.starts_with("http://") || lower.starts_with("mailto:"))
        .then(|| href.to_string())
}

fn is_remote_image(src: &str) -> bool {
    src.trim().to_ascii_lowercase().starts_with("https://")
}

fn clean(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

// ------------------------------------------------------------------ images

#[derive(Clone, Copy)]
pub enum ImageKind {
    Png,
    Jpeg,
    Gif,
    Webp,
}

/// Downloads one remote image, on the user's request.
///
/// Limited to https on a public host name, at every redirect, and to hosts whose
/// addresses are all public, so a message cannot make the app probe the local network.
/// With a size cap and a timeout. The format is taken from the bytes, not from what the
/// server claims.
pub fn fetch_image(url: &str) -> Result<(ImageKind, Vec<u8>)> {
    const MAX_REDIRECTS: usize = 3;
    let mut url = image_url(url)?;
    // The checked addresses are the ones connected to: no second lookup can swap them.
    let agent = ureq::AgentBuilder::new()
        .redirects(0)
        .https_only(true)
        .resolver(public_addresses)
        .timeout(Duration::from_secs(10))
        .build();
    let mut redirects = 0;
    let response = loop {
        let response = agent
            .get(url.as_str())
            .call()
            .map_err(|_| anyhow::anyhow!("image could not be loaded"))?;
        if !(300..400).contains(&response.status()) {
            break response;
        }
        redirects += 1;
        if redirects > MAX_REDIRECTS {
            bail!("image could not be loaded");
        }
        let Some(location) = response.header("location") else {
            bail!("image could not be loaded");
        };
        url = image_url(url.join(location)?.as_str())?;
    };
    let mut bytes = Vec::new();
    response
        .into_reader()
        .take(MAX_IMAGE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_IMAGE_BYTES {
        bail!("image is too large");
    }
    let kind = sniff(&bytes).ok_or_else(|| anyhow::anyhow!("not a supported image"))?;
    Ok((kind, bytes))
}

/// An https URL on a public-looking host name: no IP literals, no names for this Mac or
/// its local network.
fn image_url(url: &str) -> Result<url::Url> {
    let parsed = url::Url::parse(url)?;
    let host = match (parsed.scheme(), parsed.host()) {
        ("https", Some(url::Host::Domain(host))) => host.to_ascii_lowercase(),
        _ => bail!("only https images on a named host are loaded"),
    };
    let host = host.trim_end_matches('.');
    if host == "localhost"
        || [".localhost", ".local", ".internal", ".home.arpa", ".lan"]
            .iter()
            .any(|suffix| host.ends_with(suffix))
        || !host.contains('.')
    {
        bail!("local addresses are not loaded");
    }
    Ok(parsed)
}

/// The addresses of `netloc` ("host:port"), refused unless every one is public.
fn public_addresses(netloc: &str) -> std::io::Result<Vec<std::net::SocketAddr>> {
    use std::net::ToSocketAddrs as _;
    let addresses: Vec<_> = netloc.to_socket_addrs()?.collect();
    if addresses.is_empty() || addresses.iter().any(|a| !is_public(a.ip())) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "local addresses are not loaded",
        ));
    }
    Ok(addresses)
}

/// Reachable on the internet: not this machine, a private or shared network, link-local,
/// multicast or reserved. IPv6 forms that carry an IPv4 address are judged by it.
fn is_public(ip: std::net::IpAddr) -> bool {
    use std::net::{IpAddr, Ipv4Addr};
    let v4 = |ip: Ipv4Addr| {
        let [a, b, c, _] = ip.octets();
        !(a == 0
            || a == 10
            || a == 127
            || (a == 100 && (64..128).contains(&b))
            || (a == 169 && b == 254)
            || (a == 172 && (16..32).contains(&b))
            || (a == 192 && b == 168)
            || (a == 192 && b == 0 && (c == 0 || c == 2))
            || (a == 198 && (b == 18 || b == 19))
            || (a == 198 && b == 51 && c == 100)
            || (a == 203 && b == 0 && c == 113)
            || a >= 224)
    };
    match ip {
        IpAddr::V4(ip) => v4(ip),
        IpAddr::V6(ip) => {
            let s = ip.segments();
            let embedded = |high: u16, low: u16| {
                Ipv4Addr::new((high >> 8) as u8, high as u8, (low >> 8) as u8, low as u8)
            };
            if let Some(mapped) = ip.to_ipv4_mapped() {
                return v4(mapped);
            }
            match s {
                // Unspecified, loopback and the old IPv4-compatible form.
                [0, 0, 0, 0, 0, 0, _, _] => false,
                // IPv4-translated.
                [0, 0, 0, 0, 0xffff, 0, _, _] => false,
                // NAT64.
                [0x64, 0xff9b, 0, 0, 0, 0, high, low] => v4(embedded(high, low)),
                // Local NAT64 and Teredo: what they lead to cannot be told from here.
                [0x64, 0xff9b, 1, ..] | [0x2001, 0, ..] => false,
                // 6to4.
                [0x2002, high, low, ..] => v4(embedded(high, low)),
                // Documentation.
                [0x2001, 0xdb8, ..] => false,
                // Unique local, link-local and site-local, multicast.
                [first, ..] => {
                    !((first & 0xfe00) == 0xfc00
                        || (first & 0xffc0) == 0xfe80
                        || (first & 0xffc0) == 0xfec0
                        || (first & 0xff00) == 0xff00)
                }
            }
        }
    }
}

pub fn sniff(bytes: &[u8]) -> Option<ImageKind> {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some(ImageKind::Png)
    } else if bytes.starts_with(&[0xff, 0xd8, 0xff]) {
        Some(ImageKind::Jpeg)
    } else if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        Some(ImageKind::Gif)
    } else if bytes.len() > 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        Some(ImageKind::Webp)
    } else {
        None
    }
}

/// Text for the editor: escaped, one line per `<div>` (as the page itself writes them).
pub fn text_to_html(text: &str) -> String {
    text.lines()
        .map(|line| {
            if line.is_empty() {
                "<div><br></div>".to_string()
            } else {
                format!("<div>{}</div>", escape(line))
            }
        })
        .collect()
}

pub fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn texts(blocks: &[Block]) -> Vec<&str> {
        blocks.iter().map(|b| b.text.as_str()).collect()
    }

    #[test]
    fn paragraphs_and_inline_styles() {
        let blocks = from_html("<p>Hello <b>bold</b> and <i>it</i>\n   spaced</p><p>Second</p>");
        assert_eq!(texts(&blocks), ["Hello bold and it spaced", "Second"]);
        let spans = &blocks[0].spans;
        assert_eq!(&blocks[0].text[spans[0].range.clone()], "bold");
        assert!(spans[0].bold && !spans[0].italic);
        assert_eq!(&blocks[0].text[spans[1].range.clone()], "it");
        assert!(spans[1].italic);
    }

    #[test]
    fn headings_lists_quotes_rules() {
        let blocks = from_html(
            "<h2>Title</h2><ul><li>One</li><li>Two</li></ul><ol><li>A</li><li>B</li></ol>\
             <blockquote><p>Quoted</p></blockquote><hr><pre>a\n  b</pre>",
        );
        assert_eq!(blocks[0].kind, Kind::Heading(2));
        assert_eq!(
            blocks[1].kind,
            Kind::Item {
                marker: "•".into(),
                depth: 0
            }
        );
        assert_eq!(
            blocks[3].kind,
            Kind::Item {
                marker: "1.".into(),
                depth: 0
            }
        );
        assert_eq!(
            blocks[4].kind,
            Kind::Item {
                marker: "2.".into(),
                depth: 0
            }
        );
        assert_eq!((blocks[5].quote, blocks[5].text.as_str()), (1, "Quoted"));
        assert_eq!(blocks[6].kind, Kind::Rule);
        assert_eq!(
            (&blocks[7].kind, blocks[7].text.as_str()),
            (&Kind::Code, "a\n  b")
        );
    }

    #[test]
    fn links_keep_only_safe_schemes() {
        let blocks = from_html(
            "<p><a href='https://example.com/x'>ok</a> <a href='javascript:alert(1)'>bad</a> \
             <a href='file:///etc/passwd'>worse</a> <a href='mailto:a@b.co'>mail</a></p>",
        );
        let links: Vec<_> = blocks[0]
            .spans
            .iter()
            .filter_map(|s| s.link.as_deref())
            .collect();
        assert_eq!(links, ["https://example.com/x", "mailto:a@b.co"]);
        assert_eq!(blocks[0].text, "ok bad worse mail");
    }

    #[test]
    fn scripts_styles_and_hidden_text_are_dropped() {
        let blocks = from_html(
            "<html><head><style>p{color:red}</style></head><body>\
             <div style='display: none'>preheader</div><script>alert(1)</script>\
             <p>Visible</p><form><input value='x'><button>Go</button></form>\
             <iframe src='https://x.test'></iframe></body></html>",
        );
        assert_eq!(texts(&blocks), ["Visible"]);
    }

    #[test]
    fn gmail_quoted_history_is_dropped() {
        let blocks = from_html("<div>Reply</div><div class='gmail_quote'><p>Old message</p></div>");
        assert_eq!(texts(&blocks), ["Reply"]);
    }

    #[test]
    fn layout_tables_flatten_in_reading_order() {
        let blocks =
            from_html("<table><tr><td>Left</td><td>Right</td></tr><tr><td>Below</td></tr></table>");
        assert_eq!(texts(&blocks), ["Left", "Right", "Below"]);
    }

    #[test]
    fn images_are_listed_but_trackers_and_unsafe_sources_are_not() {
        let blocks = from_html(
            "<img src='https://cdn.example.com/hero.png' alt=' Hero  image '>\
             <img src='https://t.example.com/pixel.gif' width='1' height='1'>\
             <img src='http://plain.example.com/a.png'><img src='data:image/png;base64,AAAA'>\
             <img src='cid:part1'>",
        );
        assert_eq!(image_sources(&blocks), ["https://cdn.example.com/hero.png"]);
        assert_eq!(
            blocks[0].kind,
            Kind::Image {
                src: "https://cdn.example.com/hero.png".into(),
                alt: "Hero image".into()
            }
        );
    }

    #[test]
    fn plain_text_urls_become_links() {
        let blocks = from_text(vec![
            "See https://example.com/a?b=1, then (http://x.test/y).".into(),
        ]);
        let links: Vec<_> = blocks[0]
            .spans
            .iter()
            .filter_map(|s| s.link.as_deref())
            .collect();
        assert_eq!(links, ["https://example.com/a?b=1", "http://x.test/y"]);
    }

    #[test]
    fn image_fetch_refuses_local_and_non_https_targets() {
        for url in [
            "http://example.com/a.png",
            "https://127.0.0.1/a.png",
            "https://[::1]/a.png",
            "https://localhost/a.png",
            "https://router/a.png",
            "https://printer.local/a.png",
            "https://localhost./a.png",
            "https://2130706433/a.png",
            "file:///etc/passwd",
        ] {
            assert!(fetch_image(url).is_err(), "{url} should be refused");
        }
    }

    #[test]
    fn image_url_refuses_hosts_that_name_this_machine_or_its_network() {
        for url in [
            "https://2130706433/a.png",
            "https://0x7f.1/a.png",
            "https://[::ffff:127.0.0.1]/a.png",
            "https://localhost./a.png",
            "https://LOCALHOST/a.png",
            "https://app.localhost/a.png",
            "https://nas.home.arpa/a.png",
            "https://printer.local./a.png",
            "http://cdn.example.com/a.png",
        ] {
            assert!(image_url(url).is_err(), "{url} should be refused");
        }
    }

    #[test]
    fn image_url_accepts_a_public_https_name() {
        let url = image_url("https://cdn.example.com/a.png");
        assert!(url.is_ok(), "{:?}", url.err());
    }

    #[test]
    fn non_public_addresses_are_recognised() {
        for ip in [
            "127.0.0.1",
            "0.0.0.0",
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "100.127.255.255",
            "224.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "fe80::1",
            "fc00::1",
            "fd12:3456::1",
            "ff02::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "64:ff9b::a00:1",
            "2002:c0a8:101::1",
            "::ffff:0:7f00:1",
            "::ffff:0:5db8:d70e",
            "64:ff9b:1::a00:1",
            "64:ff9b:1:ffff::1",
            "2001:0:4136:e378:8000:63bf:3fff:fdd2",
        ] {
            let ip: std::net::IpAddr = ip.parse().unwrap();
            assert!(!is_public(ip), "{ip} should not count as public");
        }
    }

    #[test]
    fn public_addresses_are_allowed() {
        for ip in [
            "93.184.215.14",
            "100.63.255.255",
            "100.128.0.1",
            "172.32.0.1",
            "2606:4700::1111",
            "::ffff:93.184.215.14",
        ] {
            let ip: std::net::IpAddr = ip.parse().unwrap();
            assert!(is_public(ip), "{ip} should count as public");
        }
    }

    #[test]
    fn resolver_refuses_a_name_for_this_machine() {
        assert!(public_addresses("localhost:443").is_err());
    }

    #[test]
    fn image_format_comes_from_the_bytes() {
        assert!(matches!(
            sniff(b"\x89PNG\r\n\x1a\n...."),
            Some(ImageKind::Png)
        ));
        assert!(matches!(
            sniff(&[0xff, 0xd8, 0xff, 0xe0]),
            Some(ImageKind::Jpeg)
        ));
        assert!(sniff(b"<svg onload=alert(1)>").is_none());
    }

    #[test]
    fn deep_nesting_does_not_overflow_a_small_stack() {
        let html = format!("{}deep", "<span>".repeat(100_000));
        let blocks = std::thread::Builder::new()
            .stack_size(512 * 1024)
            .spawn(move || from_html(&html))
            .unwrap()
            .join()
            .unwrap();
        assert_eq!(texts(&blocks), ["deep"]);
    }

    #[test]
    fn quote_depth_returns_to_zero_after_more_than_255_nested_quotes() {
        let html = format!(
            "{}deep{}<p>after</p>",
            "<blockquote>".repeat(300),
            "</blockquote>".repeat(300)
        );
        let blocks = from_html(&html);
        assert_eq!(
            blocks.last().map(|b| (b.text.as_str(), b.quote)),
            Some(("after", 0))
        );
    }

    #[test]
    fn list_depth_saturates_instead_of_wrapping() {
        let html = format!("{}<li>deep</li>", "<ul>".repeat(300));
        let blocks = from_html(&html);
        assert_eq!(
            blocks[0].kind,
            Kind::Item {
                marker: "•".into(),
                depth: u8::MAX
            }
        );
    }

    #[test]
    fn huge_documents_are_capped() {
        let html = "<p>x</p>".repeat(5_000);
        assert_eq!(from_html(&html).len(), MAX_BLOCKS);
    }
}
