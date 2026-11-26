//! Signatures: the HTML a signature may hold, and the forms it is shown and sent in.
//!
//! A signature is pasted from anywhere (another mail app, a web page, a generator), so it is
//! treated like mail from a stranger. It is parsed by a real HTML parser (html5ever, through
//! `scraper`) and written out again from an allowlist: simple formatting, tables, links to
//! `http`, `https` and `mailto`, and images from `http` or `https`. Scripts, styles, frames,
//! forms, SVG and the like go with everything in them; every `on…` handler, class and id goes;
//! inline styles keep a short list of plain properties whose values cannot load or run
//! anything. What comes out is all this app ever stores, sends or shows.
//!
//! The editor and the Preview load nothing remote, so there each image is a small
//! placeholder (`for_display`); only the message that is sent has the real images.

use scraper::{ElementRef, Html, Node};

/// The longest a signature's name may be, in characters.
pub const NAME_LIMIT: usize = 60;
/// The most HTML a signature may have, in bytes (after cleaning).
pub const HTML_LIMIT: usize = 20 * 1024;
/// Anything longer is not even parsed: it could never fit.
const INPUT_LIMIT: usize = 256 * 1024;
/// Elements nested deeper than this are flattened to their text.
const MAX_DEPTH: usize = 48;

/// Dropped with everything inside them.
const DROPPED: &[&str] = &[
    "script",
    "style",
    "head",
    "title",
    "meta",
    "link",
    "base",
    "template",
    "iframe",
    "frame",
    "frameset",
    "object",
    "embed",
    "applet",
    "param",
    "svg",
    "math",
    "noscript",
    "noembed",
    "noframes",
    "form",
    "input",
    "button",
    "select",
    "option",
    "optgroup",
    "textarea",
    "label",
    "fieldset",
    "legend",
    "datalist",
    "output",
    "video",
    "audio",
    "source",
    "track",
    "canvas",
    "picture",
    "map",
    "area",
    "dialog",
    "portal",
    "xmp",
    "plaintext",
    "listing",
];

/// Kept, with the attributes `attribute` allows. Anything else is unwrapped: its text stays.
const KEPT: &[&str] = &[
    "p",
    "div",
    "span",
    "br",
    "hr",
    "b",
    "strong",
    "i",
    "em",
    "u",
    "s",
    "strike",
    "small",
    "big",
    "sub",
    "sup",
    "a",
    "ul",
    "ol",
    "li",
    "blockquote",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "pre",
    "code",
    "font",
    "center",
    "img",
    "table",
    "thead",
    "tbody",
    "tfoot",
    "tr",
    "td",
    "th",
];

/// What the formatted text editor (`editor.html`) keeps: a signature made only of these can
/// be edited there without losing anything.
const SIMPLE: &[&str] = &[
    "p",
    "div",
    "br",
    "b",
    "strong",
    "i",
    "em",
    "u",
    "s",
    "a",
    "ul",
    "ol",
    "li",
    "blockquote",
    "h1",
    "h2",
    "h3",
    "pre",
    "code",
];

/// Elements with no end tag.
const VOID: &[&str] = &["br", "hr", "img"];

/// Inline style properties that are kept (with a value `style_value` accepts).
const STYLE_PROPERTIES: &[&str] = &[
    "color",
    "background-color",
    "font-family",
    "font-size",
    "font-weight",
    "font-style",
    "font-variant",
    "text-decoration",
    "text-transform",
    "text-align",
    "line-height",
    "letter-spacing",
    "vertical-align",
    "white-space",
    "margin",
    "margin-top",
    "margin-right",
    "margin-bottom",
    "margin-left",
    "padding",
    "padding-top",
    "padding-right",
    "padding-bottom",
    "padding-left",
    "border",
    "border-top",
    "border-right",
    "border-bottom",
    "border-left",
    "border-color",
    "border-style",
    "border-width",
    "border-radius",
    "border-collapse",
    "border-spacing",
    "width",
    "height",
    "max-width",
    "min-width",
    "max-height",
    "min-height",
    "display",
];

/// What a signature is being cleaned for.
#[derive(Clone, Copy, PartialEq)]
enum Profile {
    /// Stored and sent: everything allowed, real images.
    Full,
    /// Shown in the editor or the Preview: the same, with each image a placeholder.
    Display,
    /// Saved from the formatted text editor: only what that editor keeps.
    Simple,
}

/// The signature's HTML with everything unsafe or unknown taken out (see the module notes).
pub fn clean(html: &str) -> String {
    sanitize(html, Profile::Full)
}

/// What the formatted text editor wrote, kept to what that editor can load again: WebKit
/// sometimes adds styled spans as lines are joined, which would otherwise make the next
/// load refuse it.
pub fn clean_simple(html: &str) -> String {
    sanitize(html, Profile::Simple)
}

/// For the composer and the Preview, which load nothing remote: clean, and each image a
/// small placeholder with its description.
pub fn for_display(html: &str) -> String {
    sanitize(html, Profile::Display)
}

/// Whether the formatted text editor can edit this signature without dropping anything
/// (images, tables, styles, fonts and the like are only kept by the HTML view).
pub fn fits_text_editor(html: &str) -> bool {
    let html = clean(html);
    let fragment = Html::parse_fragment(&html);
    fragment
        .root_element()
        .descendants()
        .filter_map(ElementRef::wrap)
        .skip(1)
        .all(|element| {
            let name = element.value().name();
            SIMPLE.contains(&name)
                && element
                    .value()
                    .attrs()
                    .all(|(attr, _)| name == "a" && attr == "href")
        })
}

/// The signature as plain text, for the text part of a message: one line per line, links
/// with their address when it is not already the text, images by their description.
pub fn to_text(html: &str) -> String {
    let html = clean(html);
    let fragment = Html::parse_fragment(&html);
    let mut text = Text::default();
    let mut steps = Vec::new();
    push_children(&mut steps, fragment.root_element(), 0);
    while let Some(step) = steps.pop() {
        match step {
            Step::Text(t) => text.push(t),
            Step::Leave(name, link) => {
                if let Some(link) = link {
                    text.push_raw(&format!(" <{link}>"));
                }
                if name == "pre" {
                    text.pre = text.pre.saturating_sub(1);
                }
                if is_block(name) {
                    text.block();
                }
            }
            Step::Element(element, _) => {
                let name = element.value().name();
                match name {
                    "br" => text.line(),
                    "hr" => {
                        text.block();
                        text.push_raw("---");
                        text.block();
                    }
                    "img" => {
                        let alt = element.value().attr("alt").unwrap_or("").trim();
                        if !alt.is_empty() {
                            text.push(alt);
                        }
                    }
                    _ => {
                        if is_block(name) {
                            text.block();
                        }
                        if name == "li" {
                            text.push_raw("- ");
                        }
                        if name == "pre" {
                            text.pre += 1;
                        }
                        steps.push(Step::Leave(name_static(name), link_after(element)));
                        push_children(&mut steps, element, 0);
                    }
                }
            }
        }
    }
    text.finish()
}

/// For a link: the address to write after its text, when the text does not already say it.
fn link_after(element: ElementRef<'_>) -> Option<String> {
    if element.value().name() != "a" {
        return None;
    }
    let href = element.value().attr("href")?;
    let shown = href
        .strip_prefix("mailto:")
        .map(|address| address.split('?').next().unwrap_or(address))
        .unwrap_or(href);
    let words: String = element.text().collect();
    let bare = |s: &str| {
        s.trim()
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .trim_end_matches('/')
            .to_lowercase()
    };
    (!bare(&words).contains(&bare(shown))).then(|| shown.to_string())
}

/// A tag name as one of the static names it is compared with (only those matter).
fn name_static(name: &str) -> &'static str {
    BLOCKS
        .iter()
        .chain(["pre"].iter())
        .find(|b| **b == name)
        .copied()
        .unwrap_or("")
}

const BLOCKS: &[&str] = &[
    "p",
    "div",
    "ul",
    "ol",
    "li",
    "blockquote",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "pre",
    "center",
    "table",
    "thead",
    "tbody",
    "tfoot",
    "tr",
    "td",
    "th",
];

fn is_block(name: &str) -> bool {
    BLOCKS.contains(&name)
}

/// What is left to do, the next step last. A stack, not recursion: pasted HTML can nest
/// deeper than a thread's stack can follow.
enum Step<'a> {
    Text(&'a str),
    /// An element, and how deep it is.
    Element(ElementRef<'a>, usize),
    /// An element ends (for the text: its name, and a link's address to add).
    Leave(&'static str, Option<String>),
}

/// An element's children, as steps (the first last, to be taken first). Comments, doctypes
/// and processing instructions are left out.
fn push_children<'a>(steps: &mut Vec<Step<'a>>, element: ElementRef<'a>, depth: usize) {
    for child in element.children().rev() {
        match child.value() {
            Node::Text(text) => steps.push(Step::Text(text)),
            Node::Element(_) => {
                if let Some(element) = ElementRef::wrap(child) {
                    steps.push(Step::Element(element, depth));
                }
            }
            _ => {}
        }
    }
}

/// Plain text as it is built: spaces collapsed as a browser would, lines broken by blocks.
#[derive(Default)]
struct Text {
    out: String,
    /// A space is owed before the next word.
    space: bool,
    pre: u32,
}

impl Text {
    fn push(&mut self, text: &str) {
        if self.pre > 0 {
            self.push_raw(text);
            return;
        }
        for (i, word) in text.split(char::is_whitespace).enumerate() {
            if i > 0 {
                self.space = true;
            }
            if word.is_empty() {
                continue;
            }
            self.push_raw(word);
        }
        if text.ends_with(char::is_whitespace) {
            self.space = true;
        }
    }

    fn push_raw(&mut self, text: &str) {
        if self.space && !self.out.is_empty() && !self.out.ends_with('\n') {
            self.out.push(' ');
        }
        self.space = false;
        self.out.push_str(text);
    }

    fn line(&mut self) {
        self.out.push('\n');
        self.space = false;
    }

    /// A block starts or ends: on a line of its own.
    fn block(&mut self) {
        if !self.out.is_empty() && !self.out.ends_with('\n') {
            self.out.push('\n');
        }
        self.space = false;
    }

    fn finish(self) -> String {
        let mut lines: Vec<&str> = Vec::new();
        for line in self.out.lines().map(str::trim_end) {
            // At most one empty line in a row.
            if line.is_empty() && lines.last().is_some_and(|l| l.is_empty()) {
                continue;
            }
            lines.push(line);
        }
        lines.join("\n").trim().to_string()
    }
}

// ------------------------------------------------------------------ cleaning

fn sanitize(html: &str, profile: Profile) -> String {
    if html.len() > INPUT_LIMIT {
        return String::new();
    }
    let fragment = Html::parse_fragment(html);
    let mut out = String::new();
    let mut steps = Vec::new();
    push_children(&mut steps, fragment.root_element(), 0);
    // Room kept for the end tags still to be written once the limit is reached.
    let budget = HTML_LIMIT - 1024;
    while let Some(step) = steps.pop() {
        match step {
            Step::Leave(name, _) => {
                out.push_str("</");
                out.push_str(name);
                out.push('>');
            }
            _ if out.len() >= budget => {}
            Step::Text(text) => {
                let text = escape_text(text);
                let room = budget - out.len();
                out.push_str(cut(&text, room));
            }
            Step::Element(element, depth) => {
                let name = element.value().name();
                if DROPPED.contains(&name) {
                    continue;
                }
                let allowed = match profile {
                    Profile::Simple => SIMPLE.contains(&name),
                    _ => KEPT.contains(&name),
                };
                let kept = (allowed && depth < MAX_DEPTH)
                    .then(|| open_tag(name, element.value(), profile))
                    .flatten();
                let Some(tag) = kept else {
                    // Unwrapped: what is inside stays.
                    push_children(&mut steps, element, depth);
                    continue;
                };
                if out.len() + tag.len() > budget {
                    continue;
                }
                out.push_str(&tag);
                // Void elements have no end; an image shown as a placeholder is complete.
                if VOID.contains(&name) {
                    continue;
                }
                let Some(name) = KEPT.iter().find(|k| **k == name).copied() else {
                    continue;
                };
                steps.push(Step::Leave(name, None));
                push_children(&mut steps, element, depth + 1);
            }
        }
    }
    out
}

/// At most `room` bytes of escaped text, never in the middle of a character or an entity.
fn cut(text: &str, room: usize) -> &str {
    if text.len() <= room {
        return text;
    }
    let mut end = room;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    // An entity cut in two would show as text.
    if let Some(amp) = text[..end].rfind('&')
        && !text[amp..end].contains(';')
    {
        end = amp;
    }
    &text[..end]
}

/// The start tag as it is written out, or `None` when the element cannot be kept as it is
/// (a link to nowhere safe, an image without a safe source): it is then unwrapped, or, for
/// an image, dropped.
fn open_tag(name: &str, element: &scraper::node::Element, profile: Profile) -> Option<String> {
    if name == "img" {
        let src = element.attr("src").and_then(|s| safe_url(s, false))?;
        let alt = element.attr("alt").unwrap_or("").trim();
        if profile == Profile::Display {
            let label = if alt.is_empty() { "Image" } else { alt };
            return Some(format!(
                "<span class=\"nimbra-image\">{}</span>",
                escape_text(&label.chars().take(80).collect::<String>())
            ));
        }
        let mut tag = format!("<img src=\"{}\"", escape_attr(&src));
        if !alt.is_empty() {
            tag.push_str(&format!(
                " alt=\"{}\"",
                escape_attr(&alt.chars().take(200).collect::<String>())
            ));
        }
        for attr in ["width", "height", "border"] {
            if let Some(value) = element.attr(attr).filter(|v| dimension(v)) {
                tag.push_str(&format!(" {attr}=\"{value}\""));
            }
        }
        push_style(&mut tag, element);
        tag.push('>');
        return Some(tag);
    }
    let mut tag = format!("<{name}");
    if name == "a" {
        let href = element.attr("href").and_then(|h| safe_url(h, true))?;
        tag.push_str(&format!(" href=\"{}\"", escape_attr(&href)));
    }
    if profile != Profile::Simple {
        for (attr, value) in element.attrs() {
            let value = value.trim();
            let ok = match attr {
                "dir" => matches!(value, "ltr" | "rtl" | "auto"),
                "align" => matches!(value, "left" | "right" | "center" | "justify"),
                "valign" => matches!(value, "top" | "middle" | "bottom" | "baseline"),
                "width" | "height" => {
                    matches!(name, "table" | "td" | "th" | "hr") && dimension(value)
                }
                "border" | "cellpadding" | "cellspacing" => name == "table" && digits(value),
                "colspan" | "rowspan" => matches!(name, "td" | "th") && digits(value),
                "bgcolor" => matches!(name, "table" | "tr" | "td" | "th") && color(value),
                "color" => name == "font" && color(value),
                "size" => {
                    name == "font"
                        && value.len() <= 2
                        && value
                            .trim_start_matches(['+', '-'])
                            .chars()
                            .all(|c| c.is_ascii_digit())
                }
                "face" => name == "font" && font_names(value),
                "title" => value.chars().count() <= 200,
                _ => false,
            };
            if ok {
                tag.push_str(&format!(" {attr}=\"{}\"", escape_attr(value)));
            }
        }
        push_style(&mut tag, element);
    }
    tag.push('>');
    Some(tag)
}

fn push_style(tag: &mut String, element: &scraper::node::Element) {
    if let Some(style) = element.attr("style").and_then(clean_style) {
        tag.push_str(&format!(" style=\"{}\"", escape_attr(&style)));
    }
}

/// A link (`http`, `https` or `mailto`) or an image source (`http` or `https`), written
/// out as the URL parser reads it, so what is checked is what a mail app would follow.
fn safe_url(value: &str, link: bool) -> Option<String> {
    let url = url::Url::parse(value.trim()).ok()?;
    let ok = match url.scheme() {
        "http" | "https" => url.host().is_some(),
        "mailto" => link,
        _ => false,
    };
    (ok && url.as_str().len() <= 2048).then(|| url.to_string())
}

/// An inline style kept to plain properties whose values cannot load or run anything.
fn clean_style(style: &str) -> Option<String> {
    if style.len() > 2000 {
        return None;
    }
    let kept: Vec<String> = style
        .split(';')
        .filter_map(|declaration| {
            let (property, value) = declaration.split_once(':')?;
            let property = property.trim().to_ascii_lowercase();
            let value = value.trim();
            (STYLE_PROPERTIES.contains(&property.as_str()) && style_value(value))
                .then(|| format!("{property}:{value}"))
        })
        .collect();
    (!kept.is_empty()).then(|| kept.join(";"))
}

/// A value made of words, numbers, colours, quoted font names and colour functions only:
/// no `url(`, `expression(`, `var(`, escapes, comments or anything that could end the
/// declaration.
fn style_value(value: &str) -> bool {
    if value.is_empty() || value.len() > 200 {
        return false;
    }
    let allowed = |c: char| c.is_ascii_alphanumeric() || " #%.,-'\"()/".contains(c);
    if !value.chars().all(allowed) || value.contains("/*") {
        return false;
    }
    // Every bracket opens one of the colour functions.
    let lower = value.to_ascii_lowercase();
    let mut rest = lower.as_str();
    while let Some(open) = rest.find('(') {
        let before = rest[..open]
            .rsplit(|c: char| !c.is_ascii_alphabetic())
            .next()
            .unwrap_or("");
        if !matches!(before, "rgb" | "rgba" | "hsl" | "hsla") {
            return false;
        }
        rest = &rest[open + 1..];
    }
    true
}

fn digits(value: &str) -> bool {
    !value.is_empty() && value.len() <= 4 && value.chars().all(|c| c.is_ascii_digit())
}

/// "120", "120px" or "50%".
fn dimension(value: &str) -> bool {
    let number = value
        .strip_suffix("px")
        .or_else(|| value.strip_suffix('%'))
        .unwrap_or(value);
    digits(number)
}

/// "#a0a0ff", "#fff" or a colour's name.
fn color(value: &str) -> bool {
    match value.strip_prefix('#') {
        Some(hex) => {
            matches!(hex.len(), 3 | 4 | 6 | 8) && hex.chars().all(|c| c.is_ascii_hexdigit())
        }
        None => {
            !value.is_empty() && value.len() <= 20 && value.chars().all(|c| c.is_ascii_alphabetic())
        }
    }
}

fn font_names(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 100
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || " ,-'".contains(c))
}

fn escape_text(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn escape_attr(text: &str) -> String {
    escape_text(text).replace('"', "&quot;")
}

/// The signature's HTML laid out for editing as source: a line after each block, so it is
/// not all one line. Only line breaks are added, and only where there is none yet.
pub fn source_lines(html: &str) -> String {
    const ENDS: &[&str] = &[
        "<br>",
        "</div>",
        "</p>",
        "</li>",
        "</tr>",
        "</table>",
        "</tbody>",
        "</ul>",
        "</ol>",
        "</blockquote>",
        "</h1>",
        "</h2>",
        "</h3>",
        "</h4>",
        "</h5>",
        "</h6>",
        "</pre>",
        "<hr>",
    ];
    let mut out = String::with_capacity(html.len() + html.len() / 16);
    let mut rest = html;
    while let Some(at) = rest.find('<') {
        out.push_str(&rest[..at]);
        rest = &rest[at..];
        let end = rest.find('>').map_or(rest.len(), |e| e + 1);
        let tag = &rest[..end];
        out.push_str(tag);
        rest = &rest[end..];
        if ENDS.iter().any(|e| tag.eq_ignore_ascii_case(e))
            && !rest.starts_with('\n')
            && !rest.is_empty()
        {
            out.push('\n');
        }
    }
    out.push_str(rest);
    out
}

/// A signature's name as it is kept: one line, at most `NAME_LIMIT` characters.
pub fn clean_name(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(NAME_LIMIT)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn has_no(html: &str, needles: &[&str]) {
        let lower = html.to_lowercase();
        for needle in needles {
            assert!(!lower.contains(needle), "{needle:?} is in {html:?}");
        }
    }

    #[test]
    fn simple_formatting_and_safe_links_are_kept() {
        let html = "<div><b>Luan</b> <i>Gjokaj</i></div><div><a href=\"https://nimbra.me\">nimbra.me</a> · <a href=\"mailto:luan@example.com\">mail</a></div>";
        assert_eq!(
            clean(html),
            "<div><b>Luan</b> <i>Gjokaj</i></div><div><a href=\"https://nimbra.me/\">nimbra.me</a> · <a href=\"mailto:luan@example.com\">mail</a></div>"
        );
    }

    #[test]
    fn scripts_styles_frames_and_forms_go_with_what_they_hold() {
        let html = "<div>Hi<script>alert(1)</script><style>*{color:red}</style>\
            <iframe src=\"https://x.co\">in</iframe><object data=x>o</object><embed src=x>\
            <form action=\"https://x.co\"><input value=pw><button>Go</button></form>\
            <svg onload=alert(1)><text>s</text></svg><math>m</math><noscript>n</noscript>\
            <template><b>t</b></template></div>";
        let out = clean(html);
        assert_eq!(out, "<div>Hi</div>");
    }

    #[test]
    fn handlers_classes_and_ids_are_dropped() {
        let out = clean(
            "<div onclick=\"x()\" class=\"c\" id=\"i\" onmouseover=y()><b ONLOAD=z>Bold</b></div>",
        );
        assert_eq!(out, "<div><b>Bold</b></div>");
    }

    #[test]
    fn hostile_images_and_links_are_disarmed() {
        let out = clean("<img src=x onerror=alert(1)><img src=\"javascript:alert(1)\">");
        assert_eq!(out, "");
        let out = clean("<img src=\"data:image/png;base64,AAAA\" alt=x>");
        assert_eq!(out, "");
        let out = clean(
            "<img src=\"https://cdn.example.com/logo.png\" alt=\"Logo\" width=\"120\" height=\"40px\" onerror=\"x\">",
        );
        assert_eq!(
            out,
            "<img src=\"https://cdn.example.com/logo.png\" alt=\"Logo\" width=\"120\" height=\"40px\">"
        );
        // A link anywhere else keeps its text and stops being a link.
        for href in [
            "javascript:alert(1)",
            " JaVaScRiPt:alert(1)",
            "java&#x09;script:alert(1)",
            "&#106;avascript:alert(1)",
            "vbscript:x",
            "data:text/html,<script>alert(1)</script>",
            "file:///etc/passwd",
            "/relative",
            "//no-scheme.example.com",
        ] {
            let out = clean(&format!("<a href=\"{href}\">click</a>"));
            assert_eq!(out, "click", "{href}");
        }
    }

    #[test]
    fn broken_and_sneaky_markup_comes_out_well_formed() {
        let out = clean("<scr<script>ipt>alert(1)</script>");
        has_no(&out, &["<script", "<scr"]);
        let out = clean("<div><b>open <i>never closed");
        assert_eq!(out, "<div><b>open <i>never closed</i></b></div>");
        let out = clean("<div title=\"a\" title=\"b\">x</div></b></div></div>");
        assert_eq!(out, "<div title=\"a\">x</div>");
        let out = clean("<!-- <script>alert(1)</script> --><p>after</p><!doctype html>");
        assert_eq!(out, "<p>after</p>");
        let out = clean("<div title='\"><script>alert(1)</script>'>x</div>");
        assert_eq!(
            out,
            "<div title=\"&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;\">x</div>"
        );
    }

    #[test]
    fn entities_stay_text() {
        let out = clean("<div>&lt;script&gt;alert(1)&lt;/script&gt; &amp; Tom &copy;</div>");
        assert_eq!(
            out,
            "<div>&lt;script&gt;alert(1)&lt;/script&gt; &amp; Tom ©</div>"
        );
        assert_eq!(clean("a < b > c"), "a &lt; b &gt; c");
    }

    #[test]
    fn styles_keep_plain_properties_only() {
        let out = clean(
            "<span style=\"color: #333; font-weight:bold; background:url(https://x.co/t.gif); \
             position:fixed; font-family: 'Geist', sans-serif\">x</span>",
        );
        assert_eq!(
            out,
            "<span style=\"color:#333;font-weight:bold;font-family:'Geist', sans-serif\">x</span>"
        );
        for bad in [
            "color: expression(alert(1))",
            "width: calc(1px)",
            "color: var(--x)",
            "background-color: url(x)",
            "color: red\\;",
            "color: re/**/d",
            "color: rgb(1,2,3) url(x)",
            "behavior: url(x.htc)",
            "-moz-binding: url(x)",
            "color: <script>",
        ] {
            let out = clean(&format!("<span style=\"{bad}\">x</span>"));
            assert_eq!(out, "<span>x</span>", "{bad}");
        }
        let out = clean("<span style=\"color: rgba(10, 20, 30, .5)\">x</span>");
        assert_eq!(out, "<span style=\"color:rgba(10, 20, 30, .5)\">x</span>");
    }

    #[test]
    fn tables_keep_their_layout_attributes() {
        let out = clean(
            "<table cellpadding=\"0\" cellspacing=0 border=0 onclick=x><tr><td width=\"80\" valign=\"top\" \
             bgcolor=\"#ffffff\" background=\"https://x.co/bg.png\">a</td><td colspan=2>b</td></tr></table>",
        );
        assert_eq!(
            out,
            "<table border=\"0\" cellpadding=\"0\" cellspacing=\"0\"><tbody><tr><td bgcolor=\"#ffffff\" valign=\"top\" width=\"80\">a</td><td colspan=\"2\">b</td></tr></tbody></table>"
        );
    }

    #[test]
    fn unknown_elements_are_unwrapped() {
        let out = clean("<section><custom-tag>Hi</custom-tag> <marquee>there</marquee></section>");
        assert_eq!(out, "Hi there");
    }

    #[test]
    fn size_and_depth_are_limited() {
        let long = format!("<div>{}</div>", "word ".repeat(10_000));
        let out = clean(&long);
        assert!(out.len() <= HTML_LIMIT);
        assert!(out.starts_with("<div>") && out.ends_with("</div>"));
        let deep = format!("{}deep{}", "<div>".repeat(5000), "</div>".repeat(5000));
        let out = clean(&deep);
        assert!(out.contains("deep") && out.len() <= HTML_LIMIT);
        assert_eq!(out.matches("<div>").count(), out.matches("</div>").count());
        let entities = format!("<b>{}</b>", "&amp;".repeat(10_000));
        let out = clean(&entities);
        assert!(out.ends_with("&amp;</b>"));
        assert_eq!(clean(&"x".repeat(INPUT_LIMIT + 1)), "");
    }

    #[test]
    fn cleaning_twice_changes_nothing() {
        let html = "<table><tr><td><img src=\"https://x.co/a.png\" alt=\"A\"></td><td style=\"color:#123\"><a href=\"https://x.co/\">x.co</a></td></tr></table>";
        let once = clean(html);
        assert_eq!(clean(&once), once);
    }

    #[test]
    fn images_are_placeholders_for_display() {
        let html = "<div><img src=\"https://x.co/logo.png\" alt=\"Nimbra logo\"> <img src=\"https://x.co/b.png\"> <img src=\"javascript:x\" alt=\"bad\"></div>";
        assert_eq!(
            for_display(html),
            "<div><span class=\"nimbra-image\">Nimbra logo</span> <span class=\"nimbra-image\">Image</span> </div>"
        );
        assert_eq!(
            for_display("<img src=\"https://x.co/a.png\" alt=\"<b>&\">"),
            "<span class=\"nimbra-image\">&lt;b&gt;&amp;</span>"
        );
        // A class is only ever set by this: the signature's own are dropped.
        assert_eq!(
            for_display("<span class=\"nimbra-image\">x</span>"),
            "<span>x</span>"
        );
    }

    #[test]
    fn the_text_editor_takes_simple_signatures_only() {
        assert!(fits_text_editor(
            "<div><b>Luan</b></div><div><a href=\"https://x.co\">x</a></div><ul><li>a</li></ul>"
        ));
        assert!(fits_text_editor(""));
        assert!(!fits_text_editor(
            "<div><img src=\"https://x.co/a.png\"></div>"
        ));
        assert!(!fits_text_editor("<table><tr><td>a</td></tr></table>"));
        assert!(!fits_text_editor("<div style=\"color:red\">a</div>"));
        assert!(!fits_text_editor("<span>a</span>"));
        // What it would drop anyway is not counted.
        assert!(fits_text_editor("<div onclick=x>a<script>b</script></div>"));
        assert_eq!(
            clean_simple(
                "<div style=\"color:red\"><span style=\"font-weight:bold\">a</span> <a href=\"https://x.co\" title=\"t\">b</a></div>"
            ),
            "<div>a <a href=\"https://x.co/\">b</a></div>"
        );
    }

    #[test]
    fn plain_text_has_lines_links_and_descriptions() {
        let html = "<div><b>Luan  Gjokaj</b></div><div>UX Engineer<br>Nimbra</div>\
            <div><a href=\"https://nimbra.me\">nimbra.me</a> · <a href=\"https://x.co/about\">About us</a></div>\
            <div><a href=\"mailto:luan@example.com?subject=hi\">Write to me</a></div>\
            <table><tr><td><img src=\"https://x.co/l.png\" alt=\"Logo\"></td><td>Cell</td></tr></table>\
            <ul><li>one</li><li>two</li></ul>";
        assert_eq!(
            to_text(html),
            "Luan Gjokaj\nUX Engineer\nNimbra\nnimbra.me · About us <https://x.co/about>\n\
             Write to me <luan@example.com>\nLogo\nCell\n- one\n- two"
        );
        assert_eq!(to_text("<script>x</script>"), "");
        assert_eq!(to_text("a &amp; b"), "a & b");
    }

    #[test]
    fn source_gets_a_line_per_block_once() {
        let html = "<div><b>Luan</b></div><div>UX<br>Nimbra</div><table><tbody><tr><td>a</td></tr></tbody></table>";
        let lines = source_lines(html);
        assert_eq!(
            lines,
            "<div><b>Luan</b></div>\n<div>UX<br>\nNimbra</div>\n<table><tbody><tr><td>a</td></tr>\n</tbody>\n</table>"
        );
        assert_eq!(source_lines(&lines), lines);
        // What it shows is what is kept.
        assert_eq!(to_text(&lines), to_text(html));
        assert_eq!(source_lines("a < b"), "a < b");
    }

    #[test]
    fn names_are_one_short_line() {
        assert_eq!(clean_name("Work\nsig"), "Work sig");
        assert_eq!(clean_name(&"n".repeat(100)).chars().count(), NAME_LIMIT);
    }
}
