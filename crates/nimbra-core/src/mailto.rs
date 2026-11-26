//! `mailto:` links (RFC 6068), from other apps and from links in mail. A link only ever
//! fills in a new message: whoever wrote it chooses nothing the user does not see.

/// A new message, as a `mailto:` link asks for it.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Mailto {
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub bcc: Vec<String>,
    pub subject: String,
    pub body: String,
}

const MAX_LINK: usize = 256 * 1024;
const MAX_ADDRESSES: usize = 100;
const MAX_SUBJECT: usize = 300;
const MAX_BODY: usize = 64 * 1024;

pub fn is_mailto(link: &str) -> bool {
    link.get(..7)
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("mailto:"))
}

pub fn parse(link: &str) -> Option<Mailto> {
    if link.len() > MAX_LINK || !is_mailto(link) {
        return None;
    }
    let rest = &link[7..];
    let rest = rest.split_once('#').map_or(rest, |(before, _)| before);
    let (path, query) = rest.split_once('?').unwrap_or((rest, ""));
    let mut mail = Mailto::default();
    let mut seen = std::collections::HashSet::new();
    add_addresses(&mut mail.to, &mut seen, &decode(path));
    let (mut subject, mut body) = (None, None);
    for pair in query.split('&') {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        match decode(name).to_ascii_lowercase().as_str() {
            "to" => add_addresses(&mut mail.to, &mut seen, &decode(value)),
            "cc" => add_addresses(&mut mail.cc, &mut seen, &decode(value)),
            "bcc" => add_addresses(&mut mail.bcc, &mut seen, &decode(value)),
            "subject" if subject.is_none() => subject = Some(decode(value)),
            "body" if body.is_none() => body = Some(decode(value)),
            _ => {}
        }
    }
    mail.subject = subject.as_deref().map(one_line).unwrap_or_default();
    mail.body = body.as_deref().map(plain_text).unwrap_or_default();
    Some(mail)
}

/// Percent-decoding without the form rule that `+` is a space. Bytes that are not
/// UTF-8 become the replacement character; a `%` without two hex digits stays as it is.
fn decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = |b: u8| (b as char).to_digit(16);
        if bytes[i] == b'%'
            && let (Some(hi), Some(lo)) = (
                bytes.get(i + 1).copied().and_then(hex),
                bytes.get(i + 2).copied().and_then(hex),
            )
        {
            out.push((hi * 16 + lo) as u8);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Valid addresses only, each once across To, Cc and Bcc. Anything with a control character
/// is refused whole, so a line break can never start a header of its own.
fn add_addresses(into: &mut Vec<String>, seen: &mut std::collections::HashSet<String>, list: &str) {
    for part in list.split([',', ';']) {
        if seen.len() >= MAX_ADDRESSES {
            return;
        }
        if part.chars().any(char::is_control) {
            continue;
        }
        let address = crate::mail::address_of(part);
        let Some(address) = ascii_domain(&address).filter(|a| crate::mail::is_address(a)) else {
            continue;
        };
        if seen.insert(address.to_ascii_lowercase()) {
            into.push(address);
        }
    }
}

/// An international domain in the ASCII form mail servers take.
fn ascii_domain(address: &str) -> Option<String> {
    let (local, domain) = address.rsplit_once('@')?;
    if domain.is_ascii() {
        return Some(address.to_string());
    }
    let domain = url::quirks::domain_to_ascii(domain);
    (!domain.is_empty()).then(|| format!("{local}@{domain}"))
}

fn one_line(text: &str) -> String {
    let line: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(MAX_SUBJECT)
        .collect();
    line.trim().to_string()
}

fn plain_text(text: &str) -> String {
    text.replace("\r\n", "\n")
        .chars()
        .filter(|c| !c.is_control() || matches!(c, '\n' | '\t'))
        .take(MAX_BODY)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to(link: &str) -> Vec<String> {
        parse(link).map(|m| m.to).unwrap_or_default()
    }

    #[test]
    fn takes_one_address() {
        assert_eq!(to("mailto:a@example.com"), ["a@example.com"]);
    }

    #[test]
    fn the_scheme_is_case_insensitive() {
        assert_eq!(to("MailTo:a@example.com"), ["a@example.com"]);
    }

    #[test]
    fn refuses_other_schemes() {
        assert_eq!(parse("https://example.com"), None);
        assert_eq!(parse("mail:a@example.com"), None);
        assert_eq!(parse(""), None);
    }

    #[test]
    fn takes_several_addresses() {
        assert_eq!(
            to("mailto:a@example.com,b@example.org"),
            ["a@example.com", "b@example.org"]
        );
    }

    #[test]
    fn an_encoded_comma_separates_addresses_too() {
        assert_eq!(
            to("mailto:a@example.com%2Cb@example.org"),
            ["a@example.com", "b@example.org"]
        );
        assert_eq!(
            to("mailto:a@example.com%2cb@example.org"),
            ["a@example.com", "b@example.org"]
        );
    }

    #[test]
    fn percent_decodes_addresses() {
        assert_eq!(
            to("mailto:leave%2Bme@example.com"),
            ["leave+me@example.com"]
        );
    }

    #[test]
    fn a_plus_is_a_plus() {
        assert_eq!(to("mailto:leave+me@example.com"), ["leave+me@example.com"]);
        let mail = parse("mailto:a@example.com?subject=1+1").unwrap();
        assert_eq!(mail.subject, "1+1");
    }

    #[test]
    fn reads_every_field() {
        let mail = parse(
            "mailto:a@example.com?cc=b@example.com&bcc=c@example.com&subject=Hello%20there&body=Line%20one",
        )
        .unwrap();
        assert_eq!(mail.to, ["a@example.com"]);
        assert_eq!(mail.cc, ["b@example.com"]);
        assert_eq!(mail.bcc, ["c@example.com"]);
        assert_eq!(mail.subject, "Hello there");
        assert_eq!(mail.body, "Line one");
    }

    #[test]
    fn field_names_are_case_insensitive() {
        let mail = parse("mailto:?SUBJECT=Hi&Cc=b@example.com").unwrap();
        assert_eq!(mail.subject, "Hi");
        assert_eq!(mail.cc, ["b@example.com"]);
    }

    #[test]
    fn a_to_field_adds_to_the_path() {
        assert_eq!(
            to("mailto:a@example.com?to=b@example.com&to=c@example.com"),
            ["a@example.com", "b@example.com", "c@example.com"]
        );
    }

    #[test]
    fn the_same_address_is_taken_once() {
        assert_eq!(
            to("mailto:a@example.com?to=A@Example.com"),
            ["a@example.com"]
        );
    }

    #[test]
    fn no_address_is_still_a_message() {
        let mail = parse("mailto:?subject=Feedback").unwrap();
        assert!(mail.to.is_empty());
        assert_eq!(mail.subject, "Feedback");
        assert_eq!(parse("mailto:"), Some(Mailto::default()));
    }

    #[test]
    fn invalid_addresses_are_left_out() {
        assert_eq!(
            to("mailto:not-an-address,a@example.com,@x.com"),
            ["a@example.com"]
        );
    }

    #[test]
    fn a_display_name_gives_its_address() {
        assert_eq!(to("mailto:Ann%20%3Ca@example.com%3E"), ["a@example.com"]);
    }

    #[test]
    fn a_line_break_cannot_add_a_header() {
        let mail = parse("mailto:a@example.com?subject=Hi%0D%0ABcc:%20evil@example.com").unwrap();
        assert_eq!(mail.subject, "Hi  Bcc: evil@example.com");
        assert!(mail.bcc.is_empty());
        assert!(to("mailto:a@example.com%0D%0ABcc:evil@example.com").is_empty());
        let mail = parse("mailto:?cc=b@example.com%0Abcc:evil@example.com").unwrap();
        assert!(mail.cc.is_empty());
    }

    #[test]
    fn other_fields_and_attachments_are_ignored() {
        let mail =
            parse("mailto:a@example.com?attach=/etc/passwd&attachment=x&from=me@x.com&x-y=z")
                .unwrap();
        assert_eq!(
            mail,
            Mailto {
                to: vec!["a@example.com".into()],
                ..Mailto::default()
            }
        );
    }

    #[test]
    fn the_body_keeps_its_lines_and_drops_other_controls() {
        let mail = parse("mailto:?body=one%0D%0Atwo%0Athree%09tab%00%07end").unwrap();
        assert_eq!(mail.body, "one\ntwo\nthree\ttabend");
    }

    #[test]
    fn reads_unicode() {
        let mail =
            parse("mailto:a@example.com?subject=Caf%C3%A9%20%E2%9C%93&body=%F0%9F%98%80").unwrap();
        assert_eq!(mail.subject, "Café ✓");
        assert_eq!(mail.body, "😀");
        let raw = parse("mailto:a@example.com?subject=Café").unwrap();
        assert_eq!(raw.subject, "Café");
    }

    #[test]
    fn an_international_domain_is_spelled_for_mail() {
        assert_eq!(
            to("mailto:a@b%C3%BCcher.example"),
            ["a@xn--bcher-kva.example"]
        );
    }

    #[test]
    fn broken_encodings_do_not_panic() {
        let mail = parse("mailto:a@example.com?subject=%E2%9C&body=%ZZ%2").unwrap();
        assert_eq!(mail.subject, "\u{fffd}");
        assert_eq!(mail.body, "%ZZ%2");
    }

    #[test]
    fn the_fragment_is_not_part_of_the_message() {
        let mail = parse("mailto:a@example.com?subject=Hi#ignored").unwrap();
        assert_eq!(mail.subject, "Hi");
    }

    #[test]
    fn the_first_subject_and_body_win() {
        let mail = parse("mailto:?subject=one&subject=two&body=a&body=b").unwrap();
        assert_eq!((mail.subject.as_str(), mail.body.as_str()), ("one", "a"));
    }

    #[test]
    fn long_links_are_cut_down() {
        let long = "x".repeat(MAX_BODY + 10);
        let mail = parse(&format!("mailto:?subject={long}&body={long}")).unwrap();
        assert_eq!(mail.subject.chars().count(), MAX_SUBJECT);
        assert_eq!(mail.body.chars().count(), MAX_BODY);
        let many: Vec<String> = (0..MAX_ADDRESSES + 5)
            .map(|n| format!("p{n}@example.com"))
            .collect();
        assert_eq!(
            to(&format!("mailto:{}", many.join(","))).len(),
            MAX_ADDRESSES
        );
        assert_eq!(
            parse(&format!("mailto:?body={}", "x".repeat(MAX_LINK))),
            None
        );
    }

    #[test]
    fn an_empty_field_or_pair_is_skipped() {
        let mail = parse("mailto:a@example.com?&&subject=&=x&body").unwrap();
        assert_eq!(mail.to, ["a@example.com"]);
        assert_eq!(mail.subject, "");
    }

    #[test]
    fn the_subject_is_one_trimmed_line() {
        let mail = parse("mailto:?subject=%20%20Hi%09there%20%20").unwrap();
        assert_eq!(mail.subject, "Hi there");
    }

    #[test]
    fn recognises_the_scheme() {
        assert!(is_mailto("MAILTO:a@b.co"));
        assert!(!is_mailto("mail"));
        assert!(!is_mailto("https://a"));
        assert!(!is_mailto("mailté:"));
    }
}
