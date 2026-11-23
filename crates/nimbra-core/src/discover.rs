//! Finds the IMAP and SMTP servers for an email address: from a list of well-known
//! providers first, then from the domain's own autoconfig file, then from Thunderbird's
//! ISPDB (the public list Thunderbird uses).
//!
//! Security/privacy notes:
//! - The address is checked before anything else, and its domain must be a plain host name
//!   (not an IP address) before it is put into a URL.
//! - Only HTTPS is used, and a redirect to plain HTTP is refused. Each request has a short
//!   time limit and its answer a size limit.
//! - Asking the domain's own autoconfig server (`autoconfig.<domain>` and
//!   `<domain>/.well-known/…`) sends it the full address, as Thunderbird does: that server
//!   belongs to whoever runs the mail for the address.
//! - Asking Thunderbird's ISPDB sends Mozilla the domain only, never the full address.
//! - A server that is only reached in plain text is never offered, and POP3 is ignored.
//!   Host names from the network are checked like typed ones, so a hostile file cannot
//!   carry anything else into a connection.
//! - Microsoft and Google no longer take passwords over IMAP, so their addresses come back
//!   as `NeedsOAuth`, as does any config that only offers OAuth2.

use std::io::Read as _;
use std::time::Duration;

use anyhow::{Result, bail};

use crate::mail::is_address;
use crate::servers::{Security, Server, Servers, is_host};

/// How long one request may take, from connecting to the last byte.
const TIMEOUT: Duration = Duration::from_secs(5);
/// The most an autoconfig answer may be. Real ones are a few kilobytes.
const MAX_BYTES: u64 = 64 * 1024;
/// Redirects followed per request (all of them HTTPS).
const MAX_REDIRECTS: u32 = 3;

/// What was found for an address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Found {
    /// The servers to use, with the name to sign in with.
    Servers(Servers),
    /// The provider only lets mail apps in through its own sign-in (OAuth), not a password.
    NeedsOAuth { provider: &'static str },
    /// Nothing answered: the servers have to be typed in.
    Unknown,
}

/// The servers of well-known providers. No network.
pub fn known(email: &str) -> Option<Found> {
    let email = email.trim();
    if !is_address(email) {
        return None;
    }
    let (_, domain) = email.rsplit_once('@')?;
    let domain = domain.to_ascii_lowercase();
    let preset = PRESETS
        .iter()
        .find(|preset| preset.domains.contains(&domain.as_str()))?;
    Some(match preset.servers {
        Preset::OAuth(provider) => Found::NeedsOAuth { provider },
        Preset::Password { imap, smtp } => Found::Servers(Servers {
            username: email.to_string(),
            imap: Server::new(imap.0, imap.1, imap.2),
            smtp: Server::new(smtp.0, smtp.1, smtp.2),
        }),
    })
}

/// The servers for an address: the presets, then the domain's own autoconfig, then
/// Thunderbird's ISPDB. Blocks for up to a few seconds per source; `Unknown` when none
/// of them answers.
pub fn discover(email: &str) -> Result<Found> {
    let email = email.trim();
    if !is_address(email) {
        bail!(
            "“{}” is not an email address.",
            crate::mail::sanitize(email)
        );
    }
    if let Some(found) = known(email) {
        return Ok(found);
    }
    let Some(domain) = url_domain(email) else {
        bail!(
            "“{}” is not an email address.",
            crate::mail::sanitize(email)
        );
    };
    let address: String = url::form_urlencoded::byte_serialize(email.as_bytes()).collect();
    let sources = [
        format!("https://autoconfig.{domain}/mail/config-v1.1.xml?emailaddress={address}"),
        format!("https://{domain}/.well-known/autoconfig/mail/config-v1.1.xml"),
        format!("https://autoconfig.thunderbird.net/v1.1/{domain}"),
    ];
    let agent = ureq::AgentBuilder::new()
        .timeout(TIMEOUT)
        .https_only(true)
        .redirects(MAX_REDIRECTS)
        .build();
    for url in &sources {
        let Some(xml) = fetch(&agent, url) else {
            continue;
        };
        if let Some(found) = parse(&xml, email) {
            return Ok(found);
        }
    }
    Ok(Found::Unknown)
}

/// The address's domain, lowercase, when it is safe to put into a URL: a plain DNS name,
/// not an IP address.
fn url_domain(email: &str) -> Option<String> {
    let (_, domain) = email.rsplit_once('@')?;
    let domain = domain.to_ascii_lowercase();
    let plain = is_host(&domain) && domain.parse::<std::net::IpAddr>().is_err();
    plain.then_some(domain)
}

/// The body of an HTTPS answer, or `None` for any failure (no answer, not 200, too big,
/// not text, or redirected away from HTTPS).
fn fetch(agent: &ureq::Agent, url: &str) -> Option<String> {
    let response = agent.get(url).call().ok()?;
    if response.status() != 200 || !response.get_url().starts_with("https://") {
        return None;
    }
    let mut body = Vec::new();
    response
        .into_reader()
        .take(MAX_BYTES + 1)
        .read_to_end(&mut body)
        .ok()?;
    if body.len() as u64 > MAX_BYTES {
        return None;
    }
    String::from_utf8(body).ok()
}

/// One server from an autoconfig file, after its placeholders are filled in.
struct Offer {
    server: Server,
    username: Option<String>,
    password: bool,
    oauth: bool,
}

/// Reads a Mozilla autoconfig document (`clientConfig` version 1.1). `None` when it offers
/// no usable IMAP and SMTP pair (so the next source is tried).
fn parse(xml: &str, email: &str) -> Option<Found> {
    let xml = strip_comments(xml);
    if !xml.to_ascii_lowercase().contains("<clientconfig") {
        return None;
    }
    let incoming = offers(&xml, "incomingServer", "imap", email);
    let outgoing = offers(&xml, "outgoingServer", "smtp", email);
    // Implicit TLS first, then the file's own order.
    let pick = |offers: &[Offer]| {
        let mut usable: Vec<&Offer> = offers.iter().filter(|offer| offer.password).collect();
        usable.sort_by_key(|offer| offer.server.security != Security::Tls);
        usable
            .first()
            .map(|offer| (offer.server.clone(), offer.username.clone()))
    };
    match (pick(&incoming), pick(&outgoing)) {
        (Some((imap, username)), Some((smtp, _))) => {
            let servers = Servers {
                username: username.unwrap_or_else(|| email.to_string()),
                imap,
                smtp,
            };
            servers.check().ok()?;
            Some(Found::Servers(servers))
        }
        _ => {
            // Servers that are there but only take OAuth2.
            let oauth = incoming.iter().chain(&outgoing).find(|offer| offer.oauth)?;
            Some(Found::NeedsOAuth {
                provider: oauth_provider(&oauth.server.host),
            })
        }
    }
}

/// The servers of one kind (`imap`, `smtp`) in the document. Plain-text ones, ones with a
/// host that is not a plain name, and other kinds (POP3) are left out.
fn offers(xml: &str, tag: &str, kind: &str, email: &str) -> Vec<Offer> {
    let (local, domain) = email.rsplit_once('@').unwrap_or((email, ""));
    let fill = |text: &str| {
        text.replace("%EMAILADDRESS%", email)
            .replace("%EMAILLOCALPART%", local)
            .replace("%EMAILDOMAIN%", domain)
    };
    elements(xml, tag)
        .into_iter()
        .filter(|(attributes, _)| attribute(attributes, "type").as_deref() == Some(kind))
        .filter_map(|(_, inner)| {
            let security = match text_of(inner, "socketType")?.to_ascii_uppercase().as_str() {
                "SSL" | "TLS" => Security::Tls,
                "STARTTLS" => Security::StartTls,
                _ => return None,
            };
            let port: u16 = text_of(inner, "port")?.parse().ok()?;
            let server = Server::new(&fill(&text_of(inner, "hostname")?), port, security);
            server.check().ok()?;
            let username = text_of(inner, "username")
                .map(|name| fill(&name))
                .filter(|name| {
                    !name.is_empty() && !name.contains('%') && !name.chars().any(char::is_control)
                });
            let methods: Vec<String> = elements(inner, "authentication")
                .into_iter()
                .map(|(_, text)| decode(text.trim()).to_ascii_lowercase())
                .collect();
            Some(Offer {
                username,
                // No method named means a password, as in Thunderbird.
                password: methods.is_empty()
                    || methods
                        .iter()
                        .any(|method| method == "password-cleartext" || method == "plain")
                    || takes_app_passwords(&server.host),
                oauth: methods.iter().any(|method| method == "oauth2"),
                server,
            })
        })
        .collect()
}

/// Whether `host` is `domain` or a name under it.
fn under(host: &str, domain: &str) -> bool {
    host == domain || host.ends_with(&format!(".{domain}"))
}

/// Fastmail's autoconfig lists only OAuth2 (for Thunderbird's own client), but its servers
/// take app passwords, which is what its custom-domain users are told to make.
fn takes_app_passwords(host: &str) -> bool {
    under(host, "fastmail.com") || under(host, "messagingengine.com")
}

/// Whose sign-in an OAuth2-only server needs, from its host name.
fn oauth_provider(host: &str) -> &'static str {
    let under = |domain: &str| under(host, domain);
    if under("outlook.com") || under("office365.com") || under("hotmail.com") {
        "Microsoft"
    } else if under("gmail.com") || under("googlemail.com") || under("google.com") {
        "Google"
    } else if under("yahoo.com") {
        "Yahoo"
    } else if under("aol.com") {
        "AOL"
    } else {
        "your email provider"
    }
}

/// The document without its `<!-- … -->` comments, so a commented-out server is not read.
fn strip_comments(xml: &str) -> String {
    let mut out = String::with_capacity(xml.len());
    let mut rest = xml;
    while let Some(start) = rest.find("<!--") {
        out.push_str(&rest[..start]);
        match rest[start + 4..].find("-->") {
            Some(end) => rest = &rest[start + 4 + end + 3..],
            None => return out,
        }
    }
    out.push_str(rest);
    out
}

/// Each `<tag …>inner</tag>` in `xml` (tag names matched without regard to case), as its
/// attribute text and its inner text. Self-closing and unclosed elements are skipped.
fn elements<'a>(xml: &'a str, tag: &str) -> Vec<(&'a str, &'a str)> {
    // ASCII lowercasing keeps byte offsets, so indices found in `lower` fit `xml`.
    let lower = xml.to_ascii_lowercase();
    let open = format!("<{}", tag.to_ascii_lowercase());
    let close = format!("</{}>", tag.to_ascii_lowercase());
    let mut found = Vec::new();
    let mut from = 0;
    while let Some(at) = lower[from..].find(&open).map(|at| from + at) {
        let after = at + open.len();
        // `<port>` must not match `<portal>`.
        if !matches!(
            lower[after..].chars().next(),
            Some('>' | ' ' | '\t' | '\r' | '\n')
        ) {
            from = after;
            continue;
        }
        let Some(end) = lower[after..].find('>').map(|end| after + end) else {
            break;
        };
        if lower[..end].ends_with('/') {
            from = end + 1;
            continue;
        }
        let Some(closing) = lower[end + 1..].find(&close).map(|c| end + 1 + c) else {
            break;
        };
        found.push((&xml[after..end], &xml[end + 1..closing]));
        from = closing + close.len();
    }
    found
}

/// The trimmed, unescaped text of the first `<tag>` in `xml`.
fn text_of(xml: &str, tag: &str) -> Option<String> {
    elements(xml, tag)
        .first()
        .map(|(_, text)| decode(text.trim()))
}

/// The value of `name="…"` (or `'…'`) in an element's attribute text.
fn attribute(attributes: &str, name: &str) -> Option<String> {
    let mut rest = attributes;
    while let Some(at) = rest.find(name) {
        let before_ok = at == 0 || rest[..at].ends_with(char::is_whitespace);
        let after = rest[at + name.len()..].trim_start();
        if before_ok && let Some(value) = after.strip_prefix('=') {
            let value = value.trim_start();
            let quote = value.chars().next()?;
            if quote == '"' || quote == '\'' {
                let value = &value[1..];
                return Some(decode(&value[..value.find(quote)?]).to_ascii_lowercase());
            }
        }
        rest = &rest[at + name.len()..];
    }
    None
}

/// XML's five named entities. Anything else is left as it is (and then fails the host and
/// user name checks if it matters).
fn decode(text: &str) -> String {
    text.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// The servers of one preset: (host, port, security) for IMAP and SMTP.
#[derive(Clone, Copy)]
enum Preset {
    Password {
        imap: (&'static str, u16, Security),
        smtp: (&'static str, u16, Security),
    },
    OAuth(&'static str),
}

struct Provider {
    domains: &'static [&'static str],
    servers: Preset,
}

const fn tls(imap: &'static str, smtp: &'static str) -> Preset {
    Preset::Password {
        imap: (imap, 993, Security::Tls),
        smtp: (smtp, 465, Security::Tls),
    }
}

/// Well-known providers, from their own help pages and Thunderbird's ISPDB.
const PRESETS: &[Provider] = &[
    Provider {
        domains: &["gmail.com", "googlemail.com"],
        servers: Preset::OAuth("Google"),
    },
    Provider {
        domains: &[
            "outlook.com",
            "hotmail.com",
            "live.com",
            "msn.com",
            "windowslive.com",
            "passport.com",
            "outlook.co.uk",
            "outlook.de",
            "outlook.fr",
            "outlook.es",
            "outlook.it",
            "hotmail.co.uk",
            "hotmail.de",
            "hotmail.fr",
            "hotmail.es",
            "hotmail.it",
            "live.co.uk",
            "live.de",
            "live.fr",
            "live.it",
        ],
        servers: Preset::OAuth("Microsoft"),
    },
    // Zoho, by data centre.
    Provider {
        domains: &["zoho.com", "zohomail.com"],
        servers: tls("imap.zoho.com", "smtp.zoho.com"),
    },
    Provider {
        domains: &["zoho.eu", "zohomail.eu"],
        servers: tls("imap.zoho.eu", "smtp.zoho.eu"),
    },
    Provider {
        domains: &["zoho.in", "zohomail.in"],
        servers: tls("imap.zoho.in", "smtp.zoho.in"),
    },
    Provider {
        domains: &["zoho.com.au", "zohomail.com.au"],
        servers: tls("imap.zoho.com.au", "smtp.zoho.com.au"),
    },
    Provider {
        domains: &["zoho.jp", "zohomail.jp"],
        servers: tls("imap.zoho.jp", "smtp.zoho.jp"),
    },
    Provider {
        domains: &["zohocloud.ca", "zohomailcloud.ca"],
        servers: tls("imap.zohocloud.ca", "smtp.zohocloud.ca"),
    },
    Provider {
        domains: &["zoho.sa"],
        servers: tls("imap.zoho.sa", "smtp.zoho.sa"),
    },
    // iCloud has no implicit TLS SMTP port.
    Provider {
        domains: &["icloud.com", "me.com", "mac.com"],
        servers: Preset::Password {
            imap: ("imap.mail.me.com", 993, Security::Tls),
            smtp: ("smtp.mail.me.com", 587, Security::StartTls),
        },
    },
    Provider {
        domains: &["fastmail.com", "fastmail.fm"],
        servers: tls("imap.fastmail.com", "smtp.fastmail.com"),
    },
    Provider {
        domains: &[
            "yahoo.com",
            "ymail.com",
            "rocketmail.com",
            "myyahoo.com",
            "yahoo.co.uk",
            "yahoo.ca",
            "yahoo.com.au",
            "yahoo.co.in",
            "yahoo.de",
            "yahoo.fr",
            "yahoo.es",
            "yahoo.it",
            "yahoo.com.br",
            "yahoo.com.mx",
        ],
        servers: tls("imap.mail.yahoo.com", "smtp.mail.yahoo.com"),
    },
    Provider {
        domains: &["aol.com", "aim.com", "aol.co.uk", "aol.de", "aol.fr"],
        servers: tls("imap.aol.com", "smtp.aol.com"),
    },
    Provider {
        domains: &[
            "gmx.com",
            "gmx.us",
            "gmx.co.uk",
            "gmx.fr",
            "gmx.es",
            "gmx.it",
        ],
        servers: tls("imap.gmx.com", "mail.gmx.com"),
    },
    Provider {
        domains: &["gmx.net", "gmx.de", "gmx.at", "gmx.ch"],
        servers: tls("imap.gmx.net", "mail.gmx.net"),
    },
    Provider {
        domains: &["mail.com", "email.com", "usa.com", "post.com"],
        servers: tls("imap.mail.com", "smtp.mail.com"),
    },
    Provider {
        domains: &[
            "yandex.com",
            "yandex.ru",
            "ya.ru",
            "yandex.by",
            "yandex.kz",
            "yandex.ua",
        ],
        servers: tls("imap.yandex.com", "smtp.yandex.com"),
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    fn servers(found: Option<Found>) -> Servers {
        match found {
            Some(Found::Servers(servers)) => servers,
            other => panic!("expected servers, got {other:?}"),
        }
    }

    #[test]
    fn zoho_is_found_by_region() {
        for (email, imap, smtp) in [
            ("a@zoho.com", "imap.zoho.com", "smtp.zoho.com"),
            ("a@zohomail.com", "imap.zoho.com", "smtp.zoho.com"),
            ("a@zoho.eu", "imap.zoho.eu", "smtp.zoho.eu"),
            ("a@zoho.in", "imap.zoho.in", "smtp.zoho.in"),
            ("a@zoho.com.au", "imap.zoho.com.au", "smtp.zoho.com.au"),
            ("a@zoho.jp", "imap.zoho.jp", "smtp.zoho.jp"),
            ("a@zohocloud.ca", "imap.zohocloud.ca", "smtp.zohocloud.ca"),
        ] {
            let found = servers(known(email));
            assert_eq!(found.imap, Server::new(imap, 993, Security::Tls), "{email}");
            assert_eq!(found.smtp, Server::new(smtp, 465, Security::Tls), "{email}");
            assert_eq!(found.username, email);
            assert!(found.check().is_ok());
        }
    }

    #[test]
    fn icloud_sends_with_starttls_on_587() {
        let found = servers(known(" Someone@Me.com "));
        assert_eq!(found.username, "Someone@Me.com");
        assert_eq!(
            found.imap,
            Server::new("imap.mail.me.com", 993, Security::Tls)
        );
        assert_eq!(
            found.smtp,
            Server::new("smtp.mail.me.com", 587, Security::StartTls)
        );
    }

    #[test]
    fn microsoft_and_google_need_their_sign_in() {
        for email in ["a@outlook.com", "a@hotmail.com", "a@live.com", "a@msn.com"] {
            assert_eq!(
                known(email),
                Some(Found::NeedsOAuth {
                    provider: "Microsoft"
                })
            );
        }
        assert_eq!(
            known("a@gmail.com"),
            Some(Found::NeedsOAuth { provider: "Google" })
        );
    }

    #[test]
    fn every_preset_is_a_valid_server() {
        for provider in PRESETS {
            for domain in provider.domains {
                if let Some(Found::Servers(servers)) = known(&format!("a@{domain}")) {
                    assert!(servers.check().is_ok(), "{domain}");
                }
            }
        }
    }

    #[test]
    fn other_domains_and_bad_input_are_not_known() {
        for email in [
            "a@example.com",
            "a@notzoho.com",
            "",
            "zoho.com",
            "a@",
            "@zoho.com",
        ] {
            assert_eq!(known(email), None, "{email:?}");
        }
    }

    #[test]
    fn bad_addresses_are_refused_before_any_request() {
        for email in [
            "",
            "nobody",
            "a@b",
            "a b@example.com",
            "a@exa mple.com",
            "a@x.com/evil",
        ] {
            assert!(discover(email).is_err(), "{email:?}");
        }
        assert_eq!(url_domain("a@127.0.0.1"), None);
        assert_eq!(
            url_domain("a@Mail.Example.org").as_deref(),
            Some("mail.example.org")
        );
    }

    const CONFIG: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<clientConfig version="1.1">
  <emailProvider id="example.org">
    <domain>example.org</domain>
    <displayName>Example Mail</displayName>
    <displayShortName>Example</displayShortName>
    <incomingServer type="pop3">
      <hostname>pop.example.org</hostname>
      <port>995</port>
      <socketType>SSL</socketType>
      <username>%EMAILADDRESS%</username>
      <authentication>password-cleartext</authentication>
    </incomingServer>
    <!-- <incomingServer type="imap"><hostname>old.example.org</hostname><port>993</port>
         <socketType>SSL</socketType></incomingServer> -->
    <incomingServer type="imap">
      <hostname>imap-plain.%EMAILDOMAIN%</hostname>
      <port>143</port>
      <socketType>plain</socketType>
      <username>%EMAILLOCALPART%</username>
      <authentication>password-cleartext</authentication>
    </incomingServer>
    <incomingServer type="imap">
      <hostname>mail.%EMAILDOMAIN%</hostname>
      <port>143</port>
      <socketType>STARTTLS</socketType>
      <username>%EMAILLOCALPART%</username>
      <authentication>password-cleartext</authentication>
    </incomingServer>
    <incomingServer type="imap">
      <hostname>IMAP.%EMAILDOMAIN%</hostname>
      <port>993</port>
      <socketType>SSL</socketType>
      <username>%EMAILLOCALPART%</username>
      <authentication>password-cleartext</authentication>
    </incomingServer>
    <outgoingServer type="smtp">
      <hostname>smtp.example.org</hostname>
      <port>587</port>
      <socketType>STARTTLS</socketType>
      <username>%EMAILADDRESS%</username>
      <authentication>password-cleartext</authentication>
    </outgoingServer>
    <documentation url="http://example.org/help">
      <descr lang="en">Setup</descr>
    </documentation>
  </emailProvider>
</clientConfig>"#;

    #[test]
    fn an_autoconfig_file_is_read_with_its_placeholders() {
        let found = servers(parse(CONFIG, "jo@example.org"));
        assert_eq!(found.username, "jo");
        // Implicit TLS is chosen over STARTTLS; the plain one is dropped.
        assert_eq!(
            found.imap,
            Server::new("imap.example.org", 993, Security::Tls)
        );
        assert_eq!(
            found.smtp,
            Server::new("smtp.example.org", 587, Security::StartTls)
        );
    }

    #[test]
    fn socket_types_map_to_tls_or_starttls() {
        let xml = strip_comments(CONFIG);
        let offers = offers(&xml, "incomingServer", "imap", "jo@example.org");
        let kinds: Vec<_> = offers
            .iter()
            .map(|offer| (offer.server.host.as_str(), offer.server.security))
            .collect();
        assert_eq!(
            kinds,
            [
                ("mail.example.org", Security::StartTls),
                ("imap.example.org", Security::Tls)
            ]
        );
    }

    fn config(incoming: &str, outgoing: &str) -> String {
        format!(
            "<clientConfig version=\"1.1\"><emailProvider id=\"x\">{incoming}{outgoing}</emailProvider></clientConfig>"
        )
    }

    fn server(tag: &str, kind: &str, host: &str, port: u16, socket: &str, auth: &[&str]) -> String {
        let auth: String = auth
            .iter()
            .map(|method| format!("<authentication>{method}</authentication>"))
            .collect();
        format!(
            "<{tag} type=\"{kind}\"><hostname>{host}</hostname><port>{port}</port>\
             <socketType>{socket}</socketType><username>%EMAILADDRESS%</username>{auth}</{tag}>"
        )
    }

    #[test]
    fn plain_only_and_pop3_only_configs_give_nothing() {
        let plain = config(
            &server("incomingServer", "imap", "imap.x.org", 143, "plain", &[]),
            &server("outgoingServer", "smtp", "smtp.x.org", 25, "plain", &[]),
        );
        assert_eq!(parse(&plain, "a@x.org"), None);
        let pop = config(
            &server("incomingServer", "pop3", "pop.x.org", 995, "SSL", &[]),
            &server("outgoingServer", "smtp", "smtp.x.org", 465, "SSL", &[]),
        );
        assert_eq!(parse(&pop, "a@x.org"), None);
    }

    #[test]
    fn hostile_host_names_are_refused() {
        for host in [
            "imap.x.org\r\nA1 LOGOUT",
            "imap.x.org:993",
            "user@imap.x.org",
            "imap x.org",
            "&lt;script&gt;",
            "",
        ] {
            let xml = config(
                &server("incomingServer", "imap", host, 993, "SSL", &[]),
                &server("outgoingServer", "smtp", "smtp.x.org", 465, "SSL", &[]),
            );
            assert_eq!(parse(&xml, "a@x.org"), None, "{host:?}");
        }
        // A port that is not one.
        let xml = config(
            &server("incomingServer", "imap", "imap.x.org", 0, "SSL", &[]),
            &server("outgoingServer", "smtp", "smtp.x.org", 465, "SSL", &[]),
        );
        assert_eq!(parse(&xml, "a@x.org"), None);
    }

    #[test]
    fn an_oauth_only_config_needs_the_providers_sign_in() {
        let xml = config(
            &server(
                "incomingServer",
                "imap",
                "outlook.office365.com",
                993,
                "SSL",
                &["OAuth2"],
            ),
            &server(
                "outgoingServer",
                "smtp",
                "smtp-mail.outlook.com",
                587,
                "STARTTLS",
                &["OAuth2"],
            ),
        );
        assert_eq!(
            parse(&xml, "a@contoso.com"),
            Some(Found::NeedsOAuth {
                provider: "Microsoft"
            })
        );
        // OAuth2 next to a password is fine.
        let both = config(
            &server(
                "incomingServer",
                "imap",
                "imap.x.org",
                993,
                "SSL",
                &["OAuth2", "password-cleartext"],
            ),
            &server(
                "outgoingServer",
                "smtp",
                "smtp.x.org",
                465,
                "SSL",
                &["OAuth2", "password-cleartext"],
            ),
        );
        assert!(matches!(parse(&both, "a@x.org"), Some(Found::Servers(_))));
        // Fastmail lists only OAuth2 but takes app passwords.
        let fastmail = config(
            &server(
                "incomingServer",
                "imap",
                "imap.fastmail.com",
                993,
                "SSL",
                &["OAuth2"],
            ),
            &server(
                "outgoingServer",
                "smtp",
                "smtp.fastmail.com",
                465,
                "SSL",
                &["OAuth2"],
            ),
        );
        let found = servers(parse(&fastmail, "me@my.family"));
        assert_eq!(found.username, "me@my.family");
        assert_eq!(
            found.imap,
            Server::new("imap.fastmail.com", 993, Security::Tls)
        );
        // Any other provider's name is a generic one.
        let other = config(
            &server(
                "incomingServer",
                "imap",
                "imap.x.org",
                993,
                "SSL",
                &["OAuth2"],
            ),
            &server(
                "outgoingServer",
                "smtp",
                "smtp.x.org",
                465,
                "SSL",
                &["OAuth2"],
            ),
        );
        assert_eq!(
            parse(&other, "a@x.org"),
            Some(Found::NeedsOAuth {
                provider: "your email provider"
            })
        );
    }

    #[test]
    fn other_documents_are_not_configs() {
        assert_eq!(
            parse("<html><body>Not found</body></html>", "a@x.org"),
            None
        );
        assert_eq!(parse("", "a@x.org"), None);
    }
}
