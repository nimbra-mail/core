//! Brand logos (BIMI): a sender's logo instead of their initials, for mail that passed
//! DMARC (`Summary::brand_domain`) from a domain whose DMARC policy is enforced.
//!
//! The logo is the SVG named by the domain's BIMI record (`default._bimi.<domain>`). There
//! is no check of a Verified Mark Certificate: any domain with an enforced policy shows its
//! own logo, so the sender's address stays beside it. What is looked up and fetched is per
//! domain, never per message, and kept in the store: the brand's server learns that it was
//! asked, not when or how often its mail was read.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

/// The most a logo may be: BIMI's own limit for its SVGs.
pub const MAX_LOGO: usize = 32 * 1024;
/// How long a found logo, or that there is none, is kept before it is looked up again.
const KEEP_LOGO: Duration = Duration::from_secs(7 * 24 * 60 * 60);
const KEEP_NONE: Duration = Duration::from_secs(24 * 60 * 60);
const TIMEOUT: Duration = Duration::from_secs(10);

/// What the store keeps for a domain.
#[derive(Clone, Serialize, Deserialize)]
struct Kept {
    /// When it was looked up, in ms since the epoch.
    at_ms: u64,
    /// The SVG, or none (no record, no enforced policy, or a logo that wasn't one).
    svg: Option<Vec<u8>>,
}

/// The domain's logo (an SVG), from the store or else looked up and kept: `None` when it
/// has none to show. Errors (offline, a resolver that doesn't answer) are not kept, so the
/// next look tries again. Blocking (DNS and network on a miss).
pub fn logo(store: &crate::store::Store, domain: &str) -> Result<Option<Vec<u8>>> {
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    let name = record_name(&domain)?;
    let now = now_ms();
    if let Some(kept) = store.load::<Kept>(&name) {
        let keep = if kept.svg.is_some() {
            KEEP_LOGO
        } else {
            KEEP_NONE
        };
        if now.saturating_sub(kept.at_ms) < keep.as_millis() as u64 {
            return Ok(kept.svg);
        }
    }
    let svg = match logo_url(&domain)? {
        Some(url) => fetch(&url)?,
        None => None,
    };
    store.save(
        &name,
        &Kept {
            at_ms: now,
            svg: svg.clone(),
        },
    )?;
    Ok(svg)
}

/// The store record a domain's logo is kept under: named by a hash of the domain, as
/// record names are short and plain (and the store's file names then don't spell out who
/// writes to you).
fn record_name(domain: &str) -> Result<String> {
    use sha2::{Digest, Sha256};
    if domain.is_empty()
        || domain.len() > 253
        || !domain
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        || !domain.contains('.')
    {
        bail!("not a domain name");
    }
    let digest = Sha256::digest(domain.as_bytes());
    let hex: String = digest[..16].iter().map(|b| format!("{b:02x}")).collect();
    Ok(format!("bimi-{hex}"))
}

/// The logo's address when `domain` has an enforced DMARC policy and a BIMI record with
/// one. Blocking (DNS).
fn logo_url(domain: &str) -> Result<Option<String>> {
    if !first_found(domain, "_dmarc", enforced)?.unwrap_or(false) {
        return Ok(None);
    }
    Ok(first_found(domain, "default._bimi", bimi_url)?.flatten())
}

/// The first of `domain` and its parent domains (not past two labels) with a record under
/// `prefix` that `read` makes sense of: as DMARC and BIMI fall back to the organisation's
/// domain when a subdomain has none of its own.
fn first_found<T>(
    domain: &str,
    prefix: &str,
    read: impl Fn(&str) -> Option<T>,
) -> Result<Option<T>> {
    for name in lookups(domain) {
        let records = crate::dns::txt(&format!("{prefix}.{name}"))?;
        if let Some(found) = records.iter().find_map(|record| read(record)) {
            return Ok(Some(found));
        }
    }
    Ok(None)
}

/// `domain`, then each parent down to its last two labels.
fn lookups(domain: &str) -> Vec<String> {
    let labels: Vec<&str> = domain.split('.').collect();
    (0..labels.len().saturating_sub(1))
        .map(|from| labels[from..].join("."))
        .collect()
}

/// The tags of a `v=…; a=…` record, by name in lowercase.
fn tags(record: &str) -> Vec<(String, String)> {
    record
        .split(';')
        .filter_map(|tag| tag.split_once('='))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_string()))
        .collect()
}

/// For a DMARC record: whether its policy is enforced (quarantine or reject, on all of the
/// mail). `None` for anything that isn't a DMARC record.
fn enforced(record: &str) -> Option<bool> {
    let tags = tags(record);
    let value = |name: &str| {
        tags.iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    };
    if !value("v")?.eq_ignore_ascii_case("DMARC1") {
        return None;
    }
    let policy = value("p").unwrap_or("").to_ascii_lowercase();
    let all = value("pct").is_none_or(|pct| pct == "100");
    Some(matches!(policy.as_str(), "quarantine" | "reject") && all)
}

/// For a BIMI record: its logo's https address, or `Some(None)` when it has none (an empty
/// `l=`, the way a domain says it shows no logo). `None` for anything that isn't one.
fn bimi_url(record: &str) -> Option<Option<String>> {
    let tags = tags(record);
    let value = |name: &str| {
        tags.iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    };
    if !value("v")?.eq_ignore_ascii_case("BIMI1") {
        return None;
    }
    let url = value("l").unwrap_or("").trim();
    Some(
        (url.starts_with("https://") && url.len() <= 2048 && !url.contains(char::is_whitespace))
            .then(|| url.to_string()),
    )
}

/// The logo at `url`: over https only, no larger than `MAX_LOGO`, and an SVG document
/// with no scripts or embedded HTML (it is drawn by resvg, which runs no scripts and loads
/// nothing, but what isn't a plain logo isn't kept either). Blocking (network).
fn fetch(url: &str) -> Result<Option<Vec<u8>>> {
    use std::io::Read;
    let agent = ureq::AgentBuilder::new()
        .https_only(true)
        .redirects(3)
        .timeout(TIMEOUT)
        .build();
    let response = match agent.get(url).call() {
        Ok(response) => response,
        // The server answered, with an error: it has no logo to give.
        Err(ureq::Error::Status(..)) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let mut bytes = Vec::new();
    response
        .into_reader()
        .take(MAX_LOGO as u64 + 1)
        .read_to_end(&mut bytes)?;
    Ok(is_plain_svg(&bytes).then_some(bytes))
}

/// An SVG document small enough, with nothing in it but drawing.
fn is_plain_svg(bytes: &[u8]) -> bool {
    if bytes.is_empty() || bytes.len() > MAX_LOGO {
        return false;
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    let lower = text.to_ascii_lowercase();
    let start = lower.trim_start_matches('\u{feff}').trim_start();
    (start.starts_with("<svg") || start.starts_with("<?xml"))
        && lower.contains("<svg")
        && ![
            "<script",
            "<foreignobject",
            "javascript:",
            "<iframe",
            "<!entity",
        ]
        .iter()
        .any(|bad| lower.contains(bad))
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bimi_records_give_an_https_logo_or_none() {
        assert_eq!(
            bimi_url("v=BIMI1; l=https://github.com/logo.svg; a=https://x/vmc.pem"),
            Some(Some("https://github.com/logo.svg".into()))
        );
        // Declined: the record says there is no logo.
        assert_eq!(bimi_url("v=BIMI1; l=;"), Some(None));
        // Only over https.
        assert_eq!(bimi_url("v=BIMI1; l=http://x.com/l.svg"), Some(None));
        // Not BIMI at all.
        assert_eq!(bimi_url("v=spf1 include:_spf.google.com ~all"), None);
        assert_eq!(bimi_url("google-site-verification=abc"), None);
    }

    #[test]
    fn only_an_enforced_dmarc_policy_counts() {
        assert_eq!(
            enforced("v=DMARC1; p=reject; rua=mailto:x@y.com"),
            Some(true)
        );
        assert_eq!(enforced("v=DMARC1; p=quarantine; pct=100"), Some(true));
        assert_eq!(enforced("v=DMARC1; p=quarantine; pct=50"), Some(false));
        assert_eq!(enforced("v=DMARC1; p=none"), Some(false));
        assert_eq!(enforced("v=DMARC1"), Some(false));
        assert_eq!(enforced("v=spf1 -all"), None);
    }

    #[test]
    fn subdomains_fall_back_to_their_parents_not_past_two_labels() {
        assert_eq!(
            lookups("mail.notifications.github.com"),
            [
                "mail.notifications.github.com",
                "notifications.github.com",
                "github.com"
            ]
        );
        assert_eq!(lookups("github.com"), ["github.com"]);
        assert!(lookups("com").is_empty());
    }

    #[test]
    fn only_a_plain_svg_is_kept() {
        let logo = br#"<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 10 10"><title>X</title><rect width="10" height="10"/></svg>"#;
        assert!(is_plain_svg(logo));
        assert!(is_plain_svg(
            format!(
                "<?xml version=\"1.0\"?>\n{}",
                std::str::from_utf8(logo).unwrap()
            )
            .as_bytes()
        ));
        for bad in [
            &b"<svg><script>alert(1)</script></svg>"[..],
            b"<svg><foreignObject><div/></foreignObject></svg>",
            b"<svg><a href=\"javascript:x()\"/></svg>",
            b"<!DOCTYPE svg [<!ENTITY x SYSTEM \"file:///etc/passwd\">]><svg/>",
            b"<html><body>not a logo</body></html>",
            b"",
        ] {
            assert!(!is_plain_svg(bad), "{}", String::from_utf8_lossy(bad));
        }
        let huge = format!("<svg>{}</svg>", "x".repeat(MAX_LOGO));
        assert!(!is_plain_svg(huge.as_bytes()));
    }

    #[test]
    fn a_kept_logo_is_used_without_looking_it_up_again() {
        let store = crate::store::Store::temp();
        let svg = b"<svg/>".to_vec();
        store
            .save(
                &record_name("github.com").unwrap(),
                &Kept {
                    at_ms: now_ms(),
                    svg: Some(svg.clone()),
                },
            )
            .unwrap();
        // No DNS or network here: it comes from the store.
        assert_eq!(logo(&store, "GitHub.com.").unwrap(), Some(svg));
        assert!(logo(&store, "not a domain").is_err());
    }
}
