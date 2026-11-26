//! What a sign-in brings back when the app runs the browser itself (iOS:
//! `ASWebAuthenticationSession`) and there is no loopback listener: the address it was sent
//! back to, which has to be the redirect that was asked for, with the `state` that was sent.
//!
//! The authorize URL and the code exchange are each provider's (`gmail::Authorization`,
//! `microsoft::Authorization`); this only reads the redirect. The code and the callback
//! address are never logged or put into error messages.

use anyhow::{Result, anyhow, bail};

use crate::mail::sanitize;

/// The authorization code from `callback`, the address the browser came back to. It has to
/// be `redirect_uri` itself (scheme, host, port and path) and carry `state`. `provider`
/// names who sent the user back, in an error ("Google", "Microsoft").
pub fn code(redirect_uri: &str, callback: &str, state: &str, provider: &str) -> Result<String> {
    let expected =
        url::Url::parse(redirect_uri).map_err(|_| anyhow!("The sign-in redirect is not valid."))?;
    let url = url::Url::parse(callback.trim())
        .map_err(|_| anyhow!("The sign-in came back in a form Nimbra does not know."))?;
    let same_place = url.scheme() == expected.scheme()
        && url.host_str() == expected.host_str()
        && url.port_or_known_default() == expected.port_or_known_default()
        && url.path().trim_end_matches('/') == expected.path().trim_end_matches('/');
    if !same_place {
        bail!("The sign-in came back somewhere else, so it was not used. Please try again.");
    }
    let param = |name: &str| {
        url.query_pairs()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.into_owned())
    };
    if param("state").as_deref() != Some(state) {
        bail!("The sign-in did not come back from the request Nimbra made. Please try again.");
    }
    if let Some(error) = param("error") {
        if error == "access_denied" {
            bail!("Sign-in was cancelled.");
        }
        bail!("{provider} reported: {}", sanitize(&error));
    }
    param("code")
        .filter(|code| !code.is_empty())
        .ok_or_else(|| anyhow!("{provider} did not send a sign-in code back. Please try again."))
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOGLE: &str = "com.googleusercontent.apps.123-abc:/oauth2redirect";
    const MICROSOFT: &str = "msauth.me.nimbra.ios://auth";

    #[test]
    fn the_code_comes_back_to_the_redirect_with_its_state() {
        let url = format!("{GOOGLE}?state=s1&code=c0de&scope=x");
        assert_eq!(code(GOOGLE, &url, "s1", "Google").unwrap(), "c0de");
        let url = format!("{MICROSOFT}?code=abc&state=s2");
        assert_eq!(code(MICROSOFT, &url, "s2", "Microsoft").unwrap(), "abc");
    }

    #[test]
    fn another_state_is_refused() {
        let url = format!("{GOOGLE}?state=other&code=c0de");
        assert!(code(GOOGLE, &url, "s1", "Google").is_err());
        let url = format!("{GOOGLE}?code=c0de");
        assert!(code(GOOGLE, &url, "s1", "Google").is_err());
    }

    #[test]
    fn another_place_is_refused() {
        for url in [
            "com.googleusercontent.apps.999-evil:/oauth2redirect?state=s1&code=c",
            "com.googleusercontent.apps.123-abc:/elsewhere?state=s1&code=c",
            "https://example.com/oauth2redirect?state=s1&code=c",
        ] {
            assert!(code(GOOGLE, url, "s1", "Google").is_err(), "{url}");
        }
        assert!(
            code(
                MICROSOFT,
                "msauth.me.nimbra.ios://evil?state=s&code=c",
                "s",
                "M"
            )
            .is_err()
        );
    }

    #[test]
    fn a_cancel_or_an_error_says_so_without_echoing_it_raw() {
        let url = format!("{GOOGLE}?state=s1&error=access_denied");
        let error = code(GOOGLE, &url, "s1", "Google").unwrap_err().to_string();
        assert_eq!(error, "Sign-in was cancelled.");
        let url = format!("{GOOGLE}?state=s1&error=%3Cscript%3E");
        let error = code(GOOGLE, &url, "s1", "Google").unwrap_err().to_string();
        assert!(!error.contains('<'), "{error}");
    }

    #[test]
    fn no_code_is_an_error() {
        let url = format!("{GOOGLE}?state=s1&code=");
        assert!(code(GOOGLE, &url, "s1", "Google").is_err());
    }
}
