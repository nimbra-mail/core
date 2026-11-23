//! Microsoft accounts (Outlook.com, Hotmail, Live, Microsoft 365): OAuth sign-in in the
//! browser, the refresh token in the keychain, and fresh access tokens for IMAP and SMTP
//! (XOAUTH2). The mail itself goes through `imap_mail.rs` and `smtp.rs` like any other
//! account with its own servers.
//!
//! Everything here is blocking and UI-agnostic; the app calls it from a background thread.
//!
//! Security notes:
//! - Nimbra is a public client: there is no client secret. Sign-in is the OAuth
//!   authorization code flow with PKCE (S256) and a random `state`, redirecting to a
//!   listener on the loopback addresses only (127.0.0.1 and ::1, one port).
//! - Only the expected path with the expected `state` is taken from the browser; anything
//!   else is answered with 404 and ignored.
//! - The refresh token lives in the OS keychain, under its account's id. Microsoft hands out
//!   a new one with each renewal, and the new one replaces it there. Access tokens stay in
//!   memory.
//! - Tokens are never logged or put into error messages.
//! - The address is read from the ID token without checking its signature: it came straight
//!   from Microsoft's token endpoint over TLS, and it is only used to name the account and
//!   sign in to its own mailbox, which Microsoft checks again.

use std::io::{BufRead, BufReader};
use std::net::{TcpListener, TcpStream};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context as _, Result, anyhow, bail};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;

use crate::gmail::{oauth_setting, pkce_challenge, random_token, respond};
use crate::mail::{Offline, SignedOut, is_account_id, is_address, sanitize};
use crate::servers::{Security, Server, Servers};

const AUTH_URL: &str = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize";
const TOKEN_URL: &str = "https://login.microsoftonline.com/common/oauth2/v2.0/token";
/// IMAP and SMTP for the mailbox, a refresh token, and the address (in the ID token).
const SCOPE: &str = "https://outlook.office.com/IMAP.AccessAsUser.All \
                     https://outlook.office.com/SMTP.Send offline_access openid email profile";
/// What `AccountRef.oauth` says for an account that signs in here.
pub const PROVIDER: &str = "microsoft";

const KEYCHAIN_SERVICE: &str = "nimbra";
const KEYCHAIN_USER: &str = "microsoft-refresh-token";
const SIGN_IN_TIMEOUT: Duration = Duration::from_secs(300);
const HTTP_TIMEOUT: Duration = Duration::from_secs(20);

/// Every Microsoft mailbox reads and sends through the same two servers.
pub fn servers(email: &str) -> Servers {
    Servers {
        username: email.to_string(),
        imap: Server::new("outlook.office365.com", 993, Security::Tls),
        smtp: Server::new("smtp.office365.com", 587, Security::StartTls),
    }
}

// ------------------------------------------------------------------ config

#[derive(Clone)]
pub struct Config {
    client_id: String,
}

impl Config {
    /// Reads the app's client id from `NIMBRA_MICROSOFT_CLIENT_ID` (the environment, then
    /// `~/.config/nimbra/oauth.env`). `None` when it is not there or not a GUID.
    pub fn load() -> Option<Self> {
        Self::new(&oauth_setting("NIMBRA_MICROSOFT_CLIENT_ID")?)
    }

    fn new(client_id: &str) -> Option<Self> {
        let client_id = client_id.trim();
        if !is_guid(client_id) {
            eprintln!("nimbra: NIMBRA_MICROSOFT_CLIENT_ID is not a GUID, so it is not used");
            return None;
        }
        Some(Self {
            client_id: client_id.to_ascii_lowercase(),
        })
    }
}

/// `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`, in hex digits.
fn is_guid(text: &str) -> bool {
    let groups: Vec<&str> = text.split('-').collect();
    groups.len() == 5
        && groups
            .iter()
            .zip([8, 4, 4, 4, 12])
            .all(|(group, len)| group.len() == len && group.chars().all(|c| c.is_ascii_hexdigit()))
}

// ------------------------------------------------------------------ keychain

fn keychain(account: &str) -> Result<keyring::Entry> {
    if account.is_empty() || !is_account_id(account) {
        bail!("unexpected account id");
    }
    keyring::Entry::new(KEYCHAIN_SERVICE, &format!("{KEYCHAIN_USER}-{account}"))
        .context("opening the system keychain")
}

/// The saved sign-in: `None` when there is none. A keychain that cannot be read (denied,
/// locked) is an error, which is not being signed out.
pub fn stored_refresh_token(account: &str) -> Result<Option<String>> {
    match keychain(account)?.get_password() {
        Ok(token) => Ok(Some(token)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(error) => Err(error).context("reading the sign-in from the system keychain"),
    }
}

fn store_refresh_token(account: &str, token: &str) -> Result<()> {
    keychain(account)?
        .set_password(token)
        .context("saving the sign-in to the system keychain")
}

pub fn forget_refresh_token(account: &str) {
    if let Ok(entry) = keychain(account) {
        let _ = entry.delete_credential();
    }
}

// ------------------------------------------------------------------ tokens

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(deserialize_with = "seconds")]
    expires_in: u64,
    refresh_token: Option<String>,
    id_token: Option<String>,
}

/// A number of seconds, as a number or (older endpoints) as text.
fn seconds<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Seconds {
        Number(u64),
        Text(String),
    }
    match Seconds::deserialize(deserializer)? {
        Seconds::Number(n) => Ok(n),
        Seconds::Text(text) => text.trim().parse().map_err(serde::de::Error::custom),
    }
}

/// Microsoft's answer to a token request that worked. Its text is never put in an error.
fn parse_token_reply(body: &str) -> Result<TokenResponse> {
    let reply: TokenResponse = serde_json::from_str(body)
        .map_err(|_| anyhow!("Microsoft's token reply was not readable"))?;
    if reply.access_token.is_empty() {
        bail!("Microsoft did not return a sign-in");
    }
    Ok(reply)
}

/// A refused token request, as an error: `invalid_grant` (the sign-in was revoked, expired
/// or its password changed) is `SignedOut`; anything else names only Microsoft's code.
fn token_error(status: u16, body: &str) -> anyhow::Error {
    #[derive(Deserialize, Default)]
    struct OAuthError {
        #[serde(default)]
        error: String,
    }
    let error = serde_json::from_str::<OAuthError>(body)
        .unwrap_or_default()
        .error;
    if error == "invalid_grant" {
        return SignedOut {
            account: String::new(),
        }
        .into();
    }
    match sanitize(&error) {
        code if code.is_empty() => anyhow!("Microsoft refused the sign-in ({status})"),
        code => anyhow!("Microsoft refused the sign-in ({status} {code})"),
    }
}

fn token_request(form: &[(&str, &str)]) -> Result<TokenResponse> {
    match ureq::post(TOKEN_URL).timeout(HTTP_TIMEOUT).send_form(form) {
        Ok(response) => {
            let body = response
                .into_string()
                .map_err(|_| anyhow!(Offline).context("reading Microsoft's token reply"))?;
            parse_token_reply(&body)
        }
        Err(ureq::Error::Status(code, response)) => Err(token_error(
            code,
            &response.into_string().unwrap_or_default(),
        )),
        Err(_) => Err(Offline.into()),
    }
}

/// The address the ID token is for: its `email`, else its `preferred_username`, whichever
/// is an address. Its signature is not checked (see the module notes).
fn address_from_id_token(id_token: &str) -> Result<String> {
    let unreadable = || anyhow!("Microsoft did not say which address signed in.");
    let mut parts = id_token.split('.');
    let (Some(_), Some(payload), Some(_), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(unreadable());
    };
    let bytes = URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .map_err(|_| unreadable())?;
    #[derive(Deserialize)]
    struct Claims {
        email: Option<String>,
        preferred_username: Option<String>,
    }
    let claims: Claims = serde_json::from_slice(&bytes).map_err(|_| unreadable())?;
    [claims.email, claims.preferred_username]
        .into_iter()
        .flatten()
        .map(|address| address.trim().to_string())
        .find(|address| is_address(address))
        .ok_or_else(unreadable)
}

/// A Microsoft sign-in: hands out an access token for IMAP and SMTP, renewing it a minute
/// before it runs out. Shared by the account's connections (its IDLE thread too).
pub struct Tokens {
    config: Config,
    /// Which account's keychain entry holds the refresh token. Empty while the sign-in is
    /// not yet any account's (nothing is saved then).
    account: String,
    /// The long-lived sign-in. Held while renewing, so that two connections never renew at
    /// once and the one Microsoft hands back is never lost.
    refresh: Mutex<String>,
    /// The access token and when it is over, by the wall clock: an `Instant` stands still
    /// while the Mac sleeps, and the token does not.
    access: Mutex<Option<(String, SystemTime)>>,
}

impl Tokens {
    pub fn new(config: Config, refresh_token: String, account: String) -> Self {
        Tokens {
            config,
            account,
            refresh: Mutex::new(refresh_token),
            access: Mutex::new(None),
        }
    }

    fn remember(&self, access_token: &str, expires_in: u64) {
        // Renewed a minute early so a token never runs out mid-command.
        let expiry = SystemTime::now() + Duration::from_secs(expires_in.saturating_sub(60));
        *self.access.lock().unwrap() = Some((access_token.to_string(), expiry));
    }

    fn cached(&self) -> Option<String> {
        let access = self.access.lock().unwrap();
        let (token, expiry) = access.as_ref()?;
        (SystemTime::now() < *expiry).then(|| token.clone())
    }

    /// Takes a renewal's answer: the access token, and the new refresh token when it is
    /// another one (which is then returned, to be saved).
    fn take(&self, refresh: &mut String, reply: &TokenResponse) -> Option<String> {
        self.remember(&reply.access_token, reply.expires_in);
        let new = reply
            .refresh_token
            .as_ref()
            .filter(|new| !new.is_empty() && new.as_str() != refresh.as_str())?;
        refresh.clone_from(new);
        Some(new.clone())
    }

    /// An access token that is good for at least a minute. `SignedOut` (for this account)
    /// when Microsoft has ended the sign-in; its refresh token is forgotten then.
    pub fn access_token(&self) -> Result<String> {
        if let Some(token) = self.cached() {
            return Ok(token);
        }
        let mut refresh = self.refresh.lock().unwrap();
        // Renewed by another connection while this one waited.
        if let Some(token) = self.cached() {
            return Ok(token);
        }
        let reply = token_request(&[
            ("client_id", &self.config.client_id),
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh.as_str()),
            ("scope", SCOPE),
        ])
        .map_err(|error| {
            if !error.is::<SignedOut>() {
                return error;
            }
            forget_refresh_token(&self.account);
            SignedOut {
                account: self.account.clone(),
            }
            .into()
        })?;
        if let Some(new) = self.take(&mut refresh, &reply)
            && !self.account.is_empty()
            && store_refresh_token(&self.account, &new).is_err()
        {
            // The old one still works for a while; this one is kept in memory meanwhile.
            eprintln!("nimbra: could not save the renewed Microsoft sign-in");
        }
        Ok(reply.access_token)
    }

    /// Drops an access token a server refused, unless another thread has put a newer one in
    /// its place, so the next one asked for is new.
    pub fn forget_access(&self, refused: &str) {
        let mut access = self.access.lock().unwrap();
        if access.as_ref().is_some_and(|(token, _)| token == refused) {
            *access = None;
        }
    }

    /// The same sign-in as `account`'s: its refresh token saved in the keychain for it.
    pub fn saved_as(&self, account: &str) -> Result<Tokens> {
        let refresh = self.refresh.lock().unwrap().clone();
        store_refresh_token(account, &refresh)?;
        Ok(Tokens {
            config: self.config.clone(),
            account: account.to_string(),
            refresh: Mutex::new(refresh),
            access: Mutex::new(self.access.lock().unwrap().clone()),
        })
    }
}

// ------------------------------------------------------------------ sign-in

/// The sign-in page's address, with everything it needs and no secret.
fn authorize_url(
    config: &Config,
    redirect_uri: &str,
    verifier: &str,
    state: &str,
    hint: Option<&str>,
) -> Result<String> {
    let mut url = url::Url::parse_with_params(
        AUTH_URL,
        &[
            ("client_id", config.client_id.as_str()),
            ("response_type", "code"),
            ("redirect_uri", redirect_uri),
            ("response_mode", "query"),
            ("scope", SCOPE),
            ("state", state),
            ("code_challenge", pkce_challenge(verifier).as_str()),
            ("code_challenge_method", "S256"),
            ("prompt", "select_account"),
        ],
    )?;
    if let Some(hint) = hint.filter(|h| is_address(h)) {
        url.query_pairs_mut().append_pair("login_hint", hint);
    }
    Ok(url.into())
}

/// What one request to the loopback listener was.
#[derive(Debug, PartialEq)]
enum Redirect {
    /// Not the redirect (another path, a wrong `state`, a favicon): answered 404, ignored.
    Ignore,
    Code(String),
    /// Microsoft sent the user back with an error.
    Failed(String),
}

/// Reads the redirect from an HTTP request line (`GET /?code=…&state=… HTTP/1.1`).
fn redirect(request_line: &str, state: &str) -> Redirect {
    let Some(target) = request_line
        .strip_prefix("GET ")
        .and_then(|rest| rest.split_whitespace().next())
    else {
        return Redirect::Ignore;
    };
    let Ok(url) = url::Url::parse(&format!("http://localhost{target}")) else {
        return Redirect::Ignore;
    };
    let param = |name: &str| {
        url.query_pairs()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.into_owned())
    };
    if url.path() != "/" || param("state").as_deref() != Some(state) {
        return Redirect::Ignore;
    }
    if let Some(error) = param("error") {
        return Redirect::Failed(if error == "access_denied" {
            "Sign-in was cancelled.".to_string()
        } else {
            format!("Microsoft reported: {}", sanitize(&error))
        });
    }
    match param("code").filter(|code| !code.is_empty()) {
        Some(code) => Redirect::Code(code),
        None => Redirect::Ignore,
    }
}

/// A sign-in in progress: the browser has been pointed at Microsoft, and the listeners wait
/// for it to come back.
pub struct SignIn {
    /// 127.0.0.1 and, where it could be had on the same port, ::1: "localhost" can be
    /// either in the browser.
    listeners: Vec<TcpListener>,
    redirect_uri: String,
    verifier: String,
    state: String,
}

/// Both loopback addresses on one port picked by the OS. IPv4 alone when ::1 cannot be
/// had (no IPv6, or that port taken there after a few tries).
fn loopback() -> Result<Vec<TcpListener>> {
    for _ in 0..5 {
        let v4 = TcpListener::bind(("127.0.0.1", 0)).context("opening a local port for sign-in")?;
        let port = v4.local_addr()?.port();
        match TcpListener::bind(("::1", port)) {
            Ok(v6) => return Ok(vec![v4, v6]),
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => continue,
            Err(_) => return Ok(vec![v4]),
        }
    }
    Ok(vec![
        TcpListener::bind(("127.0.0.1", 0)).context("opening a local port for sign-in")?,
    ])
}

impl SignIn {
    /// Starts listening and returns the URL to open in the browser. `hint` (an address)
    /// is filled in on Microsoft's page.
    pub fn start(config: &Config, hint: Option<&str>) -> Result<(Self, String)> {
        let listeners = loopback()?;
        for listener in &listeners {
            listener.set_nonblocking(true)?;
        }
        // The app's registration has `http://localhost`, which takes any port.
        let redirect_uri = format!("http://localhost:{}", listeners[0].local_addr()?.port());
        let verifier = random_token()?;
        let state = random_token()?;
        let url = authorize_url(config, &redirect_uri, &verifier, &state, hint)?;
        Ok((
            Self {
                listeners,
                redirect_uri,
                verifier,
                state,
            },
            url,
        ))
    }

    /// Blocks until the browser comes back (or the timeout passes) and exchanges the code.
    /// Returns the address that signed in and its sign-in, which is not saved anywhere yet
    /// (see `Tokens::saved_as`).
    pub fn finish(self, config: &Config) -> Result<(String, Tokens)> {
        let code = self.wait_for_code()?;
        let reply = token_request(&[
            ("client_id", &config.client_id),
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", &self.redirect_uri),
            ("code_verifier", &self.verifier),
            ("scope", SCOPE),
        ])?;
        let email = address_from_id_token(reply.id_token.as_deref().unwrap_or_default())?;
        let refresh = reply
            .refresh_token
            .clone()
            .filter(|r| !r.is_empty())
            .ok_or_else(|| anyhow!("Microsoft did not return a long-lived sign-in"))?;
        let tokens = Tokens::new(config.clone(), refresh, String::new());
        tokens.remember(&reply.access_token, reply.expires_in);
        Ok((email, tokens))
    }

    fn wait_for_code(&self) -> Result<String> {
        let deadline = Instant::now() + SIGN_IN_TIMEOUT;
        loop {
            if Instant::now() > deadline {
                bail!("Sign-in timed out. Please try again.");
            }
            let mut waiting = true;
            for listener in &self.listeners {
                let stream = match listener.accept() {
                    Ok((stream, _)) => stream,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                    Err(e) => return Err(e).context("waiting for the browser"),
                };
                waiting = false;
                // Anything that is not our redirect is answered and ignored.
                if let Some(result) = self.handle(stream) {
                    return result;
                }
            }
            if waiting {
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }

    fn handle(&self, stream: TcpStream) -> Option<Result<String>> {
        stream.set_nonblocking(false).ok()?;
        stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
        let mut request_line = String::new();
        // At most 8 KB of the request line.
        BufReader::new(std::io::Read::take(&stream, 8 * 1024))
            .read_line(&mut request_line)
            .ok()?;
        match redirect(&request_line, &self.state) {
            Redirect::Ignore => {
                respond(&stream, "404 Not Found", "Not found.");
                None
            }
            Redirect::Failed(reason) => {
                respond(
                    &stream,
                    "200 OK",
                    "Sign-in was cancelled. You can close this tab.",
                );
                Some(Err(anyhow!(reason)))
            }
            Redirect::Code(code) => {
                respond(
                    &stream,
                    "200 OK",
                    "Nimbra is connected. You can close this tab and return to the app.",
                );
                Some(Ok(code))
            }
        }
    }
}

/// Refuses a sign-in to another account than the one it was started for.
pub fn check_same_account(expected: &str, signed_in: &str) -> Result<()> {
    if !expected.eq_ignore_ascii_case(signed_in) {
        bail!("That was another Microsoft account, so nothing was changed. Choose {expected}.");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    const ID: &str = "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0";

    fn config() -> Config {
        Config::new(ID).unwrap()
    }

    #[test]
    fn only_a_guid_is_a_client_id() {
        assert!(is_guid(ID));
        assert!(is_guid("0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0"));
        // Kept lower case, without the spaces around it.
        assert_eq!(
            Config::new(" 0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0 ")
                .unwrap()
                .client_id,
            ID
        );
        for bad in [
            "",
            "0f1e2d3c4b5a69788796a5b4c3d2e1f0",
            "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f",
            "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0-",
            "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1fg",
            "{0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0}",
            "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0&x=1",
            "0f1e2d3c-4b5a-6978-879-6a5b4c3d2e1f0",
        ] {
            assert!(!is_guid(bad), "{bad:?}");
            assert!(Config::new(bad).is_none());
        }
    }

    #[test]
    fn the_sign_in_page_gets_every_parameter_and_no_secret() {
        let verifier = "v".repeat(43);
        let url = authorize_url(
            &config(),
            "http://localhost:51234",
            &verifier,
            "st&ate=1",
            Some("ana+x@outlook.com"),
        )
        .unwrap();
        assert!(url.starts_with(AUTH_URL));
        assert!(!url.contains(' ') && !url.contains("secret"), "{url}");
        let parsed = url::Url::parse(&url).unwrap();
        let params: Vec<(String, String)> = parsed.query_pairs().into_owned().collect();
        let get = |name: &str| {
            let found: Vec<&String> = params
                .iter()
                .filter(|(k, _)| k == name)
                .map(|(_, v)| v)
                .collect();
            assert_eq!(found.len(), 1, "{name}");
            found[0].clone()
        };
        assert_eq!(get("client_id"), ID);
        assert_eq!(get("response_type"), "code");
        assert_eq!(get("redirect_uri"), "http://localhost:51234");
        assert_eq!(get("response_mode"), "query");
        assert_eq!(get("scope"), SCOPE);
        assert!(get("scope").contains("IMAP.AccessAsUser.All"));
        assert!(get("scope").contains("offline_access"));
        // Encoded, so it cannot add a parameter of its own.
        assert_eq!(get("state"), "st&ate=1");
        assert_eq!(get("code_challenge"), pkce_challenge(&verifier));
        assert_eq!(get("code_challenge_method"), "S256");
        assert_eq!(get("prompt"), "select_account");
        assert_eq!(get("login_hint"), "ana+x@outlook.com");
        assert_eq!(params.len(), 10);

        // No hint, or one that is not an address: none given.
        for hint in [None, Some("not an address&prompt=none")] {
            let url = authorize_url(&config(), "http://localhost:1", "v", "s", hint).unwrap();
            assert!(!url.contains("login_hint"), "{url}");
            assert_eq!(url.matches("prompt=").count(), 1);
        }
    }

    fn id_token(claims: &str) -> String {
        format!(
            "eyJhbGciOiJSUzI1NiJ9.{}.c2lnbmF0dXJl",
            URL_SAFE_NO_PAD.encode(claims)
        )
    }

    #[test]
    fn the_address_comes_from_the_id_token() {
        let both = id_token(
            r#"{"email":"Ana@Outlook.com","preferred_username":"ana@contoso.onmicrosoft.com"}"#,
        );
        assert_eq!(address_from_id_token(&both).unwrap(), "Ana@Outlook.com");
        let upn = id_token(r#"{"preferred_username":"ana@contoso.com","name":"Ana"}"#);
        assert_eq!(address_from_id_token(&upn).unwrap(), "ana@contoso.com");
        // An `email` that is not an address gives way to the user name.
        let odd = id_token(r#"{"email":"","preferred_username":"ana@contoso.com"}"#);
        assert_eq!(address_from_id_token(&odd).unwrap(), "ana@contoso.com");
        for garbage in [
            String::new(),
            "abc".to_string(),
            "a.b".to_string(),
            "a.!!!.c".to_string(),
            id_token("not json"),
            id_token(r#"{"name":"Ana"}"#),
            id_token(r#"{"preferred_username":"+15551234567"}"#),
            id_token(r#"{"email":"ana@outlook.com\r\nBcc: x@y.z"}"#),
            format!("{}.extra", id_token(r#"{"email":"ana@outlook.com"}"#)),
        ] {
            assert!(address_from_id_token(&garbage).is_err(), "{garbage:?}");
        }
    }

    #[test]
    fn token_replies_are_read_and_a_new_refresh_token_replaces_the_old() {
        let reply = parse_token_reply(
            r#"{"token_type":"Bearer","scope":"x","expires_in":3599,"ext_expires_in":3599,
                "access_token":"EwA1","refresh_token":"M.R2","id_token":"a.b.c"}"#,
        )
        .unwrap();
        assert_eq!(reply.expires_in, 3599);
        assert_eq!(reply.id_token.as_deref(), Some("a.b.c"));
        // Seconds as text, and no refresh token.
        let quoted = parse_token_reply(r#"{"access_token":"EwA2","expires_in":"3600"}"#).unwrap();
        assert_eq!(quoted.expires_in, 3600);
        assert!(quoted.refresh_token.is_none());
        for bad in ["", "{}", r#"{"access_token":"","expires_in":1}"#, "<html>"] {
            let error = parse_token_reply(bad).err().expect(bad);
            assert!(!error.to_string().contains("html"));
        }

        let tokens = Tokens::new(config(), "M.R1".into(), String::new());
        let mut refresh = tokens.refresh.lock().unwrap();
        // Rotated: the new one is handed back to be saved, and used from now on.
        assert_eq!(tokens.take(&mut refresh, &reply).as_deref(), Some("M.R2"));
        assert_eq!(*refresh, "M.R2");
        // The same one again, or none: nothing to save.
        assert_eq!(tokens.take(&mut refresh, &reply), None);
        assert_eq!(tokens.take(&mut refresh, &quoted), None);
        assert_eq!(*refresh, "M.R2");
        drop(refresh);
        assert_eq!(tokens.cached().as_deref(), Some("EwA2"));
        // A refused token is dropped; a newer one is not.
        tokens.forget_access("EwA1");
        assert_eq!(tokens.cached().as_deref(), Some("EwA2"));
        tokens.forget_access("EwA2");
        assert_eq!(tokens.cached(), None);
        // One that runs out within the minute is not handed out.
        tokens.remember("EwA3", 30);
        assert_eq!(tokens.cached(), None);
    }

    #[test]
    fn an_ended_sign_in_is_signed_out_and_other_refusals_say_little() {
        let error = token_error(
            400,
            r#"{"error":"invalid_grant","error_description":"AADSTS70008: expired"}"#,
        );
        assert!(error.is::<SignedOut>());
        let error = token_error(401, r#"{"error":"invalid_client","error_description":"x"}"#);
        assert!(!error.is::<SignedOut>());
        assert_eq!(
            error.to_string(),
            "Microsoft refused the sign-in (401 invalid_client)"
        );
        let error = token_error(500, "<html>\r\nsecret</html>");
        assert_eq!(error.to_string(), "Microsoft refused the sign-in (500)");
    }

    #[test]
    fn only_the_expected_redirect_is_taken() {
        let state = "abcDEF_123-x";
        let get = |target: &str| redirect(&format!("GET {target} HTTP/1.1\r\n"), state);
        assert_eq!(
            get("/?code=M.C1&state=abcDEF_123-x"),
            Redirect::Code("M.C1".into())
        );
        // Wrong state, none, wrong path, not a GET, no code.
        for ignored in [
            "/?code=M.C1&state=other",
            "/?code=M.C1",
            "/favicon.ico",
            "/callback?code=M.C1&state=abcDEF_123-x",
            "/?state=abcDEF_123-x",
            "/?code=&state=abcDEF_123-x",
        ] {
            assert_eq!(get(ignored), Redirect::Ignore, "{ignored}");
        }
        assert_eq!(
            redirect("POST /?code=M.C1&state=abcDEF_123-x HTTP/1.1", state),
            Redirect::Ignore
        );
        assert_eq!(redirect("", state), Redirect::Ignore);
        // An error with the right state ends the wait; with another, it is ignored.
        assert_eq!(
            get("/?error=access_denied&error_description=x&state=abcDEF_123-x"),
            Redirect::Failed("Sign-in was cancelled.".into())
        );
        assert_eq!(
            get("/?error=server_error%0D%0A<b>&state=abcDEF_123-x"),
            Redirect::Failed("Microsoft reported: server_errorb".into())
        );
        assert_eq!(get("/?error=access_denied&state=nope"), Redirect::Ignore);
    }

    #[test]
    fn the_listener_waits_through_stray_requests_for_the_redirect() {
        let (pending, url) = SignIn::start(&config(), None).unwrap();
        let port: u16 = pending
            .redirect_uri
            .strip_prefix("http://localhost:")
            .unwrap()
            .parse()
            .unwrap();
        assert!(url.contains(&format!("localhost%3A{port}")));
        let state = pending.state.clone();
        let browser = std::thread::spawn(move || {
            let ask = |host: &str, target: &str| {
                let mut stream = TcpStream::connect((host, port)).unwrap();
                write!(stream, "GET {target} HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
                let mut answer = String::new();
                stream.read_to_string(&mut answer).unwrap();
                answer
            };
            assert!(ask("127.0.0.1", "/favicon.ico").starts_with("HTTP/1.1 404"));
            assert!(ask("127.0.0.1", "/?code=x&state=wrong").starts_with("HTTP/1.1 404"));
            // Over IPv6 where this Mac has it, as a browser may try that first.
            let host = if TcpStream::connect(("::1", port)).is_ok() {
                "::1"
            } else {
                "127.0.0.1"
            };
            ask(host, &format!("/?code=M.C9&state={state}"))
        });
        assert_eq!(pending.wait_for_code().unwrap(), "M.C9");
        assert!(browser.join().unwrap().starts_with("HTTP/1.1 200"));
    }

    #[test]
    fn another_account_than_the_one_asked_for_is_refused() {
        assert!(check_same_account("Ana@Outlook.com", "ana@outlook.com").is_ok());
        assert!(check_same_account("ana@outlook.com", "bob@outlook.com").is_err());
    }
}
