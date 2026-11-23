//! Gmail access: OAuth sign-in, Keychain storage and the few REST calls the UI needs.
//!
//! Everything here is blocking and UI-agnostic; the app calls it from a background thread.
//!
//! Security notes:
//! - Sign-in is the OAuth "installed app" flow with PKCE (S256) and a random `state`,
//!   redirecting to a listener bound to 127.0.0.1 only.
//! - The refresh token lives in the OS keychain. Access tokens stay in memory.
//! - Tokens and the client secret are never logged or put into error messages.
//! - HTML mail is converted to text; no remote content is ever fetched.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context as _, Result, anyhow, bail};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::mail::*;
use crate::store::Store;

const AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const API: &str = "https://gmail.googleapis.com/gmail/v1/users/me";
/// Media upload endpoint, for messages with attachments.
const UPLOAD: &str = "https://gmail.googleapis.com/upload/gmail/v1/users/me";
/// Sidebar unread counts stop here (20 pages of thread ids).
const COUNT_CAP: u32 = 10_000;
/// Read, archive and label (no permanent delete), plus the basic profile (name and photo)
/// for the account row.
const SCOPE: &str =
    "https://www.googleapis.com/auth/gmail.modify https://www.googleapis.com/auth/userinfo.profile";
/// Asked for only when the user first deletes something permanently: full mail access.
const FULL_SCOPE: &str = "https://www.googleapis.com/auth/gmail.modify https://www.googleapis.com/auth/userinfo.profile https://mail.google.com/";
/// The signed-in user's basic profile (name and photo address).
const USERINFO: &str = "https://openidconnect.googleapis.com/v1/userinfo";
/// The same person in the People API, which also says whether a photo is their own or the
/// letter Google draws, and has the Workspace profile's as well.
const PEOPLE_ME: &str = "https://people.googleapis.com/v1/people/me";
/// The largest profile photo accepted.
const PHOTO_LIMIT: u64 = 2 * 1024 * 1024;

const KEYCHAIN_SERVICE: &str = "nimbra";
const KEYCHAIN_USER: &str = "gmail-refresh-token";
const SIGN_IN_TIMEOUT: Duration = Duration::from_secs(300);
const HTTP_TIMEOUT: Duration = Duration::from_secs(20);
/// How many pages of the change feed to read before giving up and fetching afresh.
const HISTORY_PAGES: usize = 10;

/// What a request carries.
#[derive(Clone, Copy)]
enum Payload<'a> {
    None,
    Json(&'a serde_json::Value),
    Bytes(&'a [u8]),
}

/// Whether a failed request certainly never left this Mac.
fn never_left(kind: ureq::ErrorKind) -> bool {
    use ureq::ErrorKind as E;
    matches!(
        kind,
        E::Dns
            | E::ConnectionFailed
            | E::InvalidUrl
            | E::UnknownScheme
            | E::InsecureRequestHttpsOnly
            | E::InvalidProxyUrl
            | E::ProxyConnect
            | E::ProxyUnauthorized
    )
}

/// Permanent deletion needs a permission this sign-in does not have yet.
#[derive(Debug)]
pub struct NeedsFullAccess;

impl std::fmt::Display for NeedsFullAccess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Deleting permanently needs one more permission from Google.")
    }
}

impl std::error::Error for NeedsFullAccess {}

// ------------------------------------------------------------------ config

#[derive(Clone)]
pub struct Config {
    client_id: String,
    client_secret: String,
}

impl Config {
    /// Reads the OAuth client from the environment, falling back to
    /// `~/.config/nimbra/oauth.env`. Returns `None` when it is not configured.
    pub fn load() -> Option<Self> {
        let client_id = oauth_setting("NIMBRA_GOOGLE_CLIENT_ID")?;
        let client_secret = oauth_setting("NIMBRA_GOOGLE_CLIENT_SECRET")?;
        Some(Self {
            client_id,
            client_secret,
        })
    }
}

/// One OAuth setting: from the environment, falling back to `~/.config/nimbra/oauth.env`.
/// `None` when it is not there or empty.
pub(crate) fn oauth_setting(key: &str) -> Option<String> {
    let value = std::env::var(key).ok().or_else(|| {
        let file = std::env::var_os("HOME")
            .map(|home| std::path::Path::new(&home).join(".config/nimbra/oauth.env"))
            .and_then(|path| std::fs::read_to_string(path).ok())?;
        file.lines().find_map(|line| {
            let (name, value) = line.split_once('=')?;
            (name.trim() == key).then(|| value.trim().trim_matches('"').to_string())
        })
    })?;
    (!value.is_empty()).then_some(value)
}

// ------------------------------------------------------------------ keychain

fn keychain(account: &str) -> Result<keyring::Entry> {
    if !is_account_id(account) {
        bail!("unexpected account id");
    }
    let user = if account.is_empty() {
        KEYCHAIN_USER.to_string()
    } else {
        format!("{KEYCHAIN_USER}-{account}")
    };
    keyring::Entry::new(KEYCHAIN_SERVICE, &user).context("opening the system keychain")
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

// ------------------------------------------------------------------ oauth

pub(crate) fn random_token() -> Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|e| anyhow!("no secure random source: {e}"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

pub(crate) fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
    refresh_token: Option<String>,
}

fn token_request(form: &[(&str, &str)]) -> Result<TokenResponse> {
    match ureq::post(TOKEN_URL).timeout(HTTP_TIMEOUT).send_form(form) {
        Ok(response) => response.into_json().context("reading Google's token reply"),
        Err(ureq::Error::Status(code, response)) => {
            #[derive(Deserialize, Default)]
            struct OAuthError {
                #[serde(default)]
                error: String,
            }
            let error = response.into_json::<OAuthError>().unwrap_or_default().error;
            if error == "invalid_grant" {
                return Err(SignedOut {
                    account: String::new(),
                }
                .into());
            }
            bail!("Google rejected the sign-in ({code} {error})")
        }
        Err(_) => Err(Offline.into()),
    }
}

/// Refuses a sign-in to another account than the one it was started for.
fn check_same_account(expected: &str, signed_in: &str) -> Result<()> {
    if !expected.eq_ignore_ascii_case(signed_in) {
        bail!("That was another Google account, so nothing was changed. Choose {expected}.");
    }
    Ok(())
}

/// A sign-in in progress: the browser has been pointed at `url` and we are waiting for
/// Google to redirect back to our loopback listener.
pub struct SignIn {
    listener: TcpListener,
    redirect_uri: String,
    verifier: String,
    state: String,
    /// The address it has to be, when it is a sign-in to an account Nimbra already has.
    expected: Option<String>,
}

impl SignIn {
    /// Starts listening and returns the URL to open in the user's browser.
    /// `full` also asks for permanent deletion (see `FULL_SCOPE`). `expected` is the address
    /// of the account being signed in to again: the browser is pointed at it, and no other
    /// is accepted (see `finish`).
    pub fn start(config: &Config, full: bool, expected: Option<&str>) -> Result<(Self, String)> {
        // Loopback only, on a port picked by the OS.
        let listener =
            TcpListener::bind(("127.0.0.1", 0)).context("opening a local port for sign-in")?;
        listener.set_nonblocking(true)?;
        let redirect_uri = format!("http://127.0.0.1:{}", listener.local_addr()?.port());
        let verifier = random_token()?;
        let state = random_token()?;
        let mut url = url::Url::parse_with_params(
            AUTH_URL,
            &[
                ("client_id", config.client_id.as_str()),
                ("redirect_uri", redirect_uri.as_str()),
                ("response_type", "code"),
                ("scope", if full { FULL_SCOPE } else { SCOPE }),
                ("include_granted_scopes", "true"),
                ("code_challenge", pkce_challenge(&verifier).as_str()),
                ("code_challenge_method", "S256"),
                ("state", state.as_str()),
                ("access_type", "offline"),
                ("prompt", "consent"),
            ],
        )?;
        if let Some(email) = expected {
            url.query_pairs_mut().append_pair("login_hint", email);
        }
        Ok((
            Self {
                listener,
                redirect_uri,
                verifier,
                state,
                expected: expected.map(String::from),
            },
            url.into(),
        ))
    }

    /// Blocks until the browser comes back (or the timeout passes), exchanges the code and
    /// stores the refresh token in the keychain.
    pub fn finish(self, config: &Config, account: &str) -> Result<Client> {
        let code = self.wait_for_code()?;
        let tokens = token_request(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("code_verifier", &self.verifier),
            ("client_id", &config.client_id),
            ("client_secret", &config.client_secret),
            ("redirect_uri", &self.redirect_uri),
        ])?;
        let refresh = tokens
            .refresh_token
            .ok_or_else(|| anyhow!("Google did not return a long-lived sign-in"))?;
        let client = Client::new(config.clone(), refresh.clone(), account.to_string());
        client.remember(tokens.access_token, tokens.expires_in);
        // The browser lets any Google account be picked. Another one's sign-in saved as this
        // account's would send from it, and delete this one's mail kept here as someone
        // else's. So it is asked whose it is before anything is saved.
        if let Some(expected) = &self.expected {
            let (email, _) = client
                .profile()
                .context("Nimbra could not check which account signed in")?;
            check_same_account(expected, &email)?;
        }
        store_refresh_token(account, &refresh)?;
        Ok(client)
    }

    fn wait_for_code(&self) -> Result<String> {
        let deadline = Instant::now() + SIGN_IN_TIMEOUT;
        loop {
            if Instant::now() > deadline {
                bail!("Sign-in timed out. Please try again.");
            }
            let stream = match self.listener.accept() {
                Ok((stream, _)) => stream,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(100));
                    continue;
                }
                Err(e) => return Err(e).context("waiting for the browser"),
            };
            // Anything that is not our redirect (favicon requests, stray connections,
            // a wrong `state`) is answered and ignored; we keep waiting.
            if let Some(result) = self.handle(stream) {
                return result;
            }
        }
    }

    fn handle(&self, stream: TcpStream) -> Option<Result<String>> {
        stream.set_nonblocking(false).ok()?;
        stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
        let mut request_line = String::new();
        // Read at most 8 KB of the request line.
        BufReader::new(std::io::Read::take(&stream, 8 * 1024))
            .read_line(&mut request_line)
            .ok()?;
        let path = request_line.split_whitespace().nth(1)?;
        let url = url::Url::parse(&format!("http://127.0.0.1{path}")).ok()?;
        let param = |name: &str| {
            url.query_pairs()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.into_owned())
        };

        if url.path() != "/" || param("state").as_deref() != Some(self.state.as_str()) {
            respond(&stream, "404 Not Found", "Not found.");
            return None;
        }
        if let Some(error) = param("error") {
            respond(
                &stream,
                "200 OK",
                "Sign-in was cancelled. You can close this tab.",
            );
            let reason = if error == "access_denied" {
                "Sign-in was cancelled.".to_string()
            } else {
                format!("Google reported: {}", sanitize(&error))
            };
            return Some(Err(anyhow!(reason)));
        }
        let code = param("code")?;
        respond(
            &stream,
            "200 OK",
            "Nimbra is connected. You can close this tab and return to the app.",
        );
        Some(Ok(code))
    }
}

pub(crate) fn respond(mut stream: &TcpStream, status: &str, message: &str) {
    let body = format!(
        "<!doctype html><meta charset=utf-8><title>Nimbra</title>\
         <body style=\"font:16px system-ui;background:#0e0e14;color:#f5f3ef;display:grid;\
         place-items:center;height:100vh;margin:0\"><p>{message}</p>"
    );
    let _ = write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
}

// ------------------------------------------------------------------ client

pub struct Client {
    config: Config,
    refresh_token: String,
    /// The access token and when it is over, by the wall clock: an `Instant` stands still
    /// while the Mac sleeps, and the token does not.
    access: Mutex<Option<(String, SystemTime)>>,
    /// Which account's keychain entry holds the refresh token.
    account: String,
    /// Changes asked of Gmail, so that what was listed before one is known to be old.
    writes: AtomicU64,
    /// List rows by thread (and whether they name the recipient), each with the thread's
    /// history id then: one that has not moved is not fetched again (40 units). Memory only.
    rows: Mutex<HashMap<(String, bool), (String, Summary)>>,
    /// Where the newest of them are kept over a relaunch: the account's encrypted store.
    rows_kept_in: Mutex<Option<Arc<Store>>>,
}

impl Client {
    pub fn new(config: Config, refresh_token: String, account: String) -> Self {
        Self {
            config,
            refresh_token,
            access: Mutex::new(None),
            account,
            writes: AtomicU64::new(0),
            rows: Mutex::new(HashMap::new()),
            rows_kept_in: Mutex::new(None),
        }
    }

    fn remember(&self, access_token: String, expires_in: u64) {
        // Refresh a minute early so a token never expires mid-request.
        let expiry = SystemTime::now() + Duration::from_secs(expires_in.saturating_sub(60));
        *self.access.lock().unwrap() = Some((access_token, expiry));
    }

    /// The account's Google profile photo, downloaded (about 128 px). It is only ever
    /// fetched from Google's own image host, over HTTPS.
    pub fn profile_photo(&self) -> Result<Photo> {
        let people = ureq::get(PEOPLE_ME)
            .query("personFields", "photos")
            .query("sources", "READ_SOURCE_TYPE_PROFILE")
            .timeout(HTTP_TIMEOUT);
        match self.authorized(&people, Payload::None)? {
            Ok(response) => {
                let person: ProfilePhotos = response.into_json()?;
                return match own_photo(&person.photos).and_then(photo_link) {
                    Some(link) => Ok(photo_bytes(&link)?.map_or(Photo::NoPhoto, Photo::Image)),
                    None => Ok(Photo::NoPhoto),
                };
            }
            // Not turned on in the Cloud project, or not for this sign-in: the basic profile.
            Err(ureq::Error::Status(400..=499, _)) => {}
            Err(error) => return Err(error.into()),
        }
        let response =
            self.authorized(&ureq::get(USERINFO).timeout(HTTP_TIMEOUT), Payload::None)?;
        let info: serde_json::Value = match response {
            Ok(response) => response.into_json()?,
            Err(ureq::Error::Status(401 | 403, _)) => return Ok(Photo::NotAllowed),
            Err(error) => return Err(error.into()),
        };
        let link = info.get("picture").and_then(|p| p.as_str());
        let Some(link) = link.and_then(photo_link) else {
            return Ok(Photo::NoPhoto);
        };
        Ok(photo_bytes(&link)?.map_or(Photo::NoPhoto, Photo::Unchecked))
    }

    fn signed_out(&self) -> anyhow::Error {
        SignedOut {
            account: self.account.clone(),
        }
        .into()
    }

    fn access_token(&self) -> Result<String> {
        if let Some((token, expiry)) = self.access.lock().unwrap().as_ref()
            && SystemTime::now() < *expiry
        {
            return Ok(token.clone());
        }
        let tokens = token_request(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", &self.refresh_token),
            ("client_id", &self.config.client_id),
            ("client_secret", &self.config.client_secret),
        ])
        .map_err(|e| {
            if !e.is::<SignedOut>() {
                return e;
            }
            forget_refresh_token(&self.account);
            self.signed_out()
        })?;
        self.remember(tokens.access_token.clone(), tokens.expires_in);
        Ok(tokens.access_token)
    }

    /// Makes a request with the access token. A refused token is renewed and the request
    /// made once more (refused, so Gmail did nothing with it). Whether the sign-in itself
    /// has ended only the renewal can say: see `access_token`.
    fn authorized(
        &self,
        request: &ureq::Request,
        payload: Payload<'_>,
    ) -> Result<Result<ureq::Response, ureq::Error>> {
        let mut renewed = false;
        loop {
            let token = self.access_token()?;
            let call = request
                .clone()
                .set("Authorization", &format!("Bearer {token}"));
            let result = match payload {
                Payload::None => call.call(),
                Payload::Json(value) => call.send_json(value),
                Payload::Bytes(bytes) => call.send_bytes(bytes),
            };
            if renewed || !matches!(result, Err(ureq::Error::Status(401, _))) {
                // Whatever the answer: a write with a lost one may have been carried out.
                if request.method() != "GET" {
                    self.writes.fetch_add(1, Ordering::Relaxed);
                }
                return Ok(result);
            }
            self.forget_access(&token);
            renewed = true;
        }
    }

    /// Drops `refused`, unless another thread has put a newer token in its place.
    fn forget_access(&self, refused: &str) {
        let mut access = self.access.lock().unwrap();
        if access.as_ref().is_some_and(|(token, _)| token == refused) {
            *access = None;
        }
    }

    fn send<T: serde::de::DeserializeOwned>(
        &self,
        request: ureq::Request,
        body: Option<serde_json::Value>,
    ) -> Result<T> {
        // Gmail limits how many requests a user may make per minute. When it says so,
        // wait a little and try again (three times, waiting longer each time).
        let mut wait = Duration::from_millis(1500);
        let mut attempt = 0;
        loop {
            let result = self.authorized(
                &request.clone().timeout(HTTP_TIMEOUT),
                body.as_ref().map_or(Payload::None, Payload::Json),
            )?;
            if let Err(ureq::Error::Status(code @ (403 | 429), response)) = result {
                let text = response.into_string().unwrap_or_default();
                if attempt < 3 && is_rate_limited(code, &text) {
                    std::thread::sleep(wait);
                    wait *= 2;
                    attempt += 1;
                    continue;
                }
                return Err(api_error(code, &text));
            }
            // Gmail answers "204 No Content" (an empty body) when a filtered list has
            // nothing in it, such as no unread mail. That is an empty object, not an error.
            let text = self
                .finish(result)?
                .into_string()
                .context("reading Gmail's reply")
                .context(MayHaveArrived)?;
            let text = if text.trim().is_empty() {
                "{}"
            } else {
                text.as_str()
            };
            // Accepted, so it was carried out, whatever is wrong with the answer.
            return serde_json::from_str(text)
                .context("reading Gmail's reply")
                .context(MayHaveArrived);
        }
    }

    /// Uploads a whole RFC 5322 message with its JSON metadata in one multipart request
    /// (Gmail's media upload, needed for messages with attachments).
    fn upload<T: serde::de::DeserializeOwned>(
        &self,
        request: ureq::Request,
        metadata: serde_json::Value,
        raw: &[u8],
    ) -> Result<T> {
        let boundary = format!("nimbra-{}", random_hex(12)?);
        let mut body = format!(
            "--{boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n{metadata}\r\n--{boundary}\r\nContent-Type: message/rfc822\r\n\r\n"
        )
        .into_bytes();
        body.extend_from_slice(raw);
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let request = request
            .query("uploadType", "multipart")
            .timeout(Duration::from_secs(180))
            .set(
                "Content-Type",
                &format!("multipart/related; boundary={boundary}"),
            );
        let result = self.authorized(&request, Payload::Bytes(&body))?;
        self.finish(result)?
            .into_json()
            .context("reading Gmail's reply")
            .context(MayHaveArrived)
    }

    /// Turns a ureq result into the response or a readable error.
    fn finish(&self, result: Result<ureq::Response, ureq::Error>) -> Result<ureq::Response> {
        match result {
            Ok(response) => Ok(response),
            // Refused with a new token as well. The sign-in just gave that token, so this
            // is Gmail's trouble, and no reason to sign out and delete anything.
            Err(ureq::Error::Status(401, _)) => Err(anyhow!(
                "Gmail did not accept the request. Try again in a moment."
            )),
            Err(ureq::Error::Status(code, response)) => {
                Err(api_error(code, &response.into_string().unwrap_or_default()))
            }
            Err(error) if never_left(error.kind()) => Err(Offline.into()),
            Err(_) => Err(anyhow::Error::new(Offline).context(MayHaveArrived)),
        }
    }

    /// How many changes have been asked of Gmail through this connection.
    pub fn writes(&self) -> u64 {
        self.writes.load(Ordering::Relaxed)
    }

    /// Forgets the list rows kept in memory.
    pub fn forget_rows(&self) {
        self.rows.lock().unwrap().clear();
    }

    /// Takes up the rows kept in the account's store, and keeps them there from now on.
    /// Blocking.
    pub fn keep_rows_in(&self, store: &Arc<Store>) {
        let kept: Vec<KeptRow> = store.load(ROWS).unwrap_or_default();
        let mut rows = self.rows.lock().unwrap();
        for (id, recipient, version, row) in kept {
            rows.entry((id, recipient)).or_insert((version, row));
        }
        *self.rows_kept_in.lock().unwrap() = Some(store.clone());
    }

    /// Saves the newest rows. Blocking.
    fn save_rows(&self) {
        const KEPT_ROWS: usize = 600;
        let Some(store) = self.rows_kept_in.lock().unwrap().clone() else {
            return;
        };
        let taken = store.snapshot();
        let mut kept: Vec<KeptRow> = self
            .rows
            .lock()
            .unwrap()
            .iter()
            .map(|((id, recipient), (version, row))| {
                (id.clone(), *recipient, version.clone(), row.clone())
            })
            .collect();
        kept.sort_by_key(|(_, _, _, row)| std::cmp::Reverse(row.timestamp_ms));
        kept.truncate(KEPT_ROWS);
        if store.save_newest(ROWS, &kept, taken).is_err() {
            eprintln!("nimbra: could not save the list rows");
        }
    }

    /// A list row, fetched only if the thread has changed since it last was. `version` is
    /// its history id as listed; without one it is always fetched.
    fn row(&self, id: &str, version: &str, recipient: bool) -> Result<(Summary, bool)> {
        const MOST_ROWS: usize = 5000;
        let key = (id.to_string(), recipient);
        if !version.is_empty()
            && let Some((kept, row)) = self.rows.lock().unwrap().get(&key)
            && kept == version
        {
            return Ok((row.clone(), false));
        }
        let row = self.summary(id, recipient)?;
        if !version.is_empty() {
            let mut rows = self.rows.lock().unwrap();
            if rows.len() >= MOST_ROWS {
                rows.clear();
            }
            rows.insert(key, (version.to_string(), row.clone()));
        }
        Ok((row, true))
    }

    /// The account's address and its current history id (the point to sync from).
    pub fn profile(&self) -> Result<(String, String)> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Profile {
            email_address: String,
            history_id: String,
        }
        let profile: Profile = self.send(ureq::get(&format!("{API}/profile")), None)?;
        Ok((profile.email_address, profile.history_id))
    }

    /// Everything that changed in the mailbox since `start` (a history id), in Gmail's own
    /// change feed. Fails with [`HistoryExpired`] when that point is too old to sync from
    /// (Gmail keeps about a week) or too much has changed, so the caller fetches afresh.
    pub fn history(&self, start: &str) -> Result<Changes> {
        #[derive(Deserialize, Default)]
        #[serde(rename_all = "camelCase")]
        struct Page {
            #[serde(default)]
            history: Vec<Record>,
            next_page_token: Option<String>,
            history_id: Option<String>,
        }
        #[derive(Deserialize, Default)]
        #[serde(rename_all = "camelCase")]
        struct Record {
            #[serde(default)]
            messages: Vec<Ref>,
            #[serde(default)]
            messages_added: Vec<Wrapped>,
            #[serde(default)]
            messages_deleted: Vec<Wrapped>,
            #[serde(default)]
            labels_added: Vec<Wrapped>,
            #[serde(default)]
            labels_removed: Vec<Wrapped>,
        }
        #[derive(Deserialize)]
        struct Wrapped {
            message: Ref,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Ref {
            #[serde(default)]
            thread_id: String,
            #[serde(default)]
            label_ids: Vec<String>,
        }
        if !start.chars().all(|c| c.is_ascii_digit()) || start.is_empty() {
            bail!(HistoryExpired);
        }
        let mut changes = Changes::default();
        let mut token: Option<String> = None;
        for _ in 0..HISTORY_PAGES {
            let mut request = ureq::get(&format!("{API}/history"))
                .query("startHistoryId", start)
                .query("maxResults", "500");
            if let Some(token) = &token {
                request = request.query("pageToken", token);
            }
            let page: Page = match self.send(request, None) {
                Ok(page) => page,
                Err(error) if error.to_string().starts_with("Gmail error 404") => {
                    return Err(HistoryExpired.into());
                }
                Err(error) => return Err(error),
            };
            for record in page.history {
                for added in &record.messages_added {
                    let labels = &added.message.label_ids;
                    let has = |l: &str| labels.iter().any(|x| x == l);
                    // Any unread message landing in the inbox counts, including one you sent
                    // to yourself (it carries both SENT and INBOX). Drafts never do.
                    if has("INBOX") && has("UNREAD") && !has("DRAFT") {
                        changes
                            .new_unread_inbox
                            .push(added.message.thread_id.clone());
                    }
                }
                let touched = record.messages.iter().chain(
                    [
                        &record.messages_added,
                        &record.messages_deleted,
                        &record.labels_added,
                        &record.labels_removed,
                    ]
                    .into_iter()
                    .flatten()
                    .map(|w| &w.message),
                );
                for message in touched {
                    let id = &message.thread_id;
                    if is_id(id) && !changes.threads.contains(id) {
                        changes.threads.push(id.clone());
                    }
                }
            }
            if let Some(latest) = page.history_id {
                changes.latest = latest;
            }
            match page.next_page_token {
                Some(next) => token = Some(next),
                None => {
                    changes.new_unread_inbox.dedup();
                    if changes.latest.is_empty() {
                        changes.latest = start.to_string();
                    }
                    return Ok(changes);
                }
            }
        }
        // Too much has changed to apply piece by piece.
        Err(HistoryExpired.into())
    }

    /// The newest threads of a mailbox, with enough detail for the list.
    /// One page of a mailbox, and the token for the next page if there is one.
    pub fn threads_page(
        &self,
        view: View,
        label_id: Option<&str>,
        limit: usize,
        page: Option<&str>,
    ) -> Result<(Vec<Summary>, Option<String>)> {
        let listing = self.list(view, label_id, limit, page)?;
        let next = listing.next_page_token;
        // In Sent and Drafts the interesting person is the recipient, not you.
        let recipient = matches!(view, View::Sent | View::Drafts);
        let threads = listing.threads;

        // Fetch thread metadata a few at a time; one request per changed thread is the only way
        // to get subject and sender without the batch endpoint.
        self.access_token()?;
        let mut summaries: Vec<Option<Result<(Summary, bool)>>> = Vec::new();
        summaries.resize_with(threads.len(), || None);
        let workers = 6.min(threads.len().max(1));
        std::thread::scope(|scope| {
            let chunk = threads.len().div_ceil(workers).max(1);
            for (threads, out) in threads.chunks(chunk).zip(summaries.chunks_mut(chunk)) {
                scope.spawn(move || {
                    for (thread, slot) in threads.iter().zip(out) {
                        *slot = Some(self.row(&thread.id, &thread.history_id, recipient));
                    }
                });
            }
        });
        let summaries: Result<Vec<(Summary, bool)>> = summaries.into_iter().flatten().collect();
        let summaries = summaries?;
        if summaries.iter().any(|(_, fetched)| *fetched) {
            self.save_rows();
        }
        Ok((summaries.into_iter().map(|(row, _)| row).collect(), next))
    }

    /// Where the page after the first `count` threads starts, for a list that came from
    /// this Mac (and so has no page token). One request, for no thread's details.
    pub fn page_after(
        &self,
        view: View,
        label_id: Option<&str>,
        count: usize,
    ) -> Result<Option<String>> {
        Ok(self.list(view, label_id, count, None)?.next_page_token)
    }

    fn list(
        &self,
        view: View,
        label_id: Option<&str>,
        limit: usize,
        page: Option<&str>,
    ) -> Result<Listing> {
        let mut request =
            ureq::get(&format!("{API}/threads")).query("maxResults", &limit.to_string());
        if let Some(page) = page {
            if page.len() > 512 || !page.chars().all(|c| c.is_ascii_graphic()) {
                bail!("unexpected page token");
            }
            request = request.query("pageToken", page);
        }
        let request = match view {
            View::Inbox | View::AllInboxes => request.query("labelIds", "INBOX"),
            View::Primary => category(request, "CATEGORY_PERSONAL"),
            View::Updates => category(request, "CATEGORY_UPDATES"),
            View::Promotions => category(request, "CATEGORY_PROMOTIONS"),
            View::Social => category(request, "CATEGORY_SOCIAL"),
            // Gmail's own search syntax; the client library URL-encodes it.
            View::Search => match label_id
                .map(str::trim)
                .filter(|q| !q.is_empty() && q.len() <= 500)
            {
                Some(query) => request.query("q", query),
                None => bail!("Type something to search for."),
            },
            View::Label(_) => match label_id.filter(|id| is_label_id(id)) {
                Some(id) => request.query("labelIds", id),
                None => bail!("unknown label"),
            },
            View::Starred => request.query("labelIds", "STARRED"),
            View::Drafts => request.query("labelIds", "DRAFT"),
            View::Sent => request.query("labelIds", "SENT"),
            View::Snoozed => request.query("q", "in:snoozed"),
            // "Done" is Gmail's archive: everything that is not somewhere else.
            View::Done => request.query(
                "q",
                "-in:inbox -in:sent -in:drafts -in:chats -in:spam -in:trash",
            ),
            View::AllMail => request,
            View::Important => request.query("labelIds", "IMPORTANT"),
            View::Spam => request
                .query("labelIds", "SPAM")
                .query("includeSpamTrash", "true"),
            View::Trash => request
                .query("labelIds", "TRASH")
                .query("includeSpamTrash", "true"),
        };
        self.send(request, None)
    }

    pub fn summary(&self, id: &str, recipient: bool) -> Result<Summary> {
        if !is_id(id) {
            bail!("unexpected thread id");
        }
        let thread: Thread = self.send(
            ureq::get(&format!("{API}/threads/{id}"))
                .query("format", "metadata")
                .query("metadataHeaders", "From")
                .query("metadataHeaders", "To")
                .query("metadataHeaders", "Subject"),
            None,
        )?;
        let first = thread.messages.first();
        let last = thread.messages.last();
        Ok(Summary {
            id: thread.id,
            sender: last
                .map(|m| {
                    if recipient {
                        // First recipient is enough for a list row.
                        sender_name(m.header("To").split(',').next().unwrap_or(""))
                    } else {
                        sender_name(m.header("From"))
                    }
                })
                .unwrap_or_default(),
            subject: first
                .map(|m| m.header("Subject").trim().to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "(no subject)".to_string()),
            snippet: last
                .map(|m| decode_entities(&m.snippet))
                .unwrap_or_default(),
            timestamp_ms: last.map(|m| m.timestamp_ms()).unwrap_or(0),
            message_count: thread.messages.len(),
            unread: thread
                .messages
                .iter()
                .any(|m| m.label_ids.iter().any(|l| l == "UNREAD")),
            starred: thread
                .messages
                .iter()
                .any(|m| m.label_ids.iter().any(|l| l == "STARRED")),
            labels: {
                let mut labels: Vec<String> = Vec::new();
                for label in thread.messages.iter().flat_map(|m| &m.label_ids) {
                    if !labels.contains(label) {
                        labels.push(label.clone());
                    }
                }
                labels
            },
            message_labels: thread
                .messages
                .iter()
                .map(|m| m.label_ids.clone())
                .collect(),
        })
    }

    /// Every message in a thread, oldest first, as plain text.
    pub fn thread(&self, id: &str) -> Result<Vec<Message>> {
        if !is_id(id) {
            bail!("unexpected thread id");
        }
        let thread: Thread = self.send(
            ureq::get(&format!("{API}/threads/{id}")).query("format", "full"),
            None,
        )?;
        let mut messages: Vec<Message> = thread
            .messages
            .iter()
            .map(|m| Message {
                from: person(m.header("From")),
                to: people(m.header("To")),
                cc: people(m.header("Cc")),
                reply_to: people(m.header("Reply-To")).into_iter().next(),
                attachments: m
                    .payload
                    .as_ref()
                    .map(|p| attachments(p, &m.id))
                    .unwrap_or_default(),
                unsubscribe: unsubscribe_link(m.header("List-Unsubscribe")),
                sender: sender_name(m.header("From")),
                address: address_of(m.header("From")),
                message_id: m.header("Message-ID").trim().to_string(),
                others: people(m.header("To"))
                    .into_iter()
                    .chain(people(m.header("Cc")))
                    .map(|p| p.address)
                    .collect(),
                snippet: decode_entities(&m.snippet),
                timestamp_ms: m.timestamp_ms(),
                blocks: m.payload.as_ref().map(body_blocks).unwrap_or_default(),
                html: m
                    .payload
                    .as_ref()
                    .and_then(|payload| find_part(payload, "text/html"))
                    .and_then(decode_part)
                    // Very large bodies stay in the native reader only.
                    .filter(|bytes| bytes.len() <= 2 * 1024 * 1024)
                    .map(|bytes| String::from_utf8_lossy(&bytes).into_owned()),
            })
            .collect();
        // Images embedded in the message itself (`cid:` links) are inlined as data URLs,
        // so the original view can show them without any network access.
        for (message, raw) in messages.iter_mut().zip(&thread.messages) {
            if let (Some(html), Some(payload)) = (message.html.as_mut(), raw.payload.as_ref())
                && html.contains("cid:")
            {
                self.inline_images(html, payload, &raw.id);
            }
        }
        Ok(messages)
    }

    /// Replaces `cid:` image links in `html` with the image data from the message's parts.
    fn inline_images(&self, html: &mut String, payload: &Part, message_id: &str) {
        const BUDGET: usize = 4 * 1024 * 1024;
        let mut used = 0;
        let mut parts = Vec::new();
        collect_parts(payload, &mut parts);
        for part in parts {
            let Some(cid) = part
                .header("Content-ID")
                .map(|v| v.trim().trim_matches(['<', '>']).to_string())
                .filter(|cid| !cid.is_empty())
            else {
                continue;
            };
            let mime = part.mime_type.to_ascii_lowercase();
            if !matches!(
                mime.as_str(),
                "image/png" | "image/jpeg" | "image/gif" | "image/webp"
            ) {
                continue;
            }
            let reference = format!("cid:{cid}");
            if !html.contains(&reference) {
                continue;
            }
            let bytes = match decode_part(part) {
                Some(bytes) => Some(bytes),
                None => part
                    .body
                    .as_ref()
                    .and_then(|b| b.attachment_id.as_deref())
                    .and_then(|att| self.download(message_id, att).ok()),
            };
            let Some(bytes) = bytes else { continue };
            used += bytes.len();
            if used > BUDGET {
                break;
            }
            let data = format!(
                "data:{mime};base64,{}",
                base64::engine::general_purpose::STANDARD.encode(&bytes)
            );
            *html = html.replace(&reference, &data);
        }
    }

    /// Downloads one attachment's bytes.
    pub fn download(&self, message_id: &str, attachment_id: &str) -> Result<Vec<u8>> {
        #[derive(Deserialize)]
        struct Body {
            #[serde(default)]
            data: String,
        }
        if !is_id(message_id) || !is_attachment_id(attachment_id) {
            bail!("unexpected attachment id");
        }
        let body: Body = self.send(
            ureq::get(&format!(
                "{API}/messages/{message_id}/attachments/{attachment_id}"
            )),
            None,
        )?;
        URL_SAFE_NO_PAD
            .decode(body.data.trim_end_matches('='))
            .context("reading the attachment")
    }

    /// Applies one change to a thread. Nothing here deletes mail permanently: trash is
    /// Gmail's 30-day bin and can be undone.
    pub fn change(&self, id: &str, change: Change) -> Result<()> {
        if !is_id(id) {
            bail!("unexpected thread id");
        }
        let labels = |add: &[&str], remove: &[&str]| {
            (
                "modify",
                Some(serde_json::json!({ "addLabelIds": add, "removeLabelIds": remove })),
            )
        };
        // Every request carries a body: Gmail refuses a POST without one (HTTP 411).
        let (action, body) = match change {
            Change::Archive => labels(&[], &["INBOX"]),
            Change::Unarchive => labels(&["INBOX"], &[]),
            Change::Star => labels(&["STARRED"], &[]),
            Change::Unstar => labels(&[], &["STARRED"]),
            Change::MarkRead => labels(&[], &["UNREAD"]),
            Change::MarkUnread => labels(&["UNREAD"], &[]),
            Change::Spam => labels(&["SPAM"], &["INBOX"]),
            Change::NotSpam => labels(&["INBOX"], &["SPAM"]),
            Change::Trash => ("trash", Some(serde_json::json!({}))),
            Change::Untrash => {
                // Trash also takes a thread out of the inbox, and untrash does not put it
                // back: restore it to the inbox as a second step.
                self.send::<serde_json::Value>(
                    ureq::post(&format!("{API}/threads/{id}/untrash")),
                    Some(serde_json::json!({})),
                )?;
                labels(&["INBOX"], &[])
            }
        };
        self.send::<serde_json::Value>(ureq::post(&format!("{API}/threads/{id}/{action}")), body)?;
        Ok(())
    }

    /// Loads the draft that belongs to a thread in the Drafts mailbox, ready for editing.
    pub fn draft_for_thread(&self, thread_id: &str) -> Result<Draft> {
        #[derive(Deserialize, Default)]
        struct Listing {
            #[serde(default)]
            drafts: Vec<Entry>,
        }
        #[derive(Deserialize)]
        struct Entry {
            id: String,
            message: EntryMessage,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct EntryMessage {
            thread_id: String,
        }
        let listing: Listing = self.send(
            ureq::get(&format!("{API}/drafts")).query("maxResults", "100"),
            None,
        )?;
        let id = listing
            .drafts
            .into_iter()
            .find(|entry| entry.message.thread_id == thread_id)
            .map(|entry| entry.id)
            .filter(|id| is_draft_id(id))
            .ok_or_else(|| anyhow!("That draft is no longer in Gmail."))?;
        self.draft(&id, thread_id)
    }

    /// One draft, read in full.
    pub fn draft(&self, id: &str, thread_id: &str) -> Result<Draft> {
        #[derive(Deserialize)]
        struct Full {
            message: RawMessage,
        }
        if !is_draft_id(id) {
            bail!("unexpected draft id");
        }
        let id = id.to_string();
        let full: Full = self.send(
            ureq::get(&format!("{API}/drafts/{id}")).query("format", "full"),
            None,
        )?;
        let message = &full.message;
        let text = message.payload.as_ref().map(body_text).unwrap_or_default();
        let (body, quoted) = split_quote(&text);
        let in_reply_to = message.header("In-Reply-To").trim().to_string();
        Ok(Draft {
            id,
            to: message.header("To").trim().to_string(),
            cc: message.header("Cc").trim().to_string(),
            bcc: message.header("Bcc").trim().to_string(),
            attachments: message
                .payload
                .as_ref()
                .map(|p| attachments(p, &message.id))
                .unwrap_or_default(),
            subject: message.header("Subject").trim().to_string(),
            body,
            quoted,
            html: message
                .payload
                .as_ref()
                .and_then(|payload| find_part(payload, "text/html"))
                .and_then(decode_part)
                .filter(|bytes| bytes.len() <= 2 * 1024 * 1024)
                .map(|bytes| String::from_utf8_lossy(&bytes).into_owned()),
            reply: is_message_id(&in_reply_to).then(|| ReplyTo {
                thread_id: thread_id.to_string(),
                message_id: in_reply_to,
            }),
        })
    }

    /// Saves what is in the composer as a Gmail draft: a new one, or over an existing one.
    /// Returns the draft's id.
    pub fn save_draft(&self, id: Option<&str>, outgoing: &Outgoing) -> Result<String> {
        #[derive(Deserialize)]
        struct Saved {
            id: String,
        }
        let extra = self.kept_files(outgoing)?;
        let raw = outgoing.to_rfc822(true, &extra)?;
        let thread_id = match &outgoing.reply {
            Some(reply) if !is_id(&reply.thread_id) => bail!("unexpected thread id"),
            Some(reply) => Some(reply.thread_id.clone()),
            None => None,
        };
        let id = match id {
            Some(id) if is_draft_id(id) => Some(id),
            Some(_) => bail!("unexpected draft id"),
            None => None,
        };
        let saved: Saved = if raw.len() > 1_000_000 {
            let mut message = serde_json::json!({});
            if let Some(thread_id) = &thread_id {
                message["threadId"] = thread_id.clone().into();
            }
            let request = match id {
                Some(id) => ureq::put(&format!("{UPLOAD}/drafts/{id}")),
                None => ureq::post(&format!("{UPLOAD}/drafts")),
            };
            self.upload(request, serde_json::json!({ "message": message }), &raw)?
        } else {
            let mut message = serde_json::json!({ "raw": URL_SAFE_NO_PAD.encode(&raw) });
            if let Some(thread_id) = &thread_id {
                message["threadId"] = thread_id.clone().into();
            }
            let request = match id {
                Some(id) => ureq::put(&format!("{API}/drafts/{id}")),
                None => ureq::post(&format!("{API}/drafts")),
            };
            self.send(request, Some(serde_json::json!({ "message": message })))?
        };
        Ok(saved.id)
    }

    /// Downloads the attachments a draft already had, to put them back when it is saved.
    fn kept_files(&self, outgoing: &Outgoing) -> Result<Vec<OutgoingFile>> {
        outgoing
            .kept
            .iter()
            .map(|att| {
                Ok(OutgoingFile {
                    name: att.name.clone(),
                    mime: att.mime.clone(),
                    bytes: self.download(&att.message_id, &att.attachment_id)?,
                })
            })
            .collect()
    }

    /// Sends an edited draft: saves the edits over it, then asks Gmail to send that draft,
    /// which also removes it from Drafts. Runs only when the user presses Send.
    pub fn send_draft(&self, id: &str, outgoing: &Outgoing) -> Result<()> {
        outgoing.recipients()?;
        let id = self
            .save_draft(Some(id), outgoing)
            .map_err(before_sending)?;
        self.send_saved_draft(&id)
    }

    /// Keeps a message that was not sent as a draft: over the one it had or, if that is
    /// gone, as a new one.
    pub fn keep_as_draft(&self, id: Option<&str>, outgoing: &Outgoing) -> Result<String> {
        match self.save_draft(id, outgoing) {
            Err(error) if id.is_some() && !error.is::<Offline>() => self.save_draft(None, outgoing),
            result => result,
        }
    }

    /// Sends a draft exactly as it is saved in Gmail (scheduled sends).
    pub fn send_saved_draft(&self, id: &str) -> Result<()> {
        if !is_draft_id(id) {
            bail!("unexpected draft id");
        }
        self.send::<serde_json::Value>(
            ureq::post(&format!("{API}/drafts/send")),
            Some(serde_json::json!({ "id": id })),
        )
        .map_err(while_sending)?;
        Ok(())
    }

    /// Deletes a draft (one the composer saved on its own and the user then discarded).
    pub fn delete_draft(&self, id: &str) -> Result<()> {
        if !is_draft_id(id) {
            bail!("unexpected draft id");
        }
        let result = self.authorized(
            &ureq::delete(&format!("{API}/drafts/{id}")).timeout(HTTP_TIMEOUT),
            Payload::None,
        )?;
        self.finish(result)?;
        Ok(())
    }

    /// Sends a message. Runs only when the user presses Send (or its undo window ends).
    pub fn send_message(&self, outgoing: &Outgoing) -> Result<()> {
        let extra = self.kept_files(outgoing).map_err(before_sending)?;
        let raw = outgoing.to_rfc822(false, &extra)?;
        let thread_id = match &outgoing.reply {
            Some(reply) if !is_id(&reply.thread_id) => bail!("unexpected thread id"),
            Some(reply) => Some(reply.thread_id.clone()),
            None => None,
        };
        if raw.len() > 1_000_000 {
            let mut metadata = serde_json::json!({});
            if let Some(thread_id) = thread_id {
                metadata["threadId"] = thread_id.into();
            }
            self.upload::<serde_json::Value>(
                ureq::post(&format!("{UPLOAD}/messages/send")),
                metadata,
                &raw,
            )
            .map_err(while_sending)?;
        } else {
            let mut body = serde_json::json!({ "raw": URL_SAFE_NO_PAD.encode(&raw) });
            if let Some(thread_id) = thread_id {
                body["threadId"] = thread_id.into();
            }
            self.send::<serde_json::Value>(ureq::post(&format!("{API}/messages/send")), Some(body))
                .map_err(while_sending)?;
        }
        Ok(())
    }

    /// Deletes a thread for good (it does not go to Trash). Needs full mail access.
    pub fn delete_thread(&self, id: &str) -> Result<()> {
        if !is_id(id) {
            bail!("unexpected thread id");
        }
        match self.send::<serde_json::Value>(ureq::delete(&format!("{API}/threads/{id}")), None) {
            Err(error) if error.to_string().to_lowercase().contains("insufficient") => {
                Err(NeedsFullAccess.into())
            }
            other => other.map(|_| ()),
        }
    }

    /// Renames one of the user's labels.
    pub fn rename_label(&self, id: &str, name: &str) -> Result<()> {
        let name = clean_header(name);
        if !is_label_id(id) || name.is_empty() || name.chars().count() > 100 {
            bail!("A label name needs 1 to 100 characters.");
        }
        self.send::<serde_json::Value>(
            ureq::request("PATCH", &format!("{API}/labels/{id}")),
            Some(serde_json::json!({ "name": name })),
        )?;
        Ok(())
    }

    /// Deletes one of the user's labels. The mail it was on stays where it is.
    pub fn delete_label(&self, id: &str) -> Result<()> {
        if !is_label_id(id) {
            bail!("unexpected label id");
        }
        self.send::<serde_json::Value>(ureq::delete(&format!("{API}/labels/{id}")), None)?;
        Ok(())
    }

    /// Takes one of the user's labels off a thread.
    pub fn remove_label(&self, id: &str, label_id: &str) -> Result<()> {
        self.relabel(id, &[], &[label_id])
    }

    /// Adds and removes labels in one change (a move: add the label, leave the inbox).
    pub fn relabel(&self, id: &str, add: &[&str], remove: &[&str]) -> Result<()> {
        let system = ["INBOX", "SPAM", "TRASH", "UNREAD", "STARRED", "IMPORTANT"];
        let ok = |l: &&str| system.contains(l) || is_label_id(l);
        if !is_id(id) || !add.iter().all(ok) || !remove.iter().all(ok) {
            bail!("unexpected id");
        }
        self.send::<serde_json::Value>(
            ureq::post(&format!("{API}/threads/{id}/modify")),
            Some(serde_json::json!({ "addLabelIds": add, "removeLabelIds": remove })),
        )?;
        Ok(())
    }

    /// Creates a label (shown in Gmail's label list) and returns it.
    pub fn create_label(&self, name: &str) -> Result<Label> {
        #[derive(Deserialize)]
        struct Created {
            id: String,
            name: String,
        }
        let name = clean_header(name);
        if name.is_empty() || name.chars().count() > 100 {
            bail!("A label name needs 1 to 100 characters.");
        }
        let created: Created = self.send(
            ureq::post(&format!("{API}/labels")),
            Some(serde_json::json!({
                "name": name,
                "labelListVisibility": "labelShow",
                "messageListVisibility": "show",
            })),
        )?;
        if !is_label_id(&created.id) {
            bail!("unexpected label id");
        }
        Ok(Label {
            id: created.id,
            name: created.name,
        })
    }

    /// Adds one of the user's labels to a thread.
    pub fn add_label(&self, id: &str, label_id: &str) -> Result<()> {
        if !is_id(id) || !is_label_id(label_id) {
            bail!("unexpected id");
        }
        self.send::<serde_json::Value>(
            ureq::post(&format!("{API}/threads/{id}/modify")),
            Some(serde_json::json!({ "addLabelIds": [label_id] })),
        )?;
        Ok(())
    }

    /// Sidebar counts per label id, as (unread, total) threads. Unread counts only threads
    /// still in the inbox: Gmail's own label counts include archived ("Done") threads, which
    /// the mailboxes here do not list. Total is read for Drafts only (0 elsewhere). A label
    /// that cannot be read is simply left out.
    pub fn counts(&self, label_ids: &[String]) -> std::collections::HashMap<String, (u32, u32)> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Detail {
            #[serde(default)]
            threads_total: u32,
        }
        let ids: Vec<&String> = label_ids.iter().filter(|id| is_label_id(id)).collect();
        if ids.is_empty() || self.access_token().is_err() {
            return Default::default();
        }
        let mut found: Vec<Option<(u32, u32)>> = vec![None; ids.len()];
        let chunk = ids.len().div_ceil(6).max(1);
        std::thread::scope(|scope| {
            for (ids, out) in ids.chunks(chunk).zip(found.chunks_mut(chunk)) {
                scope.spawn(move || {
                    for (id, slot) in ids.iter().zip(out) {
                        *slot = if id.as_str() == "DRAFT" {
                            self.send::<Detail>(ureq::get(&format!("{API}/labels/{id}")), None)
                                .ok()
                                .map(|d| (0, d.threads_total))
                        } else {
                            self.inbox_unread(id).ok().map(|unread| (unread, 0))
                        };
                    }
                });
            }
        });
        ids.into_iter()
            .zip(found)
            .filter_map(|(id, counts)| Some((id.clone(), counts?)))
            .collect()
    }

    /// Unread threads in the inbox that carry this label, counted from thread ids (Gmail has
    /// no count for two labels together). Stops at COUNT_CAP.
    fn inbox_unread(&self, label_id: &str) -> Result<u32> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Page {
            #[serde(default)]
            threads: Vec<serde::de::IgnoredAny>,
            next_page_token: Option<String>,
        }
        let mut count = 0u32;
        let mut token: Option<String> = None;
        loop {
            let mut request = ureq::get(&format!("{API}/threads"))
                .query("maxResults", "500")
                .query("fields", "threads/id,nextPageToken")
                .query("labelIds", "INBOX")
                .query("labelIds", "UNREAD");
            if label_id != "INBOX" {
                request = request.query("labelIds", label_id);
            }
            if let Some(token) = &token {
                request = request.query("pageToken", token);
            }
            let page: Page = self.send(request, None)?;
            count += page.threads.len() as u32;
            match page.next_page_token {
                Some(next) if count < COUNT_CAP => token = Some(next),
                _ => return Ok(count),
            }
        }
    }

    /// The labels the user created, by name.
    pub fn labels(&self) -> Result<Vec<Label>> {
        #[derive(Deserialize, Default)]
        struct Listing {
            #[serde(default)]
            labels: Vec<RawLabel>,
        }
        #[derive(Deserialize)]
        struct RawLabel {
            id: String,
            name: String,
            #[serde(default, rename = "type")]
            kind: String,
        }
        let listing: Listing = self.send(ureq::get(&format!("{API}/labels")), None)?;
        let mut labels: Vec<Label> = listing
            .labels
            .into_iter()
            .filter(|l| l.kind == "user" && is_label_id(&l.id))
            .map(|l| Label {
                id: l.id,
                name: l.name,
            })
            .collect();
        labels.sort_by_key(|l| l.name.to_lowercase());
        Ok(labels)
    }
}

/// The app reaches Gmail through the provider interface; each call is the method above.
impl Provider for Client {
    fn profile(&self) -> Result<(String, String)> {
        Client::profile(self)
    }
    fn profile_photo(&self) -> Result<Photo> {
        Client::profile_photo(self)
    }
    fn writes(&self) -> u64 {
        Client::writes(self)
    }
    fn forget_rows(&self) {
        Client::forget_rows(self)
    }
    fn keep_rows_in(&self, store: &Arc<Store>) {
        Client::keep_rows_in(self, store)
    }
    fn history(&self, start: &str) -> Result<Changes> {
        Client::history(self, start)
    }
    fn threads_page(
        &self,
        view: View,
        label_id: Option<&str>,
        limit: usize,
        page: Option<&str>,
    ) -> Result<(Vec<Summary>, Option<String>)> {
        Client::threads_page(self, view, label_id, limit, page)
    }
    fn page_after(
        &self,
        view: View,
        label_id: Option<&str>,
        count: usize,
    ) -> Result<Option<String>> {
        Client::page_after(self, view, label_id, count)
    }
    fn summary(&self, id: &str, recipient: bool) -> Result<Summary> {
        Client::summary(self, id, recipient)
    }
    fn thread(&self, id: &str) -> Result<Vec<Message>> {
        Client::thread(self, id)
    }
    fn download(&self, message_id: &str, attachment_id: &str) -> Result<Vec<u8>> {
        Client::download(self, message_id, attachment_id)
    }
    fn change(&self, id: &str, change: Change) -> Result<()> {
        Client::change(self, id, change)
    }
    fn draft_for_thread(&self, thread_id: &str) -> Result<Draft> {
        Client::draft_for_thread(self, thread_id)
    }
    fn save_draft(&self, id: Option<&str>, outgoing: &Outgoing) -> Result<String> {
        Client::save_draft(self, id, outgoing)
    }
    fn send_draft(&self, id: &str, outgoing: &Outgoing) -> Result<()> {
        Client::send_draft(self, id, outgoing)
    }
    fn keep_as_draft(&self, id: Option<&str>, outgoing: &Outgoing) -> Result<String> {
        Client::keep_as_draft(self, id, outgoing)
    }
    fn send_saved_draft(&self, id: &str) -> Result<()> {
        Client::send_saved_draft(self, id)
    }
    fn delete_draft(&self, id: &str) -> Result<()> {
        Client::delete_draft(self, id)
    }
    fn send_message(&self, outgoing: &Outgoing) -> Result<()> {
        Client::send_message(self, outgoing)
    }
    fn delete_thread(&self, id: &str) -> Result<()> {
        Client::delete_thread(self, id)
    }
    fn labels(&self) -> Result<Vec<Label>> {
        Client::labels(self)
    }
    fn create_label(&self, name: &str) -> Result<Label> {
        Client::create_label(self, name)
    }
    fn rename_label(&self, id: &str, name: &str) -> Result<()> {
        Client::rename_label(self, id, name)
    }
    fn delete_label(&self, id: &str) -> Result<()> {
        Client::delete_label(self, id)
    }
    fn add_label(&self, id: &str, label_id: &str) -> Result<()> {
        Client::add_label(self, id, label_id)
    }
    fn remove_label(&self, id: &str, label_id: &str) -> Result<()> {
        Client::remove_label(self, id, label_id)
    }
    fn relabel(&self, id: &str, add: &[&str], remove: &[&str]) -> Result<()> {
        Client::relabel(self, id, add, remove)
    }
    fn counts(&self, label_ids: &[String]) -> HashMap<String, (u32, u32)> {
        Client::counts(self, label_ids)
    }
}

fn category(request: ureq::Request, label: &str) -> ureq::Request {
    request.query("labelIds", "INBOX").query("labelIds", label)
}

/// Draft ids go into request paths. Gmail's look like `r-1234…` or `r:1234…`, so they need
/// `:` as well; anything that could change the path or query is still refused.
fn is_draft_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_:".contains(c))
}

/// Label ids go into request queries, so only accept the characters Gmail uses.
fn is_label_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Gmail's "slow down" answers: too many requests, or the per-minute quota used up.
fn is_rate_limited(code: u16, body: &str) -> bool {
    code == 429
        || [
            "rateLimitExceeded",
            "userRateLimitExceeded",
            "Quota exceeded",
        ]
        .iter()
        .any(|marker| body.contains(marker))
}

/// A readable error from Gmail's error body.
fn api_error(code: u16, body: &str) -> anyhow::Error {
    #[derive(Deserialize)]
    struct ApiError {
        error: ApiErrorBody,
    }
    #[derive(Deserialize)]
    struct ApiErrorBody {
        message: String,
    }
    if is_rate_limited(code, body) {
        return anyhow!("Gmail is busy right now (too many requests). Try again in a minute.");
    }
    let message = serde_json::from_str::<ApiError>(body)
        .map(|e| e.error.message)
        .unwrap_or_default();
    Answered {
        code,
        text: message.chars().take(160).collect(),
    }
    .into()
}

/// A profile photo address, only if it is Google's image host over HTTPS, asked for at
/// 128 px (Google's size suffix, such as `=s96-c`, replaced).
fn photo_link(link: &str) -> Option<String> {
    let mut url = url::Url::parse(link).ok()?;
    let host = url.host_str()?;
    if url.scheme() != "https"
        || !(host == "googleusercontent.com" || host.ends_with(".googleusercontent.com"))
    {
        return None;
    }
    // An older link's size is a query (`?sz=50`), which would swallow the one added here.
    url.set_query(None);
    let mut text = url.to_string();
    if let Some(at) = text.rfind('=')
        && text[at..].starts_with("=s")
    {
        text.truncate(at);
    }
    Some(format!("{text}=s128-c"))
}

#[derive(Deserialize)]
struct ProfilePhotos {
    #[serde(default)]
    photos: Vec<ListedPhoto>,
}

#[derive(Deserialize)]
struct ListedPhoto {
    url: String,
    /// Drawn by Google (the letter), not given by the user.
    #[serde(default)]
    default: bool,
    #[serde(default)]
    metadata: PhotoMetadata,
}

#[derive(Deserialize, Default)]
struct PhotoMetadata {
    #[serde(default)]
    primary: bool,
}

/// The person's own photo: never a drawn one, and the primary one first (the Google and the
/// Workspace profile can each have one).
fn own_photo(photos: &[ListedPhoto]) -> Option<&str> {
    photos
        .iter()
        .filter(|photo| !photo.default)
        .max_by_key(|photo| photo.metadata.primary)
        .map(|photo| photo.url.as_str())
}

/// Downloads a photo, without the sign-in: only `photo_link`'s address, and not past
/// `PHOTO_LIMIT`.
fn photo_bytes(link: &str) -> Result<Option<Vec<u8>>> {
    use std::io::Read as _;
    let response = ureq::get(link).timeout(HTTP_TIMEOUT).call()?;
    let mut bytes = Vec::new();
    response
        .into_reader()
        .take(PHOTO_LIMIT + 1)
        .read_to_end(&mut bytes)?;
    Ok((!bytes.is_empty() && bytes.len() as u64 <= PHOTO_LIMIT).then_some(bytes))
}

/// The parts that are real attachments: they have a file name and are downloaded
/// separately. Images embedded in the body (with a Content-ID, shown inline) are left out.
fn attachments(payload: &Part, message_id: &str) -> Vec<Attachment> {
    let mut parts = Vec::new();
    collect_parts(payload, &mut parts);
    parts
        .into_iter()
        .filter(|part| !part.filename.trim().is_empty())
        .filter(|part| {
            let inline = part
                .header("Content-Disposition")
                .is_some_and(|d| d.trim_start().to_ascii_lowercase().starts_with("inline"));
            !(inline && part.header("Content-ID").is_some())
        })
        .filter_map(|part| {
            let body = part.body.as_ref()?;
            let attachment_id = body.attachment_id.clone().filter(|a| is_attachment_id(a))?;
            Some(Attachment {
                message_id: message_id.to_string(),
                attachment_id,
                name: safe_file_name(&part.filename),
                mime: part.mime_type.clone(),
                size: body.size,
            })
        })
        .collect()
}

fn collect_parts<'a>(part: &'a Part, out: &mut Vec<&'a Part>) {
    out.push(part);
    for child in &part.parts {
        collect_parts(child, out);
    }
}

/// Attachment ids are long URL-safe tokens.
fn is_attachment_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 1024
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Thread ids go into request paths, so only accept what Gmail actually issues.
fn is_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.chars().all(|c| c.is_ascii_alphanumeric())
}

// ------------------------------------------------------------------ data

/// The store record of the list rows.
const ROWS: &str = "rows";
/// A row as kept: thread, whether it names the recipient, its history id, and the row.
type KeptRow = (String, bool, String, Summary);

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct Listing {
    #[serde(default)]
    threads: Vec<ListedThread>,
    next_page_token: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListedThread {
    id: String,
    /// Moves with every change to the thread, its labels included.
    #[serde(default)]
    history_id: String,
}

#[derive(Deserialize)]
struct Thread {
    id: String,
    #[serde(default)]
    messages: Vec<RawMessage>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawMessage {
    /// Gmail's own id for the message (not the Message-ID header).
    #[serde(default)]
    id: String,
    #[serde(default)]
    snippet: String,
    #[serde(default)]
    label_ids: Vec<String>,
    #[serde(default)]
    internal_date: String,
    payload: Option<Part>,
}

impl Part {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.value.as_str())
    }
}

impl RawMessage {
    fn header(&self, name: &str) -> &str {
        self.payload
            .iter()
            .flat_map(|p| &p.headers)
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.value.as_str())
            .unwrap_or("")
    }

    fn timestamp_ms(&self) -> i64 {
        self.internal_date.parse().unwrap_or(0)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Part {
    #[serde(default)]
    mime_type: String,
    #[serde(default)]
    filename: String,
    #[serde(default)]
    headers: Vec<Header>,
    body: Option<PartBody>,
    #[serde(default)]
    parts: Vec<Part>,
}

#[derive(Deserialize)]
struct Header {
    name: String,
    value: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PartBody {
    data: Option<String>,
    attachment_id: Option<String>,
    #[serde(default)]
    size: u64,
}

// ------------------------------------------------------------------ parsing

fn find_part<'a>(part: &'a Part, mime_type: &str) -> Option<&'a Part> {
    if part.mime_type == mime_type && part.body.as_ref().is_some_and(|b| b.data.is_some()) {
        return Some(part);
    }
    part.parts.iter().find_map(|p| find_part(p, mime_type))
}

fn decode_part(part: &Part) -> Option<Vec<u8>> {
    let data = part.body.as_ref()?.data.as_ref()?;
    URL_SAFE_NO_PAD.decode(data.trim_end_matches('=')).ok()
}

/// Prefers the plain-text alternative; otherwise converts HTML to text.
fn body_text(payload: &Part) -> String {
    if let Some(bytes) = find_part(payload, "text/plain").and_then(decode_part) {
        return String::from_utf8_lossy(&bytes).into_owned();
    }
    if let Some(bytes) = find_part(payload, "text/html").and_then(decode_part) {
        return html2text::from_read(bytes.as_slice(), 10_000).unwrap_or_default();
    }
    String::new()
}

/// The message as styled blocks: the HTML alternative when it has one (it carries
/// the formatting), otherwise the plain text.
fn body_blocks(payload: &Part) -> Vec<crate::rich::Block> {
    if let Some(bytes) = find_part(payload, "text/html").and_then(decode_part) {
        let blocks = crate::rich::from_html(&String::from_utf8_lossy(&bytes));
        if !blocks.is_empty() {
            return blocks;
        }
    }
    crate::rich::from_text(paragraphs(&body_text(payload)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn done_and_all_mail_go_message_by_message_as_gmail_does() {
        let thread = |messages: &[&[&str]]| Summary {
            id: "t".into(),
            sender: String::new(),
            subject: String::new(),
            snippet: String::new(),
            timestamp_ms: 0,
            message_count: messages.len(),
            unread: false,
            starred: false,
            labels: messages
                .iter()
                .flat_map(|m| m.iter().map(|l| l.to_string()))
                .collect(),
            message_labels: messages
                .iter()
                .map(|m| m.iter().map(|l| l.to_string()).collect())
                .collect(),
        };
        let done = |messages: &[&[&str]]| View::Done.takes(&thread(messages), None);
        assert!(done(&[&["CATEGORY_UPDATES"]]) && done(&[&[]]));
        // An archived message with your reply to it.
        assert!(done(&[&["IMPORTANT"], &["SENT"]]));
        assert!(!done(&[&["INBOX"]]) && !done(&[&["SENT"]]) && !done(&[&["TRASH"]]));
        let all = |messages: &[&[&str]]| View::AllMail.takes(&thread(messages), None);
        assert!(all(&[&["INBOX"]]) && all(&[&["SPAM"], &["SENT"]]) && !all(&[&["SPAM"]]));
        assert!(View::Done.syncs(None) && !View::Search.syncs(None));
    }

    #[test]
    fn a_failing_gmail_may_have_sent_it_and_a_refusing_one_has_not() {
        let unclear = |code| while_sending(api_error(code, "{}")).is::<MayHaveArrived>();
        assert!(unclear(500) && unclear(502) && unclear(503) && unclear(408));
        assert!(!unclear(400) && !unclear(403) && !unclear(404) && !unclear(429));
        assert!(is_gone(&api_error(404, "{}")) && !is_gone(&api_error(500, "404")));
        assert_eq!(api_error(418, "").to_string(), "Gmail error 418: ");
    }

    #[test]
    fn only_a_request_that_never_left_is_safe_to_send_again() {
        use ureq::ErrorKind as E;
        assert!(never_left(E::Dns) && never_left(E::ConnectionFailed));
        assert!(!never_left(E::Io) && !never_left(E::BadStatus) && !never_left(E::BadHeader));
        let unclear = anyhow::Error::new(Offline).context(MayHaveArrived);
        assert!(unclear.is::<Offline>() && unclear.is::<MayHaveArrived>());
        assert!(!before_sending(unclear).is::<MayHaveArrived>());
    }

    #[test]
    fn pkce_matches_rfc7636_example() {
        assert_eq!(
            pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn random_tokens_are_long_and_distinct() {
        let (a, b) = (random_token().unwrap(), random_token().unwrap());
        assert_eq!(a.len(), 43);
        assert_ne!(a, b);
    }

    #[test]
    fn sender_names() {
        assert_eq!(
            sender_name("\"Mira Kovač\" <mira@example.com>"),
            "Mira Kovač"
        );
        assert_eq!(sender_name("Stripe <no-reply@stripe.com>"), "Stripe");
        assert_eq!(sender_name("<a@b.co>"), "a@b.co");
        assert_eq!(sender_name("a@b.co"), "a@b.co");
        assert_eq!(sender_name(""), "Unknown sender");
    }

    #[test]
    fn entities() {
        assert_eq!(
            decode_entities("Tom &amp; Jerry&#39;s &lt;3 "),
            "Tom & Jerry’s <3"
        );
    }

    fn outgoing(to: &str, subject: &str) -> Outgoing {
        Outgoing {
            to: to.into(),
            subject: subject.into(),
            body: "Hello\nthere".into(),
            ..Outgoing::default()
        }
    }

    #[test]
    fn attachments_and_bcc_build_a_mixed_message() {
        let mut mail = outgoing("ana@example.com", "Files");
        mail.bcc = "hidden@example.com".into();
        mail.files.push(OutgoingFile {
            name: "Plan \"Q4\".pdf".into(),
            mime: "application/pdf\r\nX-Evil: 1".into(),
            bytes: vec![1, 2, 3],
        });
        let text = String::from_utf8(mail.to_rfc822(false, &[]).unwrap()).unwrap();
        assert!(text.contains("Bcc: hidden@example.com\r\n"));
        assert!(text.contains("Content-Type: multipart/mixed; boundary=\"mixed-"));
        // The odd content type is replaced and the file name is percent-encoded.
        assert!(
            text.contains(
                "Content-Type: application/octet-stream; name*=UTF-8''Plan%20%22Q4%22.pdf"
            )
        );
        assert!(!text.contains("X-Evil"));
        // A formatted message carries both a text and an HTML version.
        mail.html = Some("<div dir=\"ltr\"><b>Hi</b></div>".into());
        let text = String::from_utf8(mail.to_rfc822(false, &[]).unwrap()).unwrap();
        assert!(text.contains("Content-Type: multipart/alternative; boundary=\"alt-"));
        assert!(text.find("text/plain").unwrap() < text.find("text/html").unwrap());
        assert!(
            text.find("multipart/alternative").unwrap()
                < text.find("application/octet-stream").unwrap()
        );
        mail.files[0].bytes = vec![0; (ATTACHMENT_LIMIT + 1) as usize];
        assert!(mail.to_rfc822(false, &[]).is_err());
    }

    #[test]
    fn drafts_split_into_own_text_and_quote() {
        let (own, quoted) =
            split_quote("Hi,\n\nSee below.\n\nLuan\n\nOn Tue, Ana wrote:\n> old\n> text\n");
        assert_eq!(own, "Hi,\n\nSee below.\n\nLuan");
        assert_eq!(quoted.as_deref(), Some("On Tue, Ana wrote:\n> old\n> text"));
        let (own, quoted) = split_quote("Luan\n\n---------- Forwarded message ---------\nFrom: x");
        assert_eq!(own, "Luan");
        assert!(quoted.unwrap().starts_with("---------- Forwarded"));
        assert_eq!(split_quote("Just me"), ("Just me".to_string(), None));
    }

    #[test]
    fn a_draft_may_lack_a_recipient_but_a_sent_message_may_not() {
        let draft = outgoing("", "Idea");
        assert!(draft.to_rfc822(false, &[]).is_err());
        let text = String::from_utf8(draft.to_rfc822(true, &[]).unwrap()).unwrap();
        assert!(!text.contains("To:") && text.contains("Subject: =?UTF-8?B?"));
    }

    #[test]
    fn recipients_are_validated() {
        let ok = outgoing("Ana <ana@example.com>, bob@example.org; ", "x")
            .recipients()
            .unwrap();
        assert_eq!(ok.0, ["ana@example.com", "bob@example.org"]);
        let mut mail = outgoing("", "x");
        mail.cc = "cc@example.com".into();
        assert_eq!(mail.recipients().unwrap().1, ["cc@example.com"]);
        mail.bcc = "a@b.co\r\nX-Evil: 1".into();
        assert!(mail.recipients().is_err());
        for bad in [
            "",
            "not-an-address",
            "a@b",
            "a@b.co\r\nBcc: evil@x.co",
            "a b@c.co",
            "a@b..",
            "<>",
        ] {
            assert!(
                outgoing(bad, "x").recipients().is_err(),
                "{bad:?} should be refused"
            );
        }
    }

    #[test]
    fn outgoing_mail_cannot_inject_headers() {
        let mut mail = outgoing("ana@example.com", "Hi\r\nBcc: evil@example.com");
        mail.reply = Some(ReplyTo {
            thread_id: "18c2f0a9b7d3e4f1".into(),
            message_id: "<abc@mail.example.com>".into(),
        });
        let text = String::from_utf8(mail.to_rfc822(false, &[]).unwrap()).unwrap();
        let (headers, body) = text.split_once("\r\n\r\n").unwrap();
        // The typed line break never becomes a real header line.
        assert!(
            !headers
                .lines()
                .any(|line| line.to_lowercase().starts_with("bcc:"))
        );
        assert!(headers.contains("To: ana@example.com\r\n"));
        assert!(headers.contains("In-Reply-To: <abc@mail.example.com>"));
        assert!(headers.contains("Subject: =?UTF-8?B?"));
        use base64::engine::general_purpose::STANDARD;
        let decoded = STANDARD.decode(body.replace("\r\n", "")).unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), "Hello\r\nthere");

        mail.reply.as_mut().unwrap().message_id = "<a>\r\nBcc: evil@x.co".into();
        let text = String::from_utf8(mail.to_rfc822(false, &[]).unwrap()).unwrap();
        assert!(!text.contains("In-Reply-To") && !text.to_lowercase().contains("bcc"));
    }

    #[test]
    fn mailboxes_hold_the_right_threads() {
        let labels = |l: &[&str]| l.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let inbox_promo = labels(&["INBOX", "UNREAD", "CATEGORY_PROMOTIONS"]);
        assert_eq!(View::Inbox.holds(&inbox_promo, None), Some(true));
        assert_eq!(View::Promotions.holds(&inbox_promo, None), Some(true));
        assert_eq!(View::Primary.holds(&inbox_promo, None), Some(false));
        assert_eq!(View::Sent.holds(&inbox_promo, None), Some(false));
        let archived = labels(&["Label_7"]);
        assert_eq!(View::Inbox.holds(&archived, None), Some(false));
        assert_eq!(View::Label(0).holds(&archived, Some("Label_7")), Some(true));
        assert_eq!(View::Label(0).holds(&archived, None), None);
        assert_eq!(View::Done.holds(&archived, None), None);
        assert_eq!(View::Search.holds(&archived, None), None);
    }

    #[test]
    fn rate_limits_are_recognised() {
        assert!(is_rate_limited(429, ""));
        assert!(is_rate_limited(
            403,
            r#"{"error":{"message":"Quota exceeded for quota metric"}}"#
        ));
        assert!(!is_rate_limited(
            403,
            r#"{"error":{"message":"Insufficient Permission"}}"#
        ));
        assert!(
            api_error(403, "Quota exceeded")
                .to_string()
                .contains("busy")
        );
        assert_eq!(
            api_error(404, r#"{"error":{"message":"Not Found"}}"#).to_string(),
            "Gmail error 404: Not Found"
        );
    }

    #[test]
    fn address_lists_respect_quotes() {
        let list = people(
            "\"Doe, Jane\" <jane@example.com>, bob@example.org, Not An Address, \"Ana\" <ana@x.co>",
        );
        let names: Vec<_> = list
            .iter()
            .map(|p| (p.name.as_str(), p.address.as_str()))
            .collect();
        assert_eq!(
            names,
            [
                ("Doe, Jane", "jane@example.com"),
                ("", "bob@example.org"),
                ("Ana", "ana@x.co")
            ]
        );
    }

    #[test]
    fn unsubscribe_links_can_be_folded_and_hold_commas() {
        let github = "<mailto:unsub+AB12@reply.github.com>,\r\n <https://github.com/notifications/unsubscribe-auth/AB12>";
        assert_eq!(
            unsubscribe_link(github).as_deref(),
            Some("https://github.com/notifications/unsubscribe-auth/AB12")
        );
        assert_eq!(
            unsubscribe_link("<https://example.com/u?lists=1,2,\r\n 3>").as_deref(),
            Some("https://example.com/u?lists=1,2,3")
        );
        assert_eq!(
            unsubscribe_link("https://example.com/bare").as_deref(),
            Some("https://example.com/bare")
        );
    }

    #[test]
    fn unsubscribe_mail_follows_the_link_and_nothing_more() {
        let mail = unsubscribe_mail(
            "MAILTO:unsub+AB12@list.example.com?Subject=stop%20list+1&body=line%3A%201%0Aline%202&cc=x@evil.example&bcc=y@evil.example",
        )
        .unwrap();
        assert_eq!(mail.to, "unsub+AB12@list.example.com");
        assert_eq!(mail.subject, "stop list+1");
        assert_eq!(mail.body, "line: 1\nline 2");

        let bare = unsubscribe_mail("mailto:leave%2Bme@list.example.com").unwrap();
        assert_eq!(bare.to, "leave+me@list.example.com");
        assert_eq!(
            (bare.subject.as_str(), bare.body.as_str()),
            ("unsubscribe", "")
        );

        let tricky = unsubscribe_mail("mailto:u@list.example.com?subject=a%0D%0ABcc:%20x@y.zz");
        assert!(!tricky.unwrap().subject.contains(['\r', '\n']));
        for bad in [
            "mailto:",
            "mailto:a@list.example.com,b@evil.example",
            "mailto:a@list.example.com%2Cb@evil.example",
            "https://example.com/u",
        ] {
            assert!(unsubscribe_mail(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn unsubscribe_prefers_https_and_rejects_odd_links() {
        assert_eq!(
            unsubscribe_link(
                "<mailto:u@list.example.com?subject=stop>, <https://example.com/u?id=1>"
            )
            .as_deref(),
            Some("https://example.com/u?id=1")
        );
        assert_eq!(
            unsubscribe_link("<mailto:u@list.example.com>").as_deref(),
            Some("mailto:u@list.example.com")
        );
        assert_eq!(unsubscribe_link("<javascript:alert(1)>"), None);
        assert_eq!(unsubscribe_link(""), None);
    }

    #[test]
    fn attachment_names_are_made_safe() {
        assert_eq!(safe_file_name("../../etc/passwd"), "_.._etc_passwd");
        assert_eq!(safe_file_name(".hidden"), "hidden");
        assert_eq!(safe_file_name("  "), "attachment");
        assert_eq!(safe_file_name("Report Q4.pdf"), "Report Q4.pdf");
    }

    #[test]
    fn attachments_and_inline_images_are_told_apart() {
        let json = r#"{"mimeType":"multipart/mixed","parts":[
            {"mimeType":"text/plain","body":{"data":"SGk"}},
            {"mimeType":"image/png","filename":"logo.png","headers":[{"name":"Content-ID","value":"<logo1>"},{"name":"Content-Disposition","value":"inline"}],"body":{"attachmentId":"ANGjdJ_a","size":10}},
            {"mimeType":"application/pdf","filename":"Plan.pdf","headers":[{"name":"Content-Disposition","value":"attachment"}],"body":{"attachmentId":"ANGjdJ_b","size":4200}}]}"#;
        let part: Part = serde_json::from_str(json).unwrap();
        let found = attachments(&part, "18c2f0a9b7d3e4f1");
        assert_eq!(found.len(), 1);
        assert_eq!((found[0].name.as_str(), found[0].size), ("Plan.pdf", 4200));
    }

    #[test]
    fn ids_are_validated() {
        assert!(is_id("18c2f0a9b7d3e4f1"));
        assert!(!is_id(""));
        assert!(!is_id("../messages"));
        assert!(!is_id("abc?x=1"));
        assert!(is_label_id("Label_12") && is_label_id("CATEGORY_UPDATES"));
        assert!(!is_label_id("a b") && !is_label_id("x&q=1") && !is_label_id(""));
        assert!(is_draft_id("r-8765432109876543210") && is_draft_id("r:8765432109876543210"));
        assert!(
            !is_draft_id("r/../x")
                && !is_draft_id("r?x=1")
                && !is_draft_id("a b")
                && !is_draft_id("")
        );
        assert_eq!(Change::Trash.inverse(), Some(Change::Untrash));
        assert_eq!(Change::MarkRead.inverse(), None);
    }

    #[test]
    fn paragraphs_drop_quotes() {
        let text =
            "Hi Luan,\n\nSounds good.\nSee you then.\n\nOn Tue, Nov 18 Mira wrote:\n> old\n> stuff";
        assert_eq!(
            paragraphs(text),
            vec!["Hi Luan,", "Sounds good.\nSee you then."]
        );
    }

    #[test]
    fn thread_json_is_parsed() {
        let json = r#"{"id":"t1","messages":[{"snippet":"Hello &amp; welcome","labelIds":["INBOX","UNREAD"],
            "internalDate":"1700000000000","payload":{"mimeType":"multipart/alternative",
            "headers":[{"name":"From","value":"Ana <ana@example.com>"},{"name":"subject","value":"Trip"}],
            "parts":[{"mimeType":"text/html","body":{"data":"PGI-SGk8L2I-"}},
                     {"mimeType":"text/plain","body":{"data":"SGkgdGhlcmUKClNlZSB5b3U="}}]}}]}"#;
        let thread: Thread = serde_json::from_str(json).unwrap();
        let message = &thread.messages[0];
        assert_eq!(message.header("From"), "Ana <ana@example.com>");
        assert_eq!(message.header("Subject"), "Trip");
        assert_eq!(message.timestamp_ms(), 1_700_000_000_000);
        let text = body_text(message.payload.as_ref().unwrap());
        assert_eq!(paragraphs(&text), vec!["Hi there", "See you"]);
    }

    #[test]
    fn html_only_mail_becomes_text() {
        let json =
            r#"{"mimeType":"text/html","body":{"data":"PHA-SGVsbG8gPGI-d29ybGQ8L2I-PC9wPg"}}"#;
        let part: Part = serde_json::from_str(json).unwrap();
        assert!(body_text(&part).contains("Hello"));
    }

    #[test]
    fn sign_in_url_has_pkce_and_loopback_redirect() {
        let config = Config {
            client_id: "id.apps.googleusercontent.com".into(),
            client_secret: "secret".into(),
        };
        let (sign_in, url) = SignIn::start(&config, false, None).unwrap();
        let url = url::Url::parse(&url).unwrap();
        let get = |k: &str| {
            url.query_pairs()
                .find(|(n, _)| n == k)
                .unwrap()
                .1
                .into_owned()
        };
        assert!(get("redirect_uri").starts_with("http://127.0.0.1:"));
        assert_eq!(get("code_challenge_method"), "S256");
        assert_eq!(get("code_challenge"), pkce_challenge(&sign_in.verifier));
        assert_eq!(get("state"), sign_in.state);
        assert!(!url.as_str().contains("secret"));
        // Full mail access (permanent delete) is only asked for when it is needed.
        assert_eq!(get("scope"), SCOPE);
        assert!(SCOPE.contains("userinfo.profile"));
        let (_, full) = SignIn::start(&config, true, None).unwrap();
        assert!(full.contains("mail.google.com"));
        // Signing in again points at that account, and takes no other.
        let (_, again) = SignIn::start(&config, false, Some("a@example.com")).unwrap();
        assert!(again.contains("login_hint=a%40example.com"));
        assert!(check_same_account("a@example.com", "A@Example.com").is_ok());
        assert!(check_same_account("a@example.com", "b@example.com").is_err());
    }

    #[test]
    fn redirect_with_wrong_state_is_ignored() {
        let config = Config {
            client_id: "id".into(),
            client_secret: "secret".into(),
        };
        let (sign_in, _) = SignIn::start(&config, false, None).unwrap();
        let port = sign_in.listener.local_addr().unwrap().port();
        let state = sign_in.state.clone();
        let waiter = std::thread::spawn(move || sign_in.wait_for_code());
        let hit = |path: String| {
            let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
            write!(s, "GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
            let mut reply = String::new();
            let _ = std::io::Read::read_to_string(&mut s, &mut reply);
            reply
        };
        assert!(hit("/?code=evil&state=wrong".into()).starts_with("HTTP/1.1 404"));
        assert!(hit(format!("/?code=good&state={state}")).starts_with("HTTP/1.1 200"));
        assert_eq!(waiter.join().unwrap().unwrap(), "good");
    }

    #[test]
    fn profile_photos_only_come_from_google() {
        assert_eq!(
            photo_link("https://lh3.googleusercontent.com/a/abc=s96-c").as_deref(),
            Some("https://lh3.googleusercontent.com/a/abc=s128-c")
        );
        assert!(photo_link("http://lh3.googleusercontent.com/a/abc").is_none());
        assert!(photo_link("https://evil.example.com/a.png").is_none());
        assert!(photo_link("https://googleusercontent.com.evil.example/a").is_none());
        assert_eq!(
            photo_link("https://lh3.googleusercontent.com/a/photo.jpg?sz=50").as_deref(),
            Some("https://lh3.googleusercontent.com/a/photo.jpg=s128-c")
        );
    }

    #[test]
    fn the_users_own_photo_is_taken_over_the_drawn_letter() {
        let pick = |json: &str| {
            let found: ProfilePhotos = serde_json::from_str(json).unwrap();
            own_photo(&found.photos).map(String::from)
        };
        let letter = r#"{"url":"letter","default":true,"metadata":{"primary":true}}"#;
        assert_eq!(pick(&format!(r#"{{"photos":[{letter}]}}"#)), None);
        assert_eq!(
            pick(&format!(r#"{{"photos":[{letter},{{"url":"mine"}}]}}"#)).as_deref(),
            Some("mine")
        );
        let two = r#"{"photos":[{"url":"a"},{"url":"b","metadata":{"primary":true}}]}"#;
        assert_eq!(pick(two).as_deref(), Some("b"));
        assert_eq!(pick("{}"), None);
    }
}
