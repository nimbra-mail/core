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

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, anyhow, bail};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use sha2::{Digest, Sha256};

const AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const API: &str = "https://gmail.googleapis.com/gmail/v1/users/me";
/// Sidebar unread counts stop here (20 pages of thread ids).
const COUNT_CAP: u32 = 10_000;
/// Read, archive and label. No send, no permanent delete.
const SCOPE: &str = "https://www.googleapis.com/auth/gmail.modify";
const KEYCHAIN_SERVICE: &str = "nimbra";
const KEYCHAIN_USER: &str = "gmail-refresh-token";
const SIGN_IN_TIMEOUT: Duration = Duration::from_secs(300);
const HTTP_TIMEOUT: Duration = Duration::from_secs(20);
/// Cap on how much of one message is rendered.
const MAX_BODY_CHARS: usize = 20_000;

/// How many pages of the change feed to read before giving up and fetching afresh.
const HISTORY_PAGES: usize = 10;

/// The change feed cannot be used from the given point (too old, or too much changed).
#[derive(Debug)]
pub struct HistoryExpired;

impl std::fmt::Display for HistoryExpired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("mailbox history is too old to sync from")
    }
}

impl std::error::Error for HistoryExpired {}

/// What changed since a point in the change feed.
#[derive(Default, Debug)]
pub struct Changes {
    /// The point to sync from next time.
    pub latest: String,
    /// Threads with any change: new or deleted messages, or labels added or removed.
    pub threads: Vec<String>,
    /// Threads that received a new unread message in the inbox (for notifications).
    pub new_unread_inbox: Vec<String>,
}

impl View {
    /// Whether a thread with these labels belongs in this mailbox. `None` for mailboxes
    /// that are a search rather than a label (Done, Snoozed, search results), which are
    /// always fetched afresh.
    pub fn holds(&self, labels: &[String], label_id: Option<&str>) -> Option<bool> {
        let has = |l: &str| labels.iter().any(|x| x == l);
        Some(match self {
            View::Inbox => has("INBOX"),
            View::Primary => has("INBOX") && has("CATEGORY_PERSONAL"),
            View::Updates => has("INBOX") && has("CATEGORY_UPDATES"),
            View::Promotions => has("INBOX") && has("CATEGORY_PROMOTIONS"),
            View::Social => has("INBOX") && has("CATEGORY_SOCIAL"),
            View::Starred => has("STARRED"),
            View::Drafts => has("DRAFT"),
            View::Sent => has("SENT"),
            View::Label(_) => has(label_id?),
            View::Snoozed | View::Done | View::Search => return None,
        })
    }
}

/// Returned when Google no longer accepts the stored sign-in (revoked, or the weekly
/// expiry of an app in Testing mode). The app reacts by asking the user to sign in again.
#[derive(Debug)]
pub struct SignedOut;

impl std::fmt::Display for SignedOut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Your Google sign-in has expired")
    }
}

impl std::error::Error for SignedOut {}

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
        let file = std::env::var_os("HOME")
            .map(|home| std::path::Path::new(&home).join(".config/nimbra/oauth.env"))
            .and_then(|path| std::fs::read_to_string(path).ok())
            .unwrap_or_default();
        let lookup = |key: &str| {
            std::env::var(key).ok().or_else(|| {
                file.lines().find_map(|line| {
                    let (name, value) = line.split_once('=')?;
                    (name.trim() == key).then(|| value.trim().trim_matches('"').to_string())
                })
            })
        };
        let client_id = lookup("NIMBRA_GOOGLE_CLIENT_ID").filter(|v| !v.is_empty())?;
        let client_secret = lookup("NIMBRA_GOOGLE_CLIENT_SECRET").filter(|v| !v.is_empty())?;
        Some(Self {
            client_id,
            client_secret,
        })
    }
}

// ------------------------------------------------------------------ keychain

fn keychain() -> Result<keyring::Entry> {
    keyring::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_USER).context("opening the system keychain")
}

pub fn stored_refresh_token() -> Option<String> {
    keychain().ok()?.get_password().ok()
}

fn store_refresh_token(token: &str) -> Result<()> {
    keychain()?
        .set_password(token)
        .context("saving the sign-in to the system keychain")
}

pub fn forget_refresh_token() {
    if let Ok(entry) = keychain() {
        let _ = entry.delete_credential();
    }
}

// ------------------------------------------------------------------ oauth

fn random_token() -> Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|e| anyhow!("no secure random source: {e}"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn pkce_challenge(verifier: &str) -> String {
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
                return Err(SignedOut.into());
            }
            bail!("Google rejected the sign-in ({code} {error})")
        }
        Err(_) => bail!("Could not reach Google. Check your connection."),
    }
}

/// A sign-in in progress: the browser has been pointed at `url` and we are waiting for
/// Google to redirect back to our loopback listener.
pub struct SignIn {
    listener: TcpListener,
    redirect_uri: String,
    verifier: String,
    state: String,
}

impl SignIn {
    /// Starts listening and returns the URL to open in the user's browser.
    pub fn start(config: &Config) -> Result<(Self, String)> {
        // Loopback only, on a port picked by the OS.
        let listener =
            TcpListener::bind(("127.0.0.1", 0)).context("opening a local port for sign-in")?;
        listener.set_nonblocking(true)?;
        let redirect_uri = format!("http://127.0.0.1:{}", listener.local_addr()?.port());
        let verifier = random_token()?;
        let state = random_token()?;
        let url = url::Url::parse_with_params(
            AUTH_URL,
            &[
                ("client_id", config.client_id.as_str()),
                ("redirect_uri", redirect_uri.as_str()),
                ("response_type", "code"),
                ("scope", SCOPE),
                ("code_challenge", pkce_challenge(&verifier).as_str()),
                ("code_challenge_method", "S256"),
                ("state", state.as_str()),
                ("access_type", "offline"),
                ("prompt", "consent"),
            ],
        )?;
        Ok((
            Self {
                listener,
                redirect_uri,
                verifier,
                state,
            },
            url.into(),
        ))
    }

    /// Blocks until the browser comes back (or the timeout passes), exchanges the code and
    /// stores the refresh token in the keychain.
    pub fn finish(self, config: &Config) -> Result<Client> {
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
        store_refresh_token(&refresh)?;
        let client = Client::new(config.clone(), refresh);
        client.remember(tokens.access_token, tokens.expires_in);
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

fn respond(mut stream: &TcpStream, status: &str, message: &str) {
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

/// Keeps short, printable ASCII only, for text that came from outside and is shown in the UI.
fn sanitize(text: &str) -> String {
    text.chars()
        .filter(|c| c.is_ascii_alphanumeric() || " _-.".contains(*c))
        .take(80)
        .collect()
}

// ------------------------------------------------------------------ client

pub struct Client {
    config: Config,
    refresh_token: String,
    access: Mutex<Option<(String, Instant)>>,
}

impl Client {
    pub fn new(config: Config, refresh_token: String) -> Self {
        Self {
            config,
            refresh_token,
            access: Mutex::new(None),
        }
    }

    fn remember(&self, access_token: String, expires_in: u64) {
        // Refresh a minute early so a token never expires mid-request.
        let expiry = Instant::now() + Duration::from_secs(expires_in.saturating_sub(60));
        *self.access.lock().unwrap() = Some((access_token, expiry));
    }

    fn access_token(&self) -> Result<String> {
        if let Some((token, expiry)) = self.access.lock().unwrap().as_ref()
            && Instant::now() < *expiry
        {
            return Ok(token.clone());
        }
        let tokens = token_request(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", &self.refresh_token),
            ("client_id", &self.config.client_id),
            ("client_secret", &self.config.client_secret),
        ])
        .inspect_err(|e| {
            if e.is::<SignedOut>() {
                forget_refresh_token();
            }
        })?;
        self.remember(tokens.access_token.clone(), tokens.expires_in);
        Ok(tokens.access_token)
    }

    fn send<T: serde::de::DeserializeOwned>(
        &self,
        request: ureq::Request,
        body: Option<serde_json::Value>,
    ) -> Result<T> {
        let request = request
            .timeout(HTTP_TIMEOUT)
            .set("Authorization", &format!("Bearer {}", self.access_token()?));
        let result = match body {
            Some(body) => request.send_json(body),
            None => request.call(),
        };
        match result {
            Ok(response) => response.into_json().context("reading Gmail's reply"),
            Err(ureq::Error::Status(401, _)) => {
                *self.access.lock().unwrap() = None;
                Err(SignedOut.into())
            }
            Err(ureq::Error::Status(code, response)) => {
                #[derive(Deserialize)]
                struct ApiError {
                    error: ApiErrorBody,
                }
                #[derive(Deserialize)]
                struct ApiErrorBody {
                    message: String,
                }
                let message = response
                    .into_json::<ApiError>()
                    .map(|e| e.error.message)
                    .unwrap_or_default();
                bail!(
                    "Gmail error {code}: {}",
                    message.chars().take(160).collect::<String>()
                )
            }
            Err(_) => bail!("Could not reach Gmail. Check your connection."),
        }
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
    pub fn threads(
        &self,
        view: View,
        label_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<Summary>> {
        #[derive(Deserialize, Default)]
        struct Listing {
            #[serde(default)]
            threads: Vec<ThreadRef>,
        }
        #[derive(Deserialize)]
        struct ThreadRef {
            id: String,
        }
        let request = ureq::get(&format!("{API}/threads")).query("maxResults", &limit.to_string());
        let request = match view {
            View::Inbox => request.query("labelIds", "INBOX"),
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
        };
        let listing: Listing = self.send(request, None)?;
        // In Sent and Drafts the interesting person is the recipient, not you.
        let recipient = matches!(view, View::Sent | View::Drafts);
        let ids: Vec<String> = listing.threads.into_iter().map(|t| t.id).collect();

        // Fetch thread metadata a few at a time; one request per thread is the only way
        // to get subject and sender without the batch endpoint.
        self.access_token()?;
        let mut summaries: Vec<Option<Result<Summary>>> = Vec::new();
        summaries.resize_with(ids.len(), || None);
        let workers = 6.min(ids.len().max(1));
        std::thread::scope(|scope| {
            for (ids, out) in ids
                .chunks(ids.len().div_ceil(workers).max(1))
                .zip(summaries.chunks_mut(ids.len().div_ceil(workers).max(1)))
            {
                scope.spawn(move || {
                    for (id, slot) in ids.iter().zip(out) {
                        *slot = Some(self.summary(id, recipient));
                    }
                });
            }
        });
        summaries.into_iter().flatten().collect()
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
            Change::Untrash => ("untrash", Some(serde_json::json!({}))),
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
        #[derive(Deserialize)]
        struct Full {
            message: RawMessage,
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
            subject: message.header("Subject").trim().to_string(),
            body,
            quoted,
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
        let mut message =
            serde_json::json!({ "raw": URL_SAFE_NO_PAD.encode(outgoing.to_rfc822(true)?) });
        if let Some(reply) = &outgoing.reply {
            if !is_id(&reply.thread_id) {
                bail!("unexpected thread id");
            }
            message["threadId"] = reply.thread_id.clone().into();
        }
        let request = match id {
            Some(id) if is_draft_id(id) => ureq::put(&format!("{API}/drafts/{id}")),
            Some(_) => bail!("unexpected draft id"),
            None => ureq::post(&format!("{API}/drafts")),
        };
        let saved: Saved = self.send(request, Some(serde_json::json!({ "message": message })))?;
        Ok(saved.id)
    }

    /// Sends an edited draft: saves the edits over it, then asks Gmail to send that draft,
    /// which also removes it from Drafts. Runs only when the user presses Send.
    pub fn send_draft(&self, id: &str, outgoing: &Outgoing) -> Result<()> {
        outgoing.recipients()?;
        let id = self.save_draft(Some(id), outgoing)?;
        self.send::<serde_json::Value>(
            ureq::post(&format!("{API}/drafts/send")),
            Some(serde_json::json!({ "id": id })),
        )?;
        Ok(())
    }

    /// Sends a plain-text message. Runs only when the user presses Send.
    pub fn send_message(&self, outgoing: &Outgoing) -> Result<()> {
        let raw = URL_SAFE_NO_PAD.encode(outgoing.to_rfc822(false)?);
        let mut body = serde_json::json!({ "raw": raw });
        if let Some(reply) = &outgoing.reply {
            if !is_id(&reply.thread_id) {
                bail!("unexpected thread id");
            }
            body["threadId"] = reply.thread_id.clone().into();
        }
        self.send::<serde_json::Value>(ureq::post(&format!("{API}/messages/send")), Some(body))?;
        Ok(())
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

/// A saved draft, opened for editing.
pub struct Draft {
    pub id: String,
    pub to: String,
    pub subject: String,
    /// The part the user wrote (including any signature).
    pub body: String,
    /// The earlier message it quotes or forwards, kept collapsed in the composer.
    pub quoted: Option<String>,
    pub reply: Option<ReplyTo>,
}

/// Splits a draft's text into what the user wrote and the quoted earlier message.
fn split_quote(text: &str) -> (String, Option<String>) {
    let lines: Vec<&str> = text.lines().collect();
    let start = lines.iter().position(|line| {
        let line = line.trim();
        line.starts_with('>')
            || (line.starts_with("On ") && line.ends_with("wrote:"))
            || line.contains("Forwarded message")
            || line.starts_with("-----Original Message")
    });
    let join = |part: &[&str]| part.join("\n").trim_end().to_string();
    match start {
        Some(start) => (
            join(&lines[..start]),
            Some(join(&lines[start..])).filter(|q| !q.is_empty()),
        ),
        None => (join(&lines), None),
    }
}

/// A message the user wrote.
pub struct Outgoing {
    pub to: String,
    pub subject: String,
    pub body: String,
    pub reply: Option<ReplyTo>,
}

#[derive(Clone, serde::Serialize, Deserialize)]
pub struct ReplyTo {
    pub thread_id: String,
    /// Message-ID of the message being answered.
    pub message_id: String,
}

impl Outgoing {
    /// The recipients, validated. Rejects anything that is not a plain address, which also
    /// rules out smuggling extra headers in through the To field.
    pub fn recipients(&self) -> Result<Vec<String>> {
        let recipients: Vec<String> = self
            .to
            .split([',', ';'])
            .map(str::trim)
            .filter(|part| !part.is_empty())
            .map(address_of)
            .collect();
        if recipients.is_empty() {
            bail!("Add at least one recipient.");
        }
        for address in &recipients {
            if !is_address(address) {
                bail!("“{}” is not a valid email address.", sanitize(address));
            }
        }
        Ok(recipients)
    }

    /// Builds the RFC 5322 message. Gmail fills in From and Date.
    /// A draft may still have no (or an unfinished) recipient; a message being sent may not.
    fn to_rfc822(&self, draft: bool) -> Result<Vec<u8>> {
        use base64::engine::general_purpose::STANDARD;
        let recipients = match self.recipients() {
            Ok(recipients) => recipients,
            Err(_) if draft => Vec::new(),
            Err(error) => return Err(error),
        };
        let mut message = String::new();
        if !recipients.is_empty() {
            message.push_str(&format!("To: {}\r\n", recipients.join(", ")));
        }
        // Encoded-word form keeps the header ASCII and free of line breaks whatever was typed.
        message.push_str(&format!(
            "Subject: =?UTF-8?B?{}?=\r\n",
            STANDARD.encode(clean_header(&self.subject))
        ));
        if let Some(reply) = &self.reply
            && is_message_id(&reply.message_id)
        {
            message.push_str(&format!("In-Reply-To: {}\r\n", reply.message_id));
            message.push_str(&format!("References: {}\r\n", reply.message_id));
        }
        message.push_str("MIME-Version: 1.0\r\n");
        message.push_str("Content-Type: text/plain; charset=UTF-8\r\n");
        message.push_str("Content-Transfer-Encoding: base64\r\n\r\n");
        let encoded = STANDARD.encode(self.body.replace("\r\n", "\n").replace('\n', "\r\n"));
        for line in encoded.as_bytes().chunks(76) {
            message.push_str(std::str::from_utf8(line).unwrap_or_default());
            message.push_str("\r\n");
        }
        Ok(message.into_bytes())
    }
}

/// Collapses a typed header value to one line without control characters.
fn clean_header(value: &str) -> String {
    value
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// `Name <a@b.co>` or `a@b.co` to `a@b.co`.
/// A sender or recipient: display name (may be empty) and address.
#[derive(Clone, Debug, Default, PartialEq, serde::Serialize, Deserialize)]
pub struct Person {
    pub name: String,
    pub address: String,
}

impl Person {
    /// The name if there is one, else the address.
    pub fn label(&self) -> &str {
        if self.name.is_empty() {
            &self.address
        } else {
            &self.name
        }
    }
}

/// A file attached to a message.
#[derive(Clone, Debug, PartialEq, serde::Serialize, Deserialize)]
pub struct Attachment {
    /// Gmail's id of the message it belongs to.
    pub message_id: String,
    pub attachment_id: String,
    pub name: String,
    pub mime: String,
    pub size: u64,
}

fn person(value: &str) -> Person {
    let address = address_of(value);
    let name = value
        .split('<')
        .next()
        .unwrap_or("")
        .trim()
        .trim_matches('"')
        .trim()
        .to_string();
    let name = if name == address { String::new() } else { name };
    Person {
        name: decode_entities(&name),
        address,
    }
}

/// Splits an address list on commas that are not inside quotes, keeping valid addresses.
fn people(list: &str) -> Vec<Person> {
    let mut parts = Vec::new();
    let (mut start, mut quoted) = (0, false);
    for (i, c) in list.char_indices() {
        match c {
            '"' => quoted = !quoted,
            ',' if !quoted => {
                parts.push(&list[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(&list[start..]);
    parts
        .into_iter()
        .filter(|p| !p.trim().is_empty())
        .map(person)
        .filter(|p| is_address(&p.address))
        .collect()
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

/// A file name that is safe to create in a folder: no path separators, no leading dots,
/// no control characters, and not too long.
pub fn safe_file_name(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_control() || "/\\:".contains(c) {
                '_'
            } else {
                c
            }
        })
        .collect();
    let cleaned = cleaned.trim().trim_start_matches('.').trim();
    let cleaned: String = cleaned.chars().take(120).collect();
    if cleaned.is_empty() {
        "attachment".to_string()
    } else {
        cleaned
    }
}

/// The best way out of a mailing list: an https link if offered, else a mailto address.
fn unsubscribe_link(header: &str) -> Option<String> {
    let links: Vec<&str> = header
        .split(',')
        .map(|p| p.trim().trim_matches(['<', '>']).trim())
        .collect();
    links
        .iter()
        .find(|l| l.to_ascii_lowercase().starts_with("https://"))
        .or_else(|| {
            links
                .iter()
                .find(|l| l.to_ascii_lowercase().starts_with("mailto:"))
        })
        .filter(|l| l.len() <= 2000 && !l.chars().any(|c| c.is_whitespace() || c.is_control()))
        .map(|l| l.to_string())
}

/// Attachment ids are long URL-safe tokens.
fn is_attachment_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 1024
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn address_of(value: &str) -> String {
    let value = value.trim();
    match (value.rfind('<'), value.rfind('>')) {
        (Some(open), Some(close)) if open < close => value[open + 1..close].trim().to_string(),
        _ => value.to_string(),
    }
}

/// A deliberately strict address check: one `@`, a dotted domain, and only characters
/// that cannot break out of a header.
fn is_address(address: &str) -> bool {
    let Some((local, domain)) = address.split_once('@') else {
        return false;
    };
    let ok = |part: &str, extra: &str| {
        !part.is_empty()
            && part
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || extra.contains(c))
    };
    address.len() <= 254
        && ok(local, ".!#$%&'*+/=?^_`{|}~-")
        && ok(domain, ".-")
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
}

fn is_message_id(value: &str) -> bool {
    value.len() <= 998
        && value.starts_with('<')
        && value.ends_with('>')
        && value.chars().all(|c| c.is_ascii_graphic())
}

/// Thread ids go into request paths, so only accept what Gmail actually issues.
fn is_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.chars().all(|c| c.is_ascii_alphanumeric())
}

// ------------------------------------------------------------------ data

/// The mailboxes the sidebar can show.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum View {
    Inbox,
    /// Gmail's inbox categories.
    Primary,
    Updates,
    Promotions,
    Social,
    /// One of the user's own labels, by position in the fetched label list.
    Label(usize),
    /// Results of a search; the query travels alongside.
    Search,
    Starred,
    Snoozed,
    Drafts,
    Sent,
    Done,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Change {
    Archive,
    Unarchive,
    Trash,
    Untrash,
    Star,
    Unstar,
    MarkRead,
    MarkUnread,
    Spam,
    NotSpam,
}

impl Change {
    /// The change that reverses this one, for undo.
    pub fn inverse(self) -> Option<Change> {
        match self {
            Change::Archive => Some(Change::Unarchive),
            Change::Unarchive => Some(Change::Archive),
            Change::Trash => Some(Change::Untrash),
            Change::Untrash => Some(Change::Trash),
            Change::Star => Some(Change::Unstar),
            Change::Unstar => Some(Change::Star),
            Change::MarkRead | Change::MarkUnread => None,
            Change::Spam => Some(Change::NotSpam),
            Change::NotSpam => Some(Change::Spam),
        }
    }
}

#[derive(Clone, serde::Serialize, Deserialize)]
pub struct Label {
    pub id: String,
    pub name: String,
}

pub struct Summary {
    pub id: String,
    pub sender: String,
    pub subject: String,
    pub snippet: String,
    pub timestamp_ms: i64,
    pub message_count: usize,
    pub unread: bool,
    pub starred: bool,
    /// Every label on any message in the thread, to tell which mailboxes it belongs to.
    pub labels: Vec<String>,
}

pub struct Message {
    pub from: Person,
    pub to: Vec<Person>,
    pub cc: Vec<Person>,
    pub reply_to: Option<Person>,
    pub attachments: Vec<Attachment>,
    /// Where to unsubscribe (`https:` or `mailto:`), from the List-Unsubscribe header.
    pub unsubscribe: Option<String>,
    /// The sender's bare email address, for replying.
    pub address: String,
    /// The RFC 5322 Message-ID header, for threading a reply.
    pub message_id: String,
    /// Everyone else the message was addressed to (To and Cc), for reply-all.
    pub others: Vec<String>,
    pub sender: String,
    pub snippet: String,
    pub timestamp_ms: i64,
    pub blocks: Vec<crate::rich::Block>,
    /// The original HTML body, if the message has one, for "Show original".
    pub html: Option<String>,
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

/// `"Mira Kovač" <mira@example.com>` becomes `Mira Kovač`; a bare address stays as is.
fn sender_name(from: &str) -> String {
    let name = from
        .split('<')
        .next()
        .unwrap_or("")
        .trim()
        .trim_matches('"')
        .trim();
    let name = if name.is_empty() {
        from.trim().trim_matches(['<', '>'])
    } else {
        name
    };
    if name.is_empty() {
        "Unknown sender".to_string()
    } else {
        name.to_string()
    }
}

/// Gmail snippets are HTML-escaped.
fn decode_entities(text: &str) -> String {
    text.replace("&#39;", "’")
        .replace("&quot;", "\"")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&nbsp;", " ")
        .replace("&amp;", "&")
        .replace(['\u{200c}', '\u{200b}', '\u{feff}', '\u{34f}'], "")
        .trim()
        .to_string()
}

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

/// Splits a message into paragraphs and drops the quoted reply chain.
fn paragraphs(text: &str) -> Vec<String> {
    let text: String = text.chars().take(MAX_BODY_CHARS).collect();
    let mut out = Vec::new();
    let mut current = String::new();
    for line in text.lines() {
        let line = line.trim_end();
        let trimmed = line.trim_start();
        if trimmed.starts_with('>') {
            continue;
        }
        // "On Tue, ... wrote:" introduces the quoted history; stop there.
        if trimmed.starts_with("On ") && trimmed.ends_with("wrote:") {
            break;
        }
        if trimmed.is_empty() {
            if !current.is_empty() {
                out.push(std::mem::take(&mut current));
            }
        } else {
            if !current.is_empty() {
                current.push('\n');
            }
            current.push_str(line);
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

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
            reply: None,
        }
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
        assert!(draft.to_rfc822(false).is_err());
        let text = String::from_utf8(draft.to_rfc822(true).unwrap()).unwrap();
        assert!(!text.contains("To:") && text.contains("Subject: =?UTF-8?B?"));
    }

    #[test]
    fn recipients_are_validated() {
        let ok = outgoing("Ana <ana@example.com>, bob@example.org; ", "x")
            .recipients()
            .unwrap();
        assert_eq!(ok, ["ana@example.com", "bob@example.org"]);
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
        let text = String::from_utf8(mail.to_rfc822(false).unwrap()).unwrap();
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
        let text = String::from_utf8(mail.to_rfc822(false).unwrap()).unwrap();
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
        let (sign_in, url) = SignIn::start(&config).unwrap();
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
    }

    #[test]
    fn redirect_with_wrong_state_is_ignored() {
        let config = Config {
            client_id: "id".into(),
            client_secret: "secret".into(),
        };
        let (sign_in, _) = SignIn::start(&config).unwrap();
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
}
