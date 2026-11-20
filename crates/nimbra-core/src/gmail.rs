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
/// Read, archive and label. No send, no permanent delete.
const SCOPE: &str = "https://www.googleapis.com/auth/gmail.modify";
const KEYCHAIN_SERVICE: &str = "nimbra";
const KEYCHAIN_USER: &str = "gmail-refresh-token";
const SIGN_IN_TIMEOUT: Duration = Duration::from_secs(300);
const HTTP_TIMEOUT: Duration = Duration::from_secs(20);
/// Cap on how much of one message is rendered.
const MAX_BODY_CHARS: usize = 20_000;

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

    pub fn email_address(&self) -> Result<String> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Profile {
            email_address: String,
        }
        Ok(self
            .send::<Profile>(ureq::get(&format!("{API}/profile")), None)?
            .email_address)
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

    fn summary(&self, id: &str, recipient: bool) -> Result<Summary> {
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
        Ok(thread
            .messages
            .iter()
            .map(|m| Message {
                sender: sender_name(m.header("From")),
                address: address_of(m.header("From")),
                message_id: m.header("Message-ID").trim().to_string(),
                snippet: decode_entities(&m.snippet),
                timestamp_ms: m.timestamp_ms(),
                blocks: m.payload.as_ref().map(body_blocks).unwrap_or_default(),
            })
            .collect())
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
        let (action, body) = match change {
            Change::Archive => labels(&[], &["INBOX"]),
            Change::Unarchive => labels(&["INBOX"], &[]),
            Change::Star => labels(&["STARRED"], &[]),
            Change::Unstar => labels(&[], &["STARRED"]),
            Change::MarkRead => labels(&[], &["UNREAD"]),
            Change::Trash => ("trash", None),
            Change::Untrash => ("untrash", None),
        };
        self.send::<serde_json::Value>(ureq::post(&format!("{API}/threads/{id}/{action}")), body)?;
        Ok(())
    }

    /// Sends a plain-text message. Runs only when the user presses Send.
    pub fn send_message(&self, outgoing: &Outgoing) -> Result<()> {
        let raw = URL_SAFE_NO_PAD.encode(outgoing.to_rfc822()?);
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

/// Label ids go into request queries, so only accept the characters Gmail uses.
fn is_label_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// A message the user wrote.
pub struct Outgoing {
    pub to: String,
    pub subject: String,
    pub body: String,
    pub reply: Option<ReplyTo>,
}

#[derive(Clone)]
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
    fn to_rfc822(&self) -> Result<Vec<u8>> {
        use base64::engine::general_purpose::STANDARD;
        let recipients = self.recipients()?;
        let mut message = String::new();
        message.push_str(&format!("To: {}\r\n", recipients.join(", ")));
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
            Change::MarkRead => None,
        }
    }
}

#[derive(Clone)]
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
}

pub struct Message {
    /// The sender's bare email address, for replying.
    pub address: String,
    /// The RFC 5322 Message-ID header, for threading a reply.
    pub message_id: String,
    pub sender: String,
    pub snippet: String,
    pub timestamp_ms: i64,
    pub blocks: Vec<crate::rich::Block>,
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
    #[serde(default)]
    snippet: String,
    #[serde(default)]
    label_ids: Vec<String>,
    #[serde(default)]
    internal_date: String,
    payload: Option<Part>,
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
struct PartBody {
    data: Option<String>,
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
        let text = String::from_utf8(mail.to_rfc822().unwrap()).unwrap();
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
        let text = String::from_utf8(mail.to_rfc822().unwrap()).unwrap();
        assert!(!text.contains("In-Reply-To") && !text.to_lowercase().contains("bcc"));
    }

    #[test]
    fn ids_are_validated() {
        assert!(is_id("18c2f0a9b7d3e4f1"));
        assert!(!is_id(""));
        assert!(!is_id("../messages"));
        assert!(!is_id("abc?x=1"));
        assert!(is_label_id("Label_12") && is_label_id("CATEGORY_UPDATES"));
        assert!(!is_label_id("a b") && !is_label_id("x&q=1") && !is_label_id(""));
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
