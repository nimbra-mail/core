//! Mail over IMAP (reading) and SMTP (sending), for accounts that are not Gmail: Zoho,
//! iCloud, Fastmail, a company's own server. It gives the app the same model Gmail does.
//!
//! - Folders are labels: INBOX, Sent (SENT), Drafts (DRAFT), Trash (TRASH), Junk (SPAM),
//!   Archive (ARCHIVE), and every other folder a label of its own. A message in two folders
//!   is one message with two labels, as Gmail is over IMAP. Taking the last label off a
//!   message moves it to Archive, which is what Done is.
//! - \Seen and \Flagged are UNREAD and STARRED.
//! - Threads are built here, from Message-ID, In-Reply-To and References.
//! - A local index (the newest few hundred messages of each folder, more as the list is
//!   scrolled) is kept in the account's encrypted store, and comparing it with the server
//!   is the change feed: each difference found moves its position on by one.
//! - Where the server has CONDSTORE (RFC 7162), a look at a folder asks only for the flags
//!   that changed since the last one, and a folder where nothing moved is skipped.
//! - Where it has IDLE (RFC 2177), a second connection waits on the inbox in a thread of
//!   its own and wakes the app as soon as the server says something changed.
//!
//! Security notes:
//! - Every connection is TLS (`tls.rs`): from the start, or after STARTTLS, which is
//!   required. The password (or, for a Microsoft account, its access token, with
//!   AUTHENTICATE XOAUTH2) is only ever sent over it, and is never logged.
//! - Everything put into a command (folder names, search words) is checked or quoted, and
//!   ids handed back by the app are parsed strictly.
//! - Mail is parsed by `mime.rs`, which treats it as hostile input.
//! - The IDLE thread holds a copy of the credential (to sign in again after a drop) and
//!   nothing else of the client; it stops when the client goes. A refused password stops
//!   it for good, so it never tries the same wrong password again and again. A refused
//!   token is dropped and a new one asked for at the next try; a sign-in Microsoft has
//!   ended stops it for good.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::mail::{
    Change, Changes, Draft, HistoryExpired, Label, MayHaveArrived, Message, Met, Offline, Outgoing,
    OutgoingFile, Person, Provider, SignedOut, Summary, View,
};
use crate::servers::{Secret, Security, Servers};
use crate::store::Store;
use crate::tls::{self, TlsStream};

type Session = ::imap::Session<TlsStream>;

/// How many of a folder's newest messages are indexed at first.
const WINDOW: usize = 300;
/// How many older ones are added each time the list needs more.
const MORE: usize = 300;
/// The most folders indexed for their labels (beyond the special ones).
const MAX_LABEL_FOLDERS: usize = 60;
/// Changes kept in the feed: older positions answer `HistoryExpired`.
const LOG_KEEP: usize = 5000;
/// Folders other than the inbox, Sent and Drafts are looked at this often by the feed.
const SLOW_SYNC: Duration = Duration::from_secs(300);
/// Raw messages kept in memory (for attachments of a thread just opened).
const RAW_KEPT: usize = 40;
/// At most this much of them: one with large attachments is fetched again instead.
const RAW_KEPT_BYTES: usize = 64 * 1024 * 1024;
/// The store record of the index.
const INDEX: &str = "imap-index";
/// What a list row needs: flags, date, the header, and the start of the text for a snippet.
const ROW_FETCH: &str = "(UID FLAGS INTERNALDATE BODY.PEEK[HEADER] BODY.PEEK[TEXT]<0.2048>)";
/// What address suggestions need of a message: who it was from and to, and when.
const PEOPLE_FETCH: &str = "(UID INTERNALDATE BODY.PEEK[HEADER.FIELDS (FROM TO CC DATE)])";
/// Messages a page of `people_page` fetches.
const PEOPLE_PAGE: usize = 200;
/// How long one IDLE lasts before it is ended and started again. RFC 2177: servers may
/// drop a client idle for 30 minutes, and routers forget quiet connections sooner.
const IDLE_RENEW: Duration = Duration::from_secs(10 * 60);
/// How long a read on the IDLE connection may wait outside an IDLE (as in `tls.rs`).
const IDLE_IO: Duration = Duration::from_secs(60);
/// Waits before connecting again after the IDLE connection failed: the first, the most.
const RETRY_FIRST: Duration = Duration::from_secs(5);
const RETRY_MOST: Duration = Duration::from_secs(5 * 60);

/// What a folder is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Role {
    Inbox,
    Sent,
    Drafts,
    Trash,
    Junk,
    Archive,
    Label,
}

impl Role {
    /// The label id the app knows it by (a user label's id is its folder's).
    fn system_label(self) -> Option<&'static str> {
        Some(match self {
            Role::Inbox => "INBOX",
            Role::Sent => "SENT",
            Role::Drafts => "DRAFT",
            Role::Trash => "TRASH",
            Role::Junk => "SPAM",
            Role::Archive => "ARCHIVE",
            Role::Label => return None,
        })
    }
}

/// A folder on the server.
#[derive(Clone, Debug)]
struct Folder {
    /// Its name on the server (modified UTF-7), as commands take it.
    name: String,
    role: Role,
}

impl Folder {
    fn label(&self) -> String {
        self.role
            .system_label()
            .map_or_else(|| label_id(&self.name), str::to_string)
    }
}

/// One message in a folder, as indexed.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Entry {
    /// Message-ID (or one made up from where it is, if it has none).
    message_id: String,
    thread: String,
    from: Person,
    to: Vec<Person>,
    /// (Indexes saved before this was kept still load.)
    #[serde(default)]
    cc: Vec<Person>,
    subject: String,
    timestamp_ms: i64,
    snippet: String,
    seen: bool,
    flagged: bool,
    /// The sender's domain when the message passed DMARC for it (`mail::dmarc_domain`).
    /// (Indexes saved before this was kept still load.)
    #[serde(default)]
    dmarc_domain: Option<String>,
}

/// What is known of one folder.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct Indexed {
    uid_validity: u32,
    /// The UID the next message will get: anything at or over it is new.
    uid_next: u32,
    /// The oldest UID indexed; everything from it up is.
    oldest: u32,
    /// Indexed back to its first message.
    complete: bool,
    messages: BTreeMap<u32, Entry>,
    /// HIGHESTMODSEQ at the last look, where the server has CONDSTORE: flags changed since
    /// are all that is asked for. (Defaults: indexes saved before still load.)
    #[serde(default)]
    mod_seq: Option<u64>,
    /// How many messages the folder had at the last look (EXISTS).
    #[serde(default)]
    exists: Option<u32>,
    /// When the feed last compared it with the server (not kept).
    #[serde(skip)]
    synced: Option<Instant>,
}

/// The index and the change feed, kept in the account's store.
#[derive(Default, Serialize, Deserialize)]
struct State {
    /// By folder name.
    folders: HashMap<String, Indexed>,
    /// The feed's position.
    seq: u64,
    /// Changes: position, thread, and whether it was an unread message arriving in the inbox.
    log: VecDeque<(u64, String, bool)>,
    /// Where a thread's messages were before Trash or Spam, to put them back.
    origins: HashMap<String, Vec<String>>,
}

impl State {
    fn note(&mut self, thread: &str, new_unread_inbox: bool) {
        self.seq += 1;
        self.log
            .push_back((self.seq, thread.to_string(), new_unread_inbox));
        while self.log.len() > LOG_KEEP {
            self.log.pop_front();
        }
    }

    /// The oldest position the feed can answer from.
    fn floor(&self) -> u64 {
        self.log.front().map_or(self.seq, |(seq, _, _)| seq - 1)
    }
}

/// What the server can do, as it said after sign-in.
#[derive(Clone, Copy, Default)]
struct Abilities {
    uid_move: bool,
    uidplus: bool,
    /// CONDSTORE (or QRESYNC, which includes it): mod-sequences, CHANGEDSINCE.
    condstore: bool,
}

/// What SELECT said of a folder, as the feed compares it with what is known.
#[derive(Clone, Copy, Debug)]
struct Seen {
    next: u32,
    exists: u32,
    /// HIGHESTMODSEQ; none without CONDSTORE (or a folder the server keeps none for).
    mod_seq: Option<u64>,
}

/// Nothing moved since the last look: no flag changed (every change raises HIGHESTMODSEQ),
/// nothing came (UIDNEXT), and so nothing went either, as the count is the same (with
/// nothing new, the count can only fall by messages going). Only with CONDSTORE: without
/// it a flag change shows in nothing SELECT says.
fn unchanged(known: &Indexed, now: Seen) -> bool {
    known.mod_seq.is_some()
        && known.mod_seq == now.mod_seq
        && known.uid_next == now.next
        && known.exists == Some(now.exists)
}

/// Whether messages may have gone since the last look: there are fewer than there were
/// plus those that came. (Fewer is certain; more or the same cannot hide one.) Not known
/// how many there were (an index saved before this was kept): they may have.
fn may_have_gone(before: Option<u32>, came: usize, now: u32) -> bool {
    before.is_none_or(|before| u64::from(now) < u64::from(before) + came as u64)
}

/// Whether something the server says during IDLE is a change to the mailbox: a message
/// came (EXISTS), went (EXPUNGE, VANISHED) or had its flags changed (FETCH).
fn announces_change(response: &::imap::types::UnsolicitedResponse) -> bool {
    use ::imap::types::UnsolicitedResponse as U;
    matches!(
        response,
        U::Exists(_) | U::Expunge(_) | U::Fetch { .. } | U::Vanished { .. }
    )
}

/// The wait before the next try, after one of `retry` failed: twice as long, to a limit.
fn next_retry(retry: Duration) -> Duration {
    (retry * 2).clamp(RETRY_FIRST, RETRY_MOST)
}

struct Connection {
    session: Session,
    abilities: Abilities,
    /// The folder selected, so the same one is not selected again.
    selected: Option<String>,
}

/// How an account signs in to its servers.
#[derive(Clone)]
pub enum Credential {
    /// Its password (or app password), from the keychain.
    Password(String),
    /// A Microsoft sign-in, which hands out access tokens for XOAUTH2.
    Microsoft(Arc<crate::microsoft::Tokens>),
}

impl Credential {
    /// What to send for one sign-in. For a Microsoft account this may renew the access
    /// token, and is `SignedOut` when Microsoft has ended the sign-in.
    fn secret(&self) -> Result<Secret> {
        match self {
            Credential::Password(password) => Ok(Secret::Password(password.clone())),
            Credential::Microsoft(tokens) => Ok(Secret::Bearer(tokens.access_token()?)),
        }
    }

    /// A server refused `secret`. A token is dropped, so the next sign-in has a new one,
    /// and true is returned: that one is worth a try. A password is not tried again.
    fn refused(&self, secret: &Secret) -> bool {
        match (self, secret) {
            (Credential::Microsoft(tokens), Secret::Bearer(token)) => {
                tokens.forget_access(token);
                true
            }
            _ => false,
        }
    }
}

/// A new access token was refused as well. Microsoft's sign-in itself works (it just gave
/// that token), so signing out and in again would not help.
fn token_refused(which: &str) -> anyhow::Error {
    anyhow!(
        "Microsoft signed Nimbra in, but its {which} server did not let it in. The account may have {which} turned off."
    )
}

pub struct Client {
    account: String,
    email: String,
    servers: Servers,
    credential: Credential,
    connection: Mutex<Option<Connection>>,
    /// The folders, found once per connection.
    folders: Mutex<Option<Vec<Folder>>>,
    state: Mutex<State>,
    store: Mutex<Option<Arc<Store>>>,
    raw: Mutex<VecDeque<(String, Arc<Vec<u8>>)>>,
    writes: AtomicU64,
    /// Shared with the IDLE thread.
    watch: Arc<Watch>,
}

/// What the IDLE thread and the client share. The thread holds this, never the client, so
/// the client can go; when it does, it stops the thread.
#[derive(Default)]
struct Watch {
    state: Mutex<Watching>,
    /// Signalled when a change is announced, and when the thread stops or gives up.
    wake: Condvar,
}

#[derive(Default)]
struct Watching {
    /// Whether the server can IDLE, as the main connection found (none before sign-in).
    can_idle: Option<bool>,
    started: bool,
    /// The thread gave up for good (the server cannot IDLE, or refused the password).
    off: bool,
    /// The client is gone.
    stop: bool,
    /// Changes the server announced, and how many of them a wait has returned for.
    announced: u64,
    seen: u64,
    /// The IDLE connection's socket, to cut it short when the client goes.
    socket: Option<TcpStream>,
}

impl Watch {
    fn announce(&self) {
        self.state.lock().unwrap().announced += 1;
        self.wake.notify_all();
    }

    fn stopped(&self) -> bool {
        self.state.lock().unwrap().stop
    }

    fn give_up(&self) {
        self.state.lock().unwrap().off = true;
        self.wake.notify_all();
    }

    /// Ends the thread: a read it is blocked in returns at once, as the socket is shut.
    fn stop(&self) {
        let mut state = self.state.lock().unwrap();
        state.stop = true;
        if let Some(socket) = state.socket.take() {
            let _ = socket.shutdown(Shutdown::Both);
        }
        drop(state);
        self.wake.notify_all();
    }

    /// Waits for `wait`, or less if stopped meanwhile. False when stopped.
    fn pause(&self, wait: Duration) -> bool {
        let state = self.state.lock().unwrap();
        let (state, _) = self
            .wake
            .wait_timeout_while(state, wait, |s| !s.stop)
            .unwrap();
        !state.stop
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        self.watch.stop();
    }
}

impl Client {
    pub fn new(account: String, email: String, servers: Servers, credential: Credential) -> Self {
        Client {
            account,
            email,
            servers,
            credential,
            connection: Mutex::new(None),
            folders: Mutex::new(None),
            state: Mutex::new(State::default()),
            store: Mutex::new(None),
            raw: Mutex::new(VecDeque::new()),
            writes: AtomicU64::new(0),
            watch: Arc::default(),
        }
    }

    // ---------------------------------------------------------------- connection

    /// Runs `work` on the connection, opening it first if there is none. A connection that
    /// broke is opened again once, for work that can safely be done twice (`again`).
    fn with<R>(
        &self,
        again: bool,
        mut work: impl FnMut(&mut Connection) -> Result<R>,
    ) -> Result<R> {
        let mut slot = self.connection.lock().unwrap();
        for attempt in 0..2 {
            if slot.is_none() {
                *slot = Some(self.open()?);
            }
            let connection = slot.as_mut().expect("opened above");
            match work(connection) {
                Ok(value) => return Ok(value),
                Err(error) if broken(&error) => {
                    *slot = None;
                    *self.folders.lock().unwrap() = None;
                    if attempt == 0 && again {
                        continue;
                    }
                    return Err(error.context(Offline));
                }
                Err(error) => return Err(error),
            }
        }
        unreachable!("the loop returns")
    }

    /// Connects, secures and signs in. A refused token is renewed and tried once more, on a
    /// new connection.
    fn open(&self) -> Result<Connection> {
        let attempt = |secret: &Secret| {
            let stream = secure_stream(&self.servers)?;
            sign_in(&self.servers, secret, &self.account, stream)
        };
        let secret = self.credential.secret()?;
        let mut session = match attempt(&secret) {
            Err(error) if error.is::<SignedOut>() && self.credential.refused(&secret) => {
                let secret = self.credential.secret()?;
                attempt(&secret).map_err(|error| {
                    if error.is::<SignedOut>() {
                        self.credential.refused(&secret);
                        token_refused("IMAP")
                    } else {
                        error
                    }
                })?
            }
            result => result?,
        };
        let (abilities, idle, enable) = session
            .capabilities()
            .map(|c| {
                let abilities = Abilities {
                    uid_move: c.has_str("MOVE"),
                    uidplus: c.has_str("UIDPLUS"),
                    condstore: c.has_str("CONDSTORE") || c.has_str("QRESYNC"),
                };
                (abilities, c.has_str("IDLE"), c.has_str("ENABLE"))
            })
            .unwrap_or_default();
        if abilities.condstore && enable {
            // So that every SELECT says HIGHESTMODSEQ (RFC 7162 3.1). Servers that keep
            // mod-sequences say it anyway; a refusal leaves the feed asking for all flags.
            let _ = session.run_command_and_check_ok("ENABLE CONDSTORE");
        }
        self.watch.state.lock().unwrap().can_idle = Some(idle);
        Ok(Connection {
            session,
            abilities,
            selected: None,
        })
    }

    /// The folders and what each is for. Special-use attributes first; names when the
    /// server has none (Sent, Sent Items, Deleted Messages…).
    fn folders(&self, connection: &mut Connection) -> Result<Vec<Folder>> {
        if let Some(folders) = self.folders.lock().unwrap().clone() {
            return Ok(folders);
        }
        let names = connection.session.list(Some(""), Some("*"))?;
        let gmail = self.servers.is_gmail();
        let mut folders: Vec<Folder> = names
            .iter()
            .filter(|name| folder_name_ok(name.name()))
            .filter_map(|name| {
                let role = role_of(name.name(), name.attributes(), gmail)?;
                Some(Folder {
                    name: name.name().to_string(),
                    role,
                })
            })
            .collect();
        // One folder per role (the first said to be it), the rest are labels.
        let mut seen = HashSet::new();
        for folder in &mut folders {
            if folder.role != Role::Label && !seen.insert(folder.role) {
                folder.role = Role::Label;
            }
        }
        if !folders.iter().any(|f| f.role == Role::Inbox) {
            folders.insert(
                0,
                Folder {
                    name: "INBOX".into(),
                    role: Role::Inbox,
                },
            );
        }
        *self.folders.lock().unwrap() = Some(folders.clone());
        Ok(folders)
    }

    fn folder(&self, connection: &mut Connection, role: Role) -> Result<Option<Folder>> {
        Ok(self
            .folders(connection)?
            .into_iter()
            .find(|f| f.role == role))
    }

    /// Archive, made if the server has none: Done needs somewhere to put mail.
    fn archive(&self, connection: &mut Connection) -> Result<Folder> {
        if let Some(folder) = self.folder(connection, Role::Archive)? {
            return Ok(folder);
        }
        let _ = connection.session.create("Archive");
        *self.folders.lock().unwrap() = None;
        self.folder(connection, Role::Archive)?
            .ok_or_else(|| anyhow!("There is no Archive folder, and one could not be made."))
    }

    fn select(connection: &mut Connection, folder: &str) -> Result<::imap::types::Mailbox> {
        let mailbox = connection.session.select(folder)?;
        connection.selected = Some(folder.to_string());
        // What the server said unasked (EXISTS, FETCH) about the folder before: SELECT has
        // the news, and the library would keep it all for as long as the connection lasts.
        connection.session.take_all_unsolicited().for_each(drop);
        Ok(mailbox)
    }

    // ---------------------------------------------------------------- index

    /// Brings one folder's index up to date with the server: new messages, flags that
    /// changed, messages that went. Each thread touched goes into the feed.
    ///
    /// With CONDSTORE: nothing is asked when nothing moved (`unchanged`); otherwise only
    /// the flags changed since the last look, and the UIDs there are (no flags) only when
    /// the count says some may have gone. Without it, every indexed message's flags.
    fn sync_folder(&self, connection: &mut Connection, folder: &Folder) -> Result<()> {
        let mailbox = Self::select(connection, &folder.name)?;
        let validity = mailbox.uid_validity.unwrap_or(0);
        let next = mailbox.uid_next.unwrap_or(0);
        let now = Seen {
            next,
            exists: mailbox.exists,
            mod_seq: mailbox
                .highest_mod_seq
                .filter(|_| connection.abilities.condstore),
        };
        let mut known = self
            .state
            .lock()
            .unwrap()
            .folders
            .get(&folder.name)
            .cloned()
            .unwrap_or_default();
        let fresh = known.uid_validity != validity || known.uid_next == 0;
        if !fresh && unchanged(&known, now) {
            if let Some(known) = self.state.lock().unwrap().folders.get_mut(&folder.name) {
                known.synced = Some(Instant::now());
            }
            return Ok(());
        }
        let mut touched: Vec<(String, bool)> = Vec::new();
        if fresh {
            // First look, or the server numbered the folder anew: index its newest.
            for entry in known.messages.values() {
                touched.push((entry.thread.clone(), false));
            }
            known = Indexed {
                uid_validity: validity,
                ..Default::default()
            };
            let uids = newest_uids(connection, None, WINDOW)?;
            known.oldest = uids.first().copied().unwrap_or(next.max(1));
            known.complete = uids.len() < WINDOW;
            for (uid, entry) in self.fetch_rows(connection, &folder.name, &uids)? {
                touched.push((entry.thread.clone(), false));
                known.messages.insert(uid, entry);
            }
        } else {
            let mut came = 0;
            if next > known.uid_next {
                let uids: Vec<u32> = connection
                    .session
                    .uid_search(format!("UID {}:*", known.uid_next.max(1)))?
                    .into_iter()
                    .filter(|uid| *uid >= known.uid_next)
                    .collect();
                came = uids.len();
                for (uid, entry) in self.fetch_rows(connection, &folder.name, &uids)? {
                    let arrival = folder.role == Role::Inbox && !entry.seen;
                    touched.push((entry.thread.clone(), arrival));
                    known.messages.insert(uid, entry);
                }
            }
            if known.oldest > 0 && !known.messages.is_empty() {
                let range = format!("{}:*", known.oldest);
                match (known.mod_seq, now.mod_seq) {
                    // CONDSTORE, and known since when: what changed, then what went.
                    (Some(since), Some(highest)) => {
                        if highest != since {
                            let fetched = connection
                                .session
                                .uid_fetch(&range, format!("(UID FLAGS) (CHANGEDSINCE {since})"))?;
                            take_flags(&mut known, &fetched, &mut touched);
                        }
                        if may_have_gone(known.exists, came, now.exists) {
                            let present = connection.session.uid_search(format!("UID {range}"))?;
                            drop_gone(&mut known, &present, &mut touched);
                        }
                    }
                    // Flags and what went, for everything indexed.
                    _ => {
                        let fetched = connection.session.uid_fetch(&range, "(UID FLAGS)")?;
                        let present = take_flags(&mut known, &fetched, &mut touched);
                        drop_gone(&mut known, &present, &mut touched);
                    }
                }
            }
        }
        known.uid_next = next.max(known.uid_next);
        known.exists = Some(now.exists);
        known.mod_seq = now.mod_seq;
        known.synced = Some(Instant::now());
        let mut state = self.state.lock().unwrap();
        state.folders.insert(folder.name.clone(), known);
        let mut noted = HashSet::new();
        for (thread, arrival) in touched {
            if noted.insert((thread.clone(), arrival)) {
                state.note(&thread, arrival);
            }
        }
        Ok(())
    }

    /// Indexes up to `MORE` older messages of a folder. False when it has no more.
    fn extend_folder(&self, connection: &mut Connection, folder: &Folder) -> Result<bool> {
        let known = self
            .state
            .lock()
            .unwrap()
            .folders
            .get(&folder.name)
            .cloned();
        let Some(mut known) = known else {
            self.sync_folder(connection, folder)?;
            return Ok(true);
        };
        if known.complete || known.oldest <= 1 {
            return Ok(false);
        }
        Self::select(connection, &folder.name)?;
        let uids = newest_uids(connection, Some(known.oldest - 1), MORE)?;
        known.complete = uids.len() < MORE;
        if let Some(first) = uids.first() {
            known.oldest = *first;
        }
        let rows = self.fetch_rows(connection, &folder.name, &uids)?;
        let mut state = self.state.lock().unwrap();
        for (uid, entry) in rows {
            known.messages.insert(uid, entry);
        }
        state.folders.insert(folder.name.clone(), known);
        Ok(!uids.is_empty())
    }

    /// Fetches the list-row data of these messages, in batches.
    fn fetch_rows(
        &self,
        connection: &mut Connection,
        folder: &str,
        uids: &[u32],
    ) -> Result<Vec<(u32, Entry)>> {
        let validity = connection
            .session
            .examine(folder)
            .ok()
            .and_then(|m| m.uid_validity)
            .unwrap_or(0);
        // EXAMINE deselected the folder that was selected for changes.
        Self::select(connection, folder)?;
        let mut rows = Vec::new();
        for batch in uids.chunks(100) {
            let set = uid_set(batch);
            if set.is_empty() {
                continue;
            }
            let fetched = connection.session.uid_fetch(&set, ROW_FETCH)?;
            for fetch in fetched.iter() {
                let Some(uid) = fetch.uid else { continue };
                let header = fetch.header().unwrap_or_default();
                let Some(headers) = crate::mime::headers(header) else {
                    continue;
                };
                let mut partial = header.to_vec();
                partial.extend_from_slice(fetch.text().unwrap_or_default());
                let (seen, flagged) = flags_of(fetch.flags());
                let key = message_key(folder, validity, uid);
                let message_id = if crate::mail::is_message_id(&headers.message_id) {
                    headers.message_id.clone()
                } else {
                    format!("<{key}@nimbra.invalid>")
                };
                let timestamp_ms = if headers.timestamp_ms > 0 {
                    headers.timestamp_ms
                } else {
                    fetch.internal_date().map_or(0, |d| d.timestamp_millis())
                };
                let root = headers
                    .references
                    .first()
                    .or(headers.in_reply_to.as_ref())
                    .unwrap_or(&message_id);
                let dmarc_domain =
                    crate::mail::dmarc_domain(&headers.authentication, &headers.from.address);
                rows.push((
                    uid,
                    Entry {
                        thread: thread_id(root),
                        message_id,
                        dmarc_domain,
                        from: headers.from,
                        to: headers.to,
                        cc: headers.cc,
                        subject: headers.subject,
                        timestamp_ms,
                        snippet: crate::mime::snippet(&partial),
                        seen,
                        flagged,
                    },
                ));
            }
        }
        Ok(rows)
    }

    /// Makes sure the folders are indexed (once each), and keeps the index.
    fn ensure_indexed(&self, connection: &mut Connection, folders: &[Folder]) -> Result<()> {
        for folder in folders {
            let indexed = self
                .state
                .lock()
                .unwrap()
                .folders
                .contains_key(&folder.name);
            if !indexed {
                self.sync_folder(connection, folder)?;
            }
        }
        Ok(())
    }

    /// Every folder whose labels show on rows: all but Trash and Junk, up to a limit.
    fn label_folders(&self, connection: &mut Connection) -> Result<Vec<Folder>> {
        let mut folders: Vec<Folder> = self
            .folders(connection)?
            .into_iter()
            .filter(|f| !matches!(f.role, Role::Trash | Role::Junk))
            .collect();
        folders.truncate(MAX_LABEL_FOLDERS + 6);
        Ok(folders)
    }

    /// The folders a mailbox lists from.
    fn view_folders(
        &self,
        connection: &mut Connection,
        view: View,
        label_id: Option<&str>,
    ) -> Result<Vec<Folder>> {
        let folders = self.folders(connection)?;
        let of = |role: Role| folders.iter().filter(|f| f.role == role).cloned().collect();
        // Every account's mailbox is listed here as this account's own.
        Ok(match view.base() {
            // (A base is never every account's.)
            View::Inbox | View::Every(_) | View::Primary => of(Role::Inbox),
            View::Sent => of(Role::Sent),
            View::Drafts => of(Role::Drafts),
            View::Trash => of(Role::Trash),
            View::Spam => of(Role::Junk),
            View::Done => of(Role::Archive),
            View::Label(_) => folders
                .iter()
                .filter(|f| Some(f.label().as_str()) == label_id)
                .cloned()
                .collect(),
            View::Starred | View::AllMail | View::Search => folders
                .iter()
                .filter(|f| !matches!(f.role, Role::Trash | Role::Junk | Role::Drafts))
                .cloned()
                .collect(),
            // Gmail's own, and the ones kept on this Mac: nothing here.
            View::Updates
            | View::Promotions
            | View::Social
            | View::Important
            | View::Snoozed
            | View::Reminders => Vec::new(),
        })
    }

    /// Threads from the index, as list rows, newest first.
    fn rows(&self, folders: &[Folder], recipient: bool) -> Vec<Summary> {
        let state = self.state.lock().unwrap();
        // Every copy of every message, by thread.
        let mut threads: HashMap<&str, Vec<(&Folder, &Entry)>> = HashMap::new();
        for folder in folders {
            if let Some(known) = state.folders.get(&folder.name) {
                for entry in known.messages.values() {
                    threads
                        .entry(&entry.thread)
                        .or_default()
                        .push((folder, entry));
                }
            }
        }
        let mut rows: Vec<Summary> = threads
            .into_iter()
            .map(|(id, copies)| summary(id, &copies, recipient))
            .collect();
        rows.sort_by_key(|row| std::cmp::Reverse(row.timestamp_ms));
        rows
    }

    /// All the copies of a thread's messages: folder, UID and entry.
    fn copies(
        &self,
        connection: &mut Connection,
        thread: &str,
    ) -> Result<Vec<(Folder, u32, Entry)>> {
        let folders = self.folders(connection)?;
        let state = self.state.lock().unwrap();
        let mut copies = Vec::new();
        for folder in folders {
            if let Some(known) = state.folders.get(&folder.name) {
                for (uid, entry) in &known.messages {
                    if entry.thread == thread {
                        copies.push((folder.clone(), *uid, entry.clone()));
                    }
                }
            }
        }
        Ok(copies)
    }

    /// Saves the index, unless the store is not open yet.
    fn save(&self) {
        let Some(store) = self.store.lock().unwrap().clone() else {
            return;
        };
        let taken = store.snapshot();
        let state = self.state.lock().unwrap();
        if store.save_newest(INDEX, &*state, taken).is_err() {
            eprintln!("nimbra: could not save the mail index");
        }
    }

    fn the_folders_for(
        &self,
        connection: &mut Connection,
        view: View,
        label_id: Option<&str>,
    ) -> Result<Vec<Folder>> {
        let mut wanted = self.view_folders(connection, view, label_id)?;
        // A thread's other messages (your replies in Sent, its labels) come from these.
        for folder in self.label_folders(connection)? {
            if !wanted.iter().any(|f| f.name == folder.name) {
                wanted.push(folder);
            }
        }
        Ok(wanted)
    }

    /// The rows of a mailbox, enough of them for `needed`: older messages are indexed
    /// until there are, or the folders have no more.
    fn listed(
        &self,
        connection: &mut Connection,
        view: View,
        label_id: Option<&str>,
        needed: usize,
    ) -> Result<Vec<Summary>> {
        if view == View::Search {
            return self.search(connection, label_id.unwrap_or_default());
        }
        let shown = self.view_folders(connection, view, label_id)?;
        if shown.is_empty() {
            return Ok(Vec::new());
        }
        let all = self.the_folders_for(connection, view, label_id)?;
        self.ensure_indexed(connection, &all)?;
        let recipient = matches!(view, View::Sent | View::Drafts);
        loop {
            let rows: Vec<Summary> = self
                .rows(&all, recipient)
                .into_iter()
                .filter(|row| self.in_view(row, view, label_id, &shown))
                .collect();
            if rows.len() >= needed {
                return Ok(rows);
            }
            let mut more = false;
            for folder in &shown {
                more |= self.extend_folder(connection, folder)?;
            }
            if !more {
                return Ok(rows);
            }
        }
    }

    fn in_view(&self, row: &Summary, view: View, label_id: Option<&str>, shown: &[Folder]) -> bool {
        let labels: Vec<String> = shown.iter().map(Folder::label).collect();
        let in_shown = row.labels.iter().any(|l| labels.contains(l));
        match view.base() {
            View::Starred => row.starred,
            View::AllMail => true,
            View::Done => in_shown,
            view => in_shown && view.holds(&row.labels, label_id) != Some(false),
        }
    }

    /// Search with IMAP SEARCH: words in the text, and from:, to:, subject:, is:unread,
    /// is:starred as Gmail has them.
    fn search(&self, connection: &mut Connection, query: &str) -> Result<Vec<Summary>> {
        let criteria = search_criteria(query)?;
        let folders = self.view_folders(connection, View::Search, None)?;
        let all = self.label_folders(connection)?;
        self.ensure_indexed(connection, &all)?;
        let mut threads = HashSet::new();
        for folder in &folders {
            Self::select(connection, &folder.name)?;
            let found = connection
                .session
                .uid_search(format!("CHARSET UTF-8 {criteria}"))
                .or_else(|_| connection.session.uid_search(&criteria))?;
            let mut found: Vec<u32> = found.into_iter().collect();
            found.sort_unstable();
            let found = &found[found.len().saturating_sub(200)..];
            let missing: Vec<u32> = {
                let state = self.state.lock().unwrap();
                let known = state.folders.get(&folder.name);
                found
                    .iter()
                    .filter(|uid| known.is_none_or(|k| !k.messages.contains_key(uid)))
                    .copied()
                    .collect()
            };
            let rows = self.fetch_rows(connection, &folder.name, &missing)?;
            let mut state = self.state.lock().unwrap();
            let known = state.folders.entry(folder.name.clone()).or_default();
            for (uid, entry) in rows {
                known.messages.insert(uid, entry);
            }
            for uid in found {
                if let Some(entry) = known.messages.get(uid) {
                    threads.insert(entry.thread.clone());
                }
            }
        }
        Ok(self
            .rows(&all, false)
            .into_iter()
            .filter(|row| threads.contains(&row.id))
            .collect())
    }

    // ---------------------------------------------------------------- changes

    /// Applies label changes to every message of a thread, as Gmail does: adding a folder
    /// label copies (or moves) the message there, taking one off removes that copy, and a
    /// message left in no folder goes to Archive. UNREAD and STARRED are flags.
    fn relabel_thread(&self, thread: &str, add: &[&str], remove: &[&str]) -> Result<()> {
        if !is_thread_id(thread) {
            bail!("unexpected thread id");
        }
        let mut touched = HashSet::new();
        self.with(false, |connection| {
            let folders = self.folders(connection)?;
            let by_label = |label: &str| folders.iter().find(|f| f.label() == label).cloned();
            let copies = self.copies(connection, thread)?;
            if copies.is_empty() {
                bail!(crate::mail::Answered {
                    code: 404,
                    text: "That conversation is not here any more.".into(),
                });
            }
            touched.extend(copies.iter().map(|c| c.0.name.clone()));
            touched.extend(
                add.iter()
                    .chain(remove)
                    .filter_map(|l| by_label(l))
                    .map(|f| f.name),
            );
            // Flags, on every copy.
            for (label, flag, on) in [("UNREAD", "\\Seen", false), ("STARRED", "\\Flagged", true)] {
                let set = if add.contains(&label) {
                    Some(on)
                } else if remove.contains(&label) {
                    Some(!on)
                } else {
                    None
                };
                if let Some(set) = set {
                    for (folder, uids) in group(&copies) {
                        Self::select(connection, &folder)?;
                        let sign = if set { '+' } else { '-' };
                        connection
                            .session
                            .uid_store(uid_set(&uids), format!("{sign}FLAGS.SILENT ({flag})"))?;
                    }
                }
            }
            // Folders, message by message.
            let add_folders: Vec<Folder> = add.iter().filter_map(|l| by_label(l)).collect();
            let remove_folders: Vec<Folder> = remove.iter().filter_map(|l| by_label(l)).collect();
            if !add_folders.is_empty() || !remove_folders.is_empty() {
                let archive = if remove_folders.is_empty() {
                    None
                } else {
                    Some(self.archive(connection)?)
                };
                if let Some(archive) = &archive {
                    touched.insert(archive.name.clone());
                }
                let mut by_message: BTreeMap<&str, Vec<&(Folder, u32, Entry)>> = BTreeMap::new();
                for copy in &copies {
                    by_message.entry(&copy.2.message_id).or_default().push(copy);
                }
                // Into the inbox (back from Done or from a snooze), as Gmail does: what was
                // archived moves back, and the user's own messages stay in Sent rather than
                // being copied in, unless they are all the thread has.
                let to_inbox = add_folders.iter().any(|f| f.role == Role::Inbox);
                let own = |copies: &[&(Folder, u32, Entry)]| {
                    copies
                        .iter()
                        .all(|c| matches!(c.0.role, Role::Sent | Role::Drafts))
                };
                let others = by_message.values().any(|copies| !own(copies));
                for copies in by_message.values() {
                    let in_folder = |f: &Folder| copies.iter().any(|c| c.0.name == f.name);
                    let mut targets: Vec<&Folder> = add_folders
                        .iter()
                        .filter(|f| !in_folder(f))
                        .filter(|f| !(f.role == Role::Inbox && others && own(copies)))
                        .collect();
                    let mut leaving: Vec<&(Folder, u32, Entry)> = copies
                        .iter()
                        .filter(|c| {
                            remove_folders.iter().any(|f| f.name == c.0.name)
                                || (to_inbox
                                    && c.0.role == Role::Archive
                                    && targets.iter().any(|f| f.role == Role::Inbox))
                        })
                        .copied()
                        .collect();
                    if targets.is_empty() && !leaving.is_empty() && leaving.len() == copies.len() {
                        // Its last folder: it goes to Archive instead of nowhere.
                        if let Some(archive) = &archive
                            && !leaving.iter().any(|c| c.0.name == archive.name)
                        {
                            targets.push(archive);
                        }
                    }
                    // A move where there is one to make, copies for the rest.
                    if let (Some(first), Some(target)) = (leaving.first().copied(), targets.first())
                    {
                        self.move_copy(connection, first, &target.name)?;
                        leaving.remove(0);
                        targets.remove(0);
                    }
                    let source = copies[0];
                    for target in targets {
                        Self::select(connection, &source.0.name)?;
                        copy_to(connection, &source.1.to_string(), &target.name)?;
                    }
                    for copy in leaving {
                        self.delete_copy(connection, copy)?;
                    }
                }
            }
            Ok(())
        })?;
        self.writes.fetch_add(1, Ordering::Relaxed);
        self.after_change(thread, &touched)
    }

    fn move_copy(
        &self,
        connection: &mut Connection,
        copy: &(Folder, u32, Entry),
        to: &str,
    ) -> Result<()> {
        Self::select(connection, &copy.0.name)?;
        if connection.abilities.uid_move {
            connection.session.uid_mv(copy.1.to_string(), to)?;
        } else {
            copy_to(connection, &copy.1.to_string(), to)?;
            self.delete_copy(connection, copy)?;
        }
        Ok(())
    }

    /// Removes one copy for good: \Deleted, then expunged (only it, where the server can).
    fn delete_copy(&self, connection: &mut Connection, copy: &(Folder, u32, Entry)) -> Result<()> {
        Self::select(connection, &copy.0.name)?;
        let uid = copy.1.to_string();
        connection
            .session
            .uid_store(&uid, "+FLAGS.SILENT (\\Deleted)")?;
        if connection.abilities.uidplus {
            connection.session.uid_expunge(&uid)?;
        } else {
            connection.session.expunge()?;
        }
        Ok(())
    }

    /// After a change: the folders it touched are looked at again, so the feed and the
    /// rows have it, and the index is kept.
    fn after_change(&self, thread: &str, touched: &HashSet<String>) -> Result<()> {
        self.with(true, |connection| {
            for folder in self.folders(connection)? {
                if touched.contains(&folder.name) {
                    self.sync_folder(connection, &folder)?;
                }
            }
            Ok(())
        })?;
        self.state.lock().unwrap().note(thread, false);
        self.save();
        Ok(())
    }

    // ---------------------------------------------------------------- messages

    /// A message's raw content, from memory or the server.
    fn raw(&self, key: &str) -> Result<Arc<Vec<u8>>> {
        if let Some((_, raw)) = self.raw.lock().unwrap().iter().find(|(k, _)| k == key) {
            return Ok(raw.clone());
        }
        let (folder, validity, uid) = parse_key(key)?;
        let raw = self.with(true, |connection| {
            let mailbox = Self::select(connection, &folder)?;
            if mailbox.uid_validity.is_some_and(|v| v != validity) {
                bail!(crate::mail::Answered {
                    code: 404,
                    text: "That message is not here any more.".into(),
                });
            }
            let fetched = connection
                .session
                .uid_fetch(uid.to_string(), "(UID BODY.PEEK[])")?;
            fetched
                .iter()
                .find(|f| f.uid == Some(uid))
                .and_then(|f| f.body())
                .map(<[u8]>::to_vec)
                .ok_or_else(|| {
                    anyhow!(crate::mail::Answered {
                        code: 404,
                        text: "That message is not here any more.".into(),
                    })
                })
        })?;
        let raw = Arc::new(raw);
        keep_raw(&mut self.raw.lock().unwrap(), key, raw.clone());
        Ok(raw)
    }

    /// The files a draft already had, downloaded to be attached again.
    fn kept_files(&self, outgoing: &Outgoing) -> Result<Vec<OutgoingFile>> {
        outgoing
            .kept
            .iter()
            .map(|att| {
                Ok(OutgoingFile {
                    name: att.name.clone(),
                    mime: att.mime.clone(),
                    bytes: Provider::download(self, &att.message_id, &att.attachment_id)?,
                })
            })
            .collect()
    }

    /// Puts a message in a folder; its key there (when the server says, or it is found).
    fn append(
        &self,
        role: Role,
        raw: &[u8],
        message_id: &str,
        flags: &[::imap::types::Flag<'static>],
    ) -> Result<Option<String>> {
        self.with(false, |connection| {
            let Some(folder) = self.folder(connection, role)? else {
                bail!(
                    "This account has no {} folder.",
                    if role == Role::Drafts {
                        "Drafts"
                    } else {
                        "Sent"
                    }
                );
            };
            // The library puts the name in quotes without escaping what is in it.
            if folder.name.contains(['"', '\\']) {
                bail!("Nimbra cannot save into a folder whose name has quotes in it.");
            }
            let appended = connection
                .session
                .append(&folder.name, raw)
                .flags(flags.iter().cloned())
                .finish()?;
            let mailbox = Self::select(connection, &folder.name)?;
            let validity = appended.uid_validity.or(mailbox.uid_validity).unwrap_or(0);
            let uid = appended.uids.and_then(|uids| match uids.first() {
                Some(imap_proto::UidSetMember::Uid(uid)) => Some(*uid),
                Some(imap_proto::UidSetMember::UidRange(range)) => Some(*range.start()),
                None => None,
            });
            let uid = match uid {
                Some(uid) => Some(uid),
                None => find_by_message_id(connection, message_id)?,
            };
            Ok(uid.map(|uid| message_key(&folder.name, validity, uid)))
        })
    }

    /// Whether Sent already has a message (servers that file what they send themselves).
    fn in_sent(&self, message_id: &str) -> Result<bool> {
        self.with(true, |connection| {
            let Some(folder) = self.folder(connection, Role::Sent)? else {
                return Ok(true);
            };
            Self::select(connection, &folder.name)?;
            Ok(find_by_message_id(connection, message_id)?.is_some())
        })
    }

    /// Hands a built message to the SMTP server, then files it in Sent unless the server
    /// did. `raw` has no Bcc header; `recipients` has everyone.
    fn deliver(&self, raw: &[u8], recipients: &[String], message_id: &str) -> Result<()> {
        let send = |secret: &Secret| {
            crate::smtp::send(
                &self.servers.smtp,
                &self.servers.username,
                secret,
                &self.email,
                recipients,
                raw,
            )
        };
        // A refused sign-in is before anything is sent, so a renewed token can be tried.
        let secret = self.credential.secret()?;
        let sent = match send(&secret) {
            Err(error)
                if error.is::<crate::smtp::AuthFailed>() && self.credential.refused(&secret) =>
            {
                let secret = self.credential.secret()?;
                send(&secret).map_err(|error| {
                    if error.is::<crate::smtp::AuthFailed>() {
                        self.credential.refused(&secret);
                        token_refused("SMTP")
                    } else {
                        error
                    }
                })
            }
            sent => sent,
        };
        sent.map_err(|error| {
            if error.is::<crate::smtp::AuthFailed>() {
                SignedOut {
                    account: self.account.clone(),
                }
                .into()
            } else {
                error
            }
        })?;
        self.writes.fetch_add(1, Ordering::Relaxed);
        // Gmail files what goes through its SMTP server in Sent Mail itself.
        if self.servers.is_gmail() {
            return Ok(());
        }
        // Sent: some servers file it themselves a moment later.
        std::thread::sleep(Duration::from_millis(1500));
        if !self.in_sent(message_id).unwrap_or(true) {
            let _ = self.append(Role::Sent, raw, message_id, &[::imap::types::Flag::Seen]);
        }
        Ok(())
    }

    fn sync_watched(&self, everything: bool) -> Result<()> {
        self.with(true, |connection| {
            let folders = self.folders(connection)?;
            for folder in folders {
                let (indexed, due) = {
                    let state = self.state.lock().unwrap();
                    match state.folders.get(&folder.name) {
                        Some(known) => (
                            true,
                            known.synced.is_none_or(|at| at.elapsed() >= SLOW_SYNC),
                        ),
                        None => (false, false),
                    }
                };
                let always = matches!(folder.role, Role::Inbox | Role::Sent | Role::Drafts);
                if (indexed || always) && (always || everything || due) {
                    self.sync_folder(connection, &folder)?;
                }
            }
            Ok(())
        })
    }
}

impl Provider for Client {
    fn profile(&self) -> Result<(String, String)> {
        self.with(true, |connection| {
            self.folders(connection)?;
            Ok(())
        })?;
        Ok((
            self.email.clone(),
            self.state.lock().unwrap().seq.to_string(),
        ))
    }

    fn writes(&self) -> u64 {
        self.writes.load(Ordering::Relaxed)
    }

    fn forget_rows(&self) {
        *self.state.lock().unwrap() = State::default();
        self.raw.lock().unwrap().clear();
    }

    fn keep_rows_in(&self, store: &Arc<Store>) {
        if let Some(saved) = store.load::<State>(INDEX) {
            let mut state = self.state.lock().unwrap();
            if state.folders.is_empty() {
                *state = saved;
            }
        }
        *self.store.lock().unwrap() = Some(store.clone());
    }

    fn history(&self, start: &str) -> Result<Changes> {
        let start: u64 = start.parse().map_err(|_| anyhow!(HistoryExpired))?;
        {
            let state = self.state.lock().unwrap();
            if start < state.floor() || start > state.seq {
                return Err(HistoryExpired.into());
            }
        }
        self.sync_watched(false)?;
        self.save();
        let state = self.state.lock().unwrap();
        let mut changes = Changes {
            latest: state.seq.to_string(),
            ..Default::default()
        };
        for (seq, thread, arrival) in &state.log {
            if *seq <= start {
                continue;
            }
            if !changes.threads.contains(thread) {
                changes.threads.push(thread.clone());
            }
            if *arrival && !changes.new_unread_inbox.contains(thread) {
                changes.new_unread_inbox.push(thread.clone());
            }
        }
        Ok(changes)
    }

    /// Starts the IDLE thread the first time, where the server can IDLE (as the main
    /// connection found: before it is open, nothing is known and this returns at once).
    fn wait_for_change(&self, timeout: Duration) -> bool {
        let mut state = self.watch.state.lock().unwrap();
        if state.can_idle != Some(true) || state.off || state.stop {
            return false;
        }
        if !state.started {
            state.started = true;
            let watch = self.watch.clone();
            let servers = self.servers.clone();
            let credential = self.credential.clone();
            let spawned = std::thread::Builder::new()
                .name("nimbra-imap-idle".into())
                .spawn(move || idle_inbox(&watch, &servers, &credential));
            if spawned.is_err() {
                state.off = true;
                return false;
            }
        }
        let (mut state, _) = self
            .watch
            .wake
            .wait_timeout_while(state, timeout, |s| {
                s.announced == s.seen && !s.off && !s.stop
            })
            .unwrap();
        let changed = state.announced != state.seen;
        state.seen = state.announced;
        changed
    }

    fn threads_page(
        &self,
        view: View,
        label_id: Option<&str>,
        limit: usize,
        page: Option<&str>,
    ) -> Result<(Vec<Summary>, Option<String>)> {
        let offset: usize = match page {
            Some(page) => page.parse().context("unexpected page token")?,
            None => 0,
        };
        let rows = self.with(true, |connection| {
            if offset == 0 && view != View::Search {
                // A first page is a fresh look: what is shown is synced now.
                for folder in self.view_folders(connection, view, label_id)? {
                    self.sync_folder(connection, &folder)?;
                }
            }
            self.listed(connection, view, label_id, offset + limit + 1)
        })?;
        self.save();
        let page: Vec<Summary> = rows.iter().skip(offset).take(limit).cloned().collect();
        let next = (rows.len() > offset + limit).then(|| (offset + limit).to_string());
        Ok((page, next))
    }

    fn page_after(
        &self,
        view: View,
        label_id: Option<&str>,
        count: usize,
    ) -> Result<Option<String>> {
        let rows = self.with(true, |connection| {
            self.listed(connection, view, label_id, count + 1)
        })?;
        Ok((rows.len() > count).then(|| count.to_string()))
    }

    /// The newest messages of Sent or the inbox, a page at a time, older than the UID in
    /// `page`. Only their From, To, Cc and Date, read without marking anything read.
    fn people_page(&self, sent: bool, page: Option<&str>) -> Result<(Vec<Met>, Option<String>)> {
        let below: u32 = match page {
            Some(page) => page.parse().context("unexpected page token")?,
            None => u32::MAX,
        };
        self.with(true, |connection| {
            let role = if sent { Role::Sent } else { Role::Inbox };
            let Some(folder) = self.folder(connection, role)? else {
                return Ok((Vec::new(), None));
            };
            Self::select(connection, &folder.name)?;
            let mut uids: Vec<u32> = connection
                .session
                .uid_search("ALL")?
                .into_iter()
                .filter(|uid| *uid < below)
                .collect();
            uids.sort_unstable_by(|a, b| b.cmp(a));
            let more = uids.len() > PEOPLE_PAGE;
            uids.truncate(PEOPLE_PAGE);
            let mut people = Vec::new();
            for batch in uids.chunks(100) {
                let set = uid_set(batch);
                if set.is_empty() {
                    continue;
                }
                for fetch in connection.session.uid_fetch(&set, PEOPLE_FETCH)?.iter() {
                    let Some(headers) = fetch.header().and_then(crate::mime::headers) else {
                        continue;
                    };
                    let timestamp_ms = if headers.timestamp_ms > 0 {
                        headers.timestamp_ms
                    } else {
                        fetch.internal_date().map_or(0, |d| d.timestamp_millis())
                    };
                    people.push(Met {
                        from: headers.from,
                        to: headers.to,
                        cc: headers.cc,
                        timestamp_ms,
                        sent,
                    });
                }
            }
            let next = uids.last().filter(|_| more).map(u32::to_string);
            Ok((people, next))
        })
    }

    fn summary(&self, id: &str, recipient: bool) -> Result<Summary> {
        if !is_thread_id(id) {
            bail!("unexpected thread id");
        }
        let copies = self.with(true, |connection| self.copies(connection, id))?;
        if copies.is_empty() {
            bail!(crate::mail::Answered {
                code: 404,
                text: "That conversation is not here any more.".into(),
            });
        }
        let copies: Vec<(&Folder, &Entry)> = copies.iter().map(|(f, _, e)| (f, e)).collect();
        Ok(summary(id, &copies, recipient))
    }

    fn thread(&self, id: &str) -> Result<Vec<Message>> {
        if !is_thread_id(id) {
            bail!("unexpected thread id");
        }
        let copies = self.with(true, |connection| self.copies(connection, id))?;
        // One copy of each message: not the one in Trash when there is another.
        let mut chosen: BTreeMap<String, (Folder, u32, Entry)> = BTreeMap::new();
        for copy in copies {
            let better = chosen
                .get(&copy.2.message_id)
                .is_none_or(|kept| kept.0.role == Role::Trash && copy.0.role != Role::Trash);
            if better {
                chosen.insert(copy.2.message_id.clone(), copy);
            }
        }
        let mut messages = Vec::new();
        for (folder, uid, entry) in chosen.into_values() {
            let validity = self
                .state
                .lock()
                .unwrap()
                .folders
                .get(&folder.name)
                .map_or(0, |k| k.uid_validity);
            let key = message_key(&folder.name, validity, uid);
            let raw = self.raw(&key)?;
            if let Some(mut message) = crate::mime::message(&raw, &key) {
                if message.timestamp_ms == 0 {
                    message.timestamp_ms = entry.timestamp_ms;
                }
                messages.push(message);
            }
        }
        messages.sort_by_key(|m| m.timestamp_ms);
        Ok(messages)
    }

    fn download(&self, message_id: &str, attachment_id: &str) -> Result<Vec<u8>> {
        let raw = self.raw(message_id)?;
        crate::mime::attachment(&raw, attachment_id)
            .ok_or_else(|| anyhow!("That attachment is not in the message any more."))
    }

    fn change(&self, id: &str, change: Change) -> Result<()> {
        match change {
            Change::Archive => self.relabel_thread(id, &[], &["INBOX"]),
            Change::Unarchive => self.relabel_thread(id, &["INBOX"], &["ARCHIVE"]),
            Change::Star => self.relabel_thread(id, &["STARRED"], &[]),
            Change::Unstar => self.relabel_thread(id, &[], &["STARRED"]),
            Change::MarkRead => self.relabel_thread(id, &[], &["UNREAD"]),
            Change::MarkUnread => self.relabel_thread(id, &["UNREAD"], &[]),
            Change::Trash | Change::Spam => {
                let (to, label) = if change == Change::Trash {
                    (Role::Trash, "TRASH")
                } else {
                    (Role::Junk, "SPAM")
                };
                // Remember where it was, to put it back.
                let from: Vec<String> = self
                    .with(true, |connection| self.copies(connection, id))?
                    .into_iter()
                    .filter(|c| {
                        c.0.role != to && c.0.role != Role::Sent && c.0.role != Role::Drafts
                    })
                    .map(|c| c.0.label())
                    .collect::<HashSet<_>>()
                    .into_iter()
                    .collect();
                self.state
                    .lock()
                    .unwrap()
                    .origins
                    .insert(id.to_string(), from.clone());
                let remove: Vec<&str> = from.iter().map(String::as_str).collect();
                self.relabel_thread(id, &[label], &remove)
            }
            Change::Untrash | Change::NotSpam => {
                let label = if change == Change::Untrash {
                    "TRASH"
                } else {
                    "SPAM"
                };
                let back = self
                    .state
                    .lock()
                    .unwrap()
                    .origins
                    .remove(id)
                    .filter(|o| !o.is_empty())
                    .unwrap_or_else(|| vec!["INBOX".to_string()]);
                let add: Vec<&str> = back.iter().map(String::as_str).collect();
                self.relabel_thread(id, &add, &[label])
            }
        }
    }

    fn draft_for_thread(&self, thread_id: &str) -> Result<Draft> {
        if !is_thread_id(thread_id) {
            bail!("unexpected thread id");
        }
        let copies = self.with(true, |connection| {
            if let Some(drafts) = self.folder(connection, Role::Drafts)? {
                self.sync_folder(connection, &drafts)?;
            }
            self.copies(connection, thread_id)
        })?;
        let (folder, uid, _) = copies
            .into_iter()
            .filter(|c| c.0.role == Role::Drafts)
            .max_by_key(|c| c.2.timestamp_ms)
            .ok_or_else(|| {
                anyhow!(crate::mail::Answered {
                    code: 404,
                    text: "That draft is not here any more.".into(),
                })
            })?;
        let validity = self
            .state
            .lock()
            .unwrap()
            .folders
            .get(&folder.name)
            .map_or(0, |k| k.uid_validity);
        let key = message_key(&folder.name, validity, uid);
        let raw = self.raw(&key)?;
        crate::mime::draft(&raw, &key, &key, thread_id)
            .ok_or_else(|| anyhow!("That draft could not be read."))
    }

    fn save_draft(&self, id: Option<&str>, outgoing: &Outgoing) -> Result<String> {
        let extra = self.kept_files(outgoing)?;
        let message_id = crate::mail::new_message_id(&self.email)?;
        let raw = outgoing.to_rfc822_from(&self.email, &message_id, true, &extra)?;
        let key = self
            .append(
                Role::Drafts,
                &raw,
                &message_id,
                &[::imap::types::Flag::Draft, ::imap::types::Flag::Seen],
            )?
            .ok_or_else(|| anyhow!("The draft was saved, but the server did not say where."))?;
        if let Some(old) = id {
            let _ = self.delete_draft(old);
        }
        self.writes.fetch_add(1, Ordering::Relaxed);
        let _ = self.with(true, |connection| {
            if let Some(drafts) = self.folder(connection, Role::Drafts)? {
                self.sync_folder(connection, &drafts)?;
            }
            Ok(())
        });
        self.save();
        Ok(key)
    }

    fn send_draft(&self, id: &str, outgoing: &Outgoing) -> Result<()> {
        self.send_message(outgoing)?;
        if let Err(error) = self.delete_draft(id)
            && !crate::mail::is_gone(&error)
        {
            eprintln!("nimbra: a sent message's draft was left in Drafts");
        }
        Ok(())
    }

    fn keep_as_draft(&self, id: Option<&str>, outgoing: &Outgoing) -> Result<String> {
        self.save_draft(id, outgoing)
    }

    fn send_saved_draft(&self, id: &str) -> Result<()> {
        let raw = self.raw(id).map_err(crate::mail::before_sending)?;
        let draft = crate::mime::draft(&raw, id, id, "")
            .ok_or_else(|| anyhow!("That draft could not be read."))
            .map_err(crate::mail::before_sending)?;
        let mut recipients = Vec::new();
        for list in [&draft.to, &draft.cc, &draft.bcc] {
            recipients.extend(crate::mail::addresses(list).map_err(crate::mail::before_sending)?);
        }
        let message_id = header_message_id(&raw)
            .map_or_else(|| crate::mail::new_message_id(&self.email), Ok)
            .map_err(crate::mail::before_sending)?;
        let sent = crate::mail::without_bcc(&raw);
        self.deliver(&sent, &recipients, &message_id)?;
        if let Err(error) = self.delete_draft(id)
            && !crate::mail::is_gone(&error)
        {
            eprintln!("nimbra: a sent message's draft was left in Drafts");
        }
        Ok(())
    }

    fn delete_draft(&self, id: &str) -> Result<()> {
        let (folder, validity, uid) = parse_key(id)?;
        self.with(false, |connection| {
            let mailbox = Self::select(connection, &folder)?;
            if mailbox.uid_validity.is_some_and(|v| v != validity) {
                bail!(crate::mail::Answered {
                    code: 404,
                    text: "That draft is not here any more.".into(),
                });
            }
            let Some(role) = self
                .folders(connection)?
                .into_iter()
                .find(|f| f.name == folder)
                .map(|f| f.role)
            else {
                bail!("unexpected draft id");
            };
            if role != Role::Drafts {
                bail!("unexpected draft id");
            }
            let entry = Entry {
                message_id: String::new(),
                thread: String::new(),
                from: Person::default(),
                to: Vec::new(),
                cc: Vec::new(),
                subject: String::new(),
                timestamp_ms: 0,
                snippet: String::new(),
                seen: true,
                flagged: false,
                dmarc_domain: None,
            };
            self.delete_copy(
                connection,
                &(
                    Folder {
                        name: folder.clone(),
                        role,
                    },
                    uid,
                    entry,
                ),
            )
        })?;
        self.writes.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn send_message(&self, outgoing: &Outgoing) -> Result<()> {
        let (to, cc, bcc) = outgoing.recipients().map_err(crate::mail::before_sending)?;
        let extra = self
            .kept_files(outgoing)
            .map_err(crate::mail::before_sending)?;
        let message_id = crate::mail::new_message_id(&self.email)?;
        let raw = outgoing
            .to_rfc822_from(&self.email, &message_id, false, &extra)
            .map_err(crate::mail::before_sending)?;
        let recipients: Vec<String> = to.into_iter().chain(cc).chain(bcc).collect();
        self.deliver(&raw, &recipients, &message_id)
    }

    fn delete_thread(&self, id: &str) -> Result<()> {
        if !is_thread_id(id) {
            bail!("unexpected thread id");
        }
        let mut touched = HashSet::new();
        self.with(false, |connection| {
            for copy in self.copies(connection, id)? {
                self.delete_copy(connection, &copy)?;
                touched.insert(copy.0.name.clone());
            }
            Ok(())
        })?;
        self.writes.fetch_add(1, Ordering::Relaxed);
        self.after_change(id, &touched)
    }

    fn labels(&self) -> Result<Vec<Label>> {
        let folders = self.with(true, |connection| {
            *self.folders.lock().unwrap() = None;
            self.folders(connection)
        })?;
        let mut labels: Vec<Label> = folders
            .into_iter()
            .filter(|f| f.role == Role::Label)
            .map(|f| Label {
                id: label_id(&f.name),
                name: decode_utf7(&f.name),
            })
            .collect();
        labels.sort_by_key(|l| l.name.to_lowercase());
        Ok(labels)
    }

    fn create_label(&self, name: &str) -> Result<Label> {
        let name = name.trim();
        if name.is_empty() || name.len() > 200 || name.chars().any(char::is_control) {
            bail!("That name cannot be a folder.");
        }
        let encoded = encode_utf7(name);
        self.with(false, |connection| {
            connection.session.create(&encoded)?;
            *self.folders.lock().unwrap() = None;
            Ok(())
        })?;
        Ok(Label {
            id: label_id(&encoded),
            name: name.to_string(),
        })
    }

    fn rename_label(&self, id: &str, name: &str) -> Result<()> {
        let from = folder_of_label(id)?;
        let name = name.trim();
        if name.is_empty() || name.len() > 200 || name.chars().any(char::is_control) {
            bail!("That name cannot be a folder.");
        }
        let to = encode_utf7(name);
        self.with(false, |connection| {
            connection.selected = None;
            connection.session.rename(&from, &to)?;
            *self.folders.lock().unwrap() = None;
            Ok(())
        })?;
        let mut state = self.state.lock().unwrap();
        if let Some(known) = state.folders.remove(&from) {
            state.folders.insert(to, known);
        }
        Ok(())
    }

    fn delete_label(&self, id: &str) -> Result<()> {
        let folder = folder_of_label(id)?;
        self.with(false, |connection| {
            let role = self
                .folders(connection)?
                .into_iter()
                .find(|f| f.name == folder)
                .map(|f| f.role);
            match role {
                Some(Role::Label) => {}
                Some(_) => bail!("That folder is one the account needs."),
                None => bail!(crate::mail::Answered {
                    code: 404,
                    text: "That folder is not here any more.".into(),
                }),
            }
            if connection.selected.as_deref() == Some(folder.as_str()) {
                let _ = connection.session.close();
                connection.selected = None;
            }
            connection.session.delete(&folder)?;
            *self.folders.lock().unwrap() = None;
            Ok(())
        })?;
        self.state.lock().unwrap().folders.remove(&folder);
        self.save();
        Ok(())
    }

    fn add_label(&self, id: &str, label_id: &str) -> Result<()> {
        self.relabel_thread(id, &[label_id], &[])
    }

    fn remove_label(&self, id: &str, label_id: &str) -> Result<()> {
        self.relabel_thread(id, &[], &[label_id])
    }

    fn relabel(&self, id: &str, add: &[&str], remove: &[&str]) -> Result<()> {
        self.relabel_thread(id, add, remove)
    }

    fn counts(&self, label_ids: &[String]) -> HashMap<String, (u32, u32)> {
        let result = self.with(true, |connection| {
            let folders = self.folders(connection)?;
            let mut counts = HashMap::new();
            for id in label_ids {
                let Some(folder) = folders.iter().find(|f| &f.label() == id) else {
                    continue;
                };
                if connection.selected.as_deref() == Some(folder.name.as_str()) {
                    // STATUS is not for the selected folder (RFC 3501).
                    connection.selected = None;
                    let _ = connection.session.close();
                }
                let Ok(status) = connection.session.status(&folder.name, "(MESSAGES UNSEEN)")
                else {
                    continue;
                };
                let counted = if folder.role == Role::Drafts {
                    (0, status.exists)
                } else {
                    (status.unseen.unwrap_or(0), 0)
                };
                counts.insert(id.clone(), counted);
            }
            Ok(counts)
        });
        result.unwrap_or_default()
    }
}

// ------------------------------------------------------------------ helpers

/// AUTHENTICATE PLAIN: the password goes as base64 over the TLS connection.
struct Plain<'a> {
    username: &'a str,
    password: &'a str,
}

impl ::imap::Authenticator for Plain<'_> {
    type Response = Vec<u8>;
    fn process(&self, _: &[u8]) -> Self::Response {
        let mut response = vec![0];
        response.extend_from_slice(self.username.as_bytes());
        response.push(0);
        response.extend_from_slice(self.password.as_bytes());
        response
    }
}

/// A secure connection to the IMAP server: TLS from the start, or after STARTTLS.
fn secure_stream(servers: &Servers) -> Result<TlsStream> {
    let server = &servers.imap;
    match server.security {
        Security::Tls => tls::connect(&server.host, server.port),
        Security::StartTls => starttls(&server.host, server.port),
    }
}

/// AUTHENTICATE XOAUTH2. The library sends the command alone and hands each challenge
/// here: the first (empty) gets the sign-in string; a refusal comes as a second one (base64
/// JSON), answered with an empty line, after which the server says NO.
struct XOAuth2 {
    initial: String,
    sent: std::cell::Cell<bool>,
}

impl ::imap::Authenticator for XOAuth2 {
    type Response = Vec<u8>;
    fn process(&self, _: &[u8]) -> Self::Response {
        if self.sent.replace(true) {
            Vec::new()
        } else {
            self.initial.as_bytes().to_vec()
        }
    }
}

/// Signs in over a secure stream. A refused password or token is `SignedOut` (for
/// `account`).
fn sign_in<S: Read + Write>(
    servers: &Servers,
    secret: &Secret,
    account: &str,
    stream: S,
) -> Result<::imap::Session<S>> {
    let mut client = ::imap::Client::new(stream);
    if servers.imap.security == Security::Tls {
        client
            .read_greeting()
            .map_err(|e| anyhow!(Offline).context(e))?;
    }
    let (plain, xoauth2) = client
        .capabilities()
        .map(|c| (c.has_str("AUTH=PLAIN"), c.has_str("AUTH=XOAUTH2")))
        .unwrap_or((false, false));
    let password = match secret {
        Secret::Password(password) => password,
        Secret::Bearer(_) if !xoauth2 => {
            bail!("The mail server does not offer a way to sign in that Nimbra knows.")
        }
        Secret::Bearer(token) => {
            let initial = crate::servers::xoauth2(&servers.username, token)?;
            let signed_in = client.authenticate(
                "XOAUTH2",
                &XOAuth2 {
                    initial,
                    sent: std::cell::Cell::new(false),
                },
            );
            return signed_in_or_refused(signed_in, servers, account);
        }
    };
    let signed_in = if plain {
        client.authenticate(
            "PLAIN",
            &Plain {
                username: &servers.username,
                password,
            },
        )
    } else {
        client.login(&servers.username, password)
    };
    signed_in_or_refused(signed_in, servers, account)
}

/// The session, or why there is none: NO or BAD is a refused sign-in.
fn signed_in_or_refused<S: Read + Write>(
    signed_in: std::result::Result<::imap::Session<S>, (::imap::Error, ::imap::Client<S>)>,
    servers: &Servers,
    account: &str,
) -> Result<::imap::Session<S>> {
    match signed_in {
        Ok(session) => Ok(session),
        // What the server said goes along (cleaned, short): "enable IMAP first" and the like
        // is what tells someone setting up an account what to do.
        Err((::imap::Error::No(no), _)) => {
            let said = said(&no.information);
            let app_password = servers.is_gmail() && crate::mail::asks_for_app_password(&said);
            let refused = anyhow!(SignedOut {
                account: account.to_string(),
            })
            .context(ServerSaid(said));
            Err(if app_password {
                refused.context(crate::mail::NeedsAppPassword)
            } else {
                refused
            })
        }
        Err((::imap::Error::Bad(_), _)) => Err(SignedOut {
            account: account.to_string(),
        }
        .into()),
        Err((error, _)) => Err(anyhow!(Offline).context(error.to_string())),
    }
}

/// What a server said when it refused a sign-in, for whoever is setting the account up.
#[derive(Debug)]
pub struct ServerSaid(pub String);

impl std::fmt::Display for ServerSaid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A server's words, made safe to show: no control characters, one line, 200 at most.
fn said(text: &str) -> String {
    let clean: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    clean.chars().take(200).collect()
}

/// The IDLE connection's stream: the library sets how long a read may wait while idling.
struct Idling(TlsStream);

impl Read for Idling {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }
}

impl Write for Idling {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

impl ::imap::extensions::idle::SetReadTimeout for Idling {
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> ::imap::Result<()> {
        // None (after an IDLE) puts back the usual limit, not no limit at all.
        self.0
            .sock
            .set_read_timeout(Some(timeout.unwrap_or(IDLE_IO)))
            .map_err(::imap::Error::Io)
    }
}

/// How an IDLE connection ended, when it was not by failing.
enum Ended {
    /// The client is gone.
    Stopped,
    /// The server cannot IDLE.
    Unable,
}

/// The IDLE thread: waits on the inbox over a connection of its own, announcing each
/// change, and connects again (waiting longer each time) when the connection fails.
fn idle_inbox(watch: &Watch, servers: &Servers, credential: &Credential) {
    let mut retry = RETRY_FIRST;
    let mut watched_before = false;
    loop {
        let began = Instant::now();
        let mut watching = false;
        let ended = idle_session(watch, servers, credential, watched_before, &mut watching);
        watched_before |= watching;
        // A connection that lasted: the next failure starts the waits over.
        if watching && began.elapsed() >= IDLE_IO {
            retry = RETRY_FIRST;
        }
        match ended {
            Ok(Ended::Stopped) => return,
            Ok(Ended::Unable) => return watch.give_up(),
            // The password was refused, or Microsoft ended the sign-in: polling tells the
            // app. Never tried again from here, so a wrong one is not sent over and over.
            Err(error) if error.is::<SignedOut>() => return watch.give_up(),
            Err(_) => {}
        }
        if !watch.pause(retry) {
            return;
        }
        retry = next_retry(retry);
    }
}

/// One IDLE connection, from connecting until it fails or the client goes. `again`: one
/// watched before, so changes may have come while there was none: announced at once.
/// `watching` is set once the inbox is open.
fn idle_session(
    watch: &Watch,
    servers: &Servers,
    credential: &Credential,
    again: bool,
    watching: &mut bool,
) -> Result<Ended> {
    let secret = credential.secret()?;
    let stream = secure_stream(servers)?;
    {
        let mut state = watch.state.lock().unwrap();
        let socket = stream.sock.try_clone()?;
        if state.stop {
            return Ok(Ended::Stopped);
        }
        state.socket = Some(socket);
    }
    let mut session = sign_in(servers, &secret, "", Idling(stream)).map_err(|error| {
        // A refused token: a new one at the next try, after a wait.
        if error.is::<SignedOut>() && credential.refused(&secret) {
            token_refused("IMAP")
        } else {
            error
        }
    })?;
    let can = session
        .capabilities()
        .map(|c| c.has_str("IDLE"))
        .unwrap_or(false);
    if !can {
        let _ = session.logout();
        return Ok(Ended::Unable);
    }
    // Read-only: this connection never changes anything.
    session.examine("INBOX")?;
    *watching = true;
    if again {
        watch.announce();
    }
    loop {
        if watch.stopped() {
            return Ok(Ended::Stopped);
        }
        let waited = session
            .idle()
            .timeout(IDLE_RENEW)
            .keepalive(false)
            .wait_while(|response| !announces_change(&response));
        let outcome = match waited {
            Ok(outcome) => outcome,
            Err(_) if watch.stopped() => return Ok(Ended::Stopped),
            Err(error) => return Err(error.into()),
        };
        // What came while IDLE was being ended counts too.
        let more = session
            .take_all_unsolicited()
            .any(|response| announces_change(&response));
        if outcome == ::imap::extensions::idle::WaitOutcome::MailboxChanged || more {
            watch.announce();
        }
    }
}

/// IMAP on a plain connection made secure with STARTTLS before anything else. A server
/// that does not take it is refused.
fn starttls(host: &str, port: u16) -> Result<TlsStream> {
    let mut stream = tls::tcp(host, port)?;
    let greeting = read_line(&mut stream)?;
    if !greeting.starts_with("* OK") && !greeting.starts_with("* PREAUTH") {
        bail!("{host} did not greet as an IMAP server does.");
    }
    stream.write_all(b"a0 STARTTLS\r\n")?;
    loop {
        let line = read_line(&mut stream)?;
        if line.starts_with("a0 ") {
            if !line.starts_with("a0 OK") {
                bail!(
                    "{host} does not offer a secure connection (STARTTLS), so Nimbra did not sign in."
                );
            }
            break;
        }
    }
    tls::upgrade(stream, host)
}

/// One line from a plain connection, read byte by byte so nothing past it is taken (the
/// TLS handshake follows it).
fn read_line(stream: &mut TcpStream) -> Result<String> {
    let mut line = Vec::new();
    let mut byte = [0u8];
    while line.len() < 4096 {
        if stream.read(&mut byte).map_err(|_| anyhow!(Offline))? == 0 {
            bail!(Offline);
        }
        if byte[0] == b'\n' {
            return Ok(String::from_utf8_lossy(&line).trim_end().to_string());
        }
        line.push(byte[0]);
    }
    bail!("The server sent a line too long to be IMAP.")
}

/// UID COPY, with the folder name quoted (the library leaves it bare, so a name with a
/// space would be cut short, and one with quotes would change the command).
fn copy_to(connection: &mut Connection, uids: &str, folder: &str) -> Result<()> {
    if uids.is_empty()
        || !uids
            .bytes()
            .all(|b| b.is_ascii_digit() || b == b':' || b == b',')
    {
        bail!("unexpected message list");
    }
    connection
        .session
        .run_command_and_check_ok(format!("UID COPY {uids} {}", quote(folder)?))?;
    Ok(())
}

/// Whether an error means the connection is gone (rather than a refusal).
fn broken(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<::imap::Error>(),
            Some(::imap::Error::Io(_) | ::imap::Error::ConnectionLost | ::imap::Error::Bye(_))
        ) || cause.downcast_ref::<std::io::Error>().is_some()
    })
}

fn flags_of(flags: &[::imap::types::Flag<'_>]) -> (bool, bool) {
    use ::imap::types::Flag;
    (
        flags.iter().any(|f| matches!(f, Flag::Seen)),
        flags.iter().any(|f| matches!(f, Flag::Flagged)),
    )
}

/// Takes the flags fetched into the index, noting each thread whose flags changed. The
/// UIDs fetched.
fn take_flags(
    known: &mut Indexed,
    fetched: &::imap::types::Fetches,
    touched: &mut Vec<(String, bool)>,
) -> HashSet<u32> {
    let mut present = HashSet::new();
    for fetch in fetched.iter() {
        let Some(uid) = fetch.uid else { continue };
        present.insert(uid);
        let (seen, flagged) = flags_of(fetch.flags());
        if let Some(entry) = known.messages.get_mut(&uid)
            && (entry.seen != seen || entry.flagged != flagged)
        {
            entry.seen = seen;
            entry.flagged = flagged;
            touched.push((entry.thread.clone(), false));
        }
    }
    present
}

/// Takes out of the index the messages the server no longer has, noting their threads.
fn drop_gone(known: &mut Indexed, present: &HashSet<u32>, touched: &mut Vec<(String, bool)>) {
    let gone: Vec<u32> = known
        .messages
        .keys()
        .filter(|uid| !present.contains(uid))
        .copied()
        .collect();
    for uid in gone {
        if let Some(entry) = known.messages.remove(&uid) {
            touched.push((entry.thread, false));
        }
    }
}

/// The newest `count` UIDs of the selected folder, at or under `below` if given, oldest
/// first.
fn newest_uids(connection: &mut Connection, below: Option<u32>, count: usize) -> Result<Vec<u32>> {
    let query = match below {
        Some(0) => return Ok(Vec::new()),
        Some(top) => format!("UID 1:{top}"),
        None => "ALL".to_string(),
    };
    let mut uids: Vec<u32> = connection.session.uid_search(query)?.into_iter().collect();
    uids.sort_unstable();
    let start = uids.len().saturating_sub(count);
    Ok(uids.split_off(start))
}

fn find_by_message_id(connection: &mut Connection, message_id: &str) -> Result<Option<u32>> {
    if !crate::mail::is_message_id(message_id) {
        return Ok(None);
    }
    let found = connection
        .session
        .uid_search(format!("HEADER Message-ID {}", quote(message_id)?))?;
    Ok(found.into_iter().max())
}

/// "1,4:7,9" for a list of UIDs.
fn uid_set(uids: &[u32]) -> String {
    let mut sorted = uids.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    let mut parts = Vec::new();
    let mut i = 0;
    while i < sorted.len() {
        let start = sorted[i];
        let mut end = start;
        while i + 1 < sorted.len() && sorted[i + 1] == end + 1 {
            i += 1;
            end = sorted[i];
        }
        parts.push(if start == end {
            start.to_string()
        } else {
            format!("{start}:{end}")
        });
        i += 1;
    }
    parts.join(",")
}

/// A thread's copies grouped by folder name.
fn group(copies: &[(Folder, u32, Entry)]) -> Vec<(String, Vec<u32>)> {
    let mut groups: Vec<(String, Vec<u32>)> = Vec::new();
    for (folder, uid, _) in copies {
        match groups.iter_mut().find(|(name, _)| *name == folder.name) {
            Some((_, uids)) => uids.push(*uid),
            None => groups.push((folder.name.clone(), vec![*uid])),
        }
    }
    groups
}

/// A list row from a thread's copies.
fn summary(id: &str, copies: &[(&Folder, &Entry)], recipient: bool) -> Summary {
    let mut messages: Vec<&Entry> = Vec::new();
    let mut labels_of: HashMap<&str, Vec<String>> = HashMap::new();
    for (folder, entry) in copies {
        let labels = labels_of.entry(&entry.message_id).or_default();
        let label = folder.label();
        if !labels.contains(&label) {
            labels.push(label);
        }
        if !messages.iter().any(|m| m.message_id == entry.message_id) {
            messages.push(entry);
        }
    }
    // Flags: a message is read or starred if any of its copies is.
    for message in &messages {
        let copies_of = copies
            .iter()
            .filter(|(_, e)| e.message_id == message.message_id);
        let (mut seen, mut flagged) = (false, false);
        for (_, entry) in copies_of {
            seen |= entry.seen;
            flagged |= entry.flagged;
        }
        let labels = labels_of.entry(&message.message_id).or_default();
        if !seen && !labels.iter().any(|l| l == "SENT" || l == "DRAFT") {
            labels.push("UNREAD".into());
        }
        if flagged {
            labels.push("STARRED".into());
        }
    }
    messages.sort_by_key(|m| m.timestamp_ms);
    let latest = messages.last().copied();
    let message_labels: Vec<Vec<String>> = messages
        .iter()
        .map(|m| {
            labels_of
                .get(m.message_id.as_str())
                .cloned()
                .unwrap_or_default()
        })
        .collect();
    let mut labels: Vec<String> = Vec::new();
    for label in message_labels.iter().flatten() {
        if !labels.contains(label) {
            labels.push(label.clone());
        }
    }
    let people = messages
        .iter()
        .zip(&message_labels)
        .map(|(m, labels)| Met {
            from: m.from.clone(),
            to: m.to.clone(),
            cc: m.cc.clone(),
            timestamp_ms: m.timestamp_ms,
            sent: labels.iter().any(|l| l == "SENT"),
        })
        .collect();
    let sender_address = latest
        .and_then(|m| {
            if recipient {
                m.to.first().map(|p| p.address.trim().to_string())
            } else {
                Some(m.from.address.trim().to_string())
            }
        })
        .unwrap_or_default();
    let sender = latest.map_or_else(String::new, |m| {
        if recipient {
            m.to.iter()
                .map(|p| p.label().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        } else {
            crate::mail::sender_name(&if m.from.name.is_empty() {
                m.from.address.clone()
            } else {
                format!("{} <{}>", m.from.name, m.from.address)
            })
        }
    });
    let brand_domain = latest
        .filter(|_| !recipient)
        .and_then(|m| m.dmarc_domain.clone());
    Summary {
        id: id.to_string(),
        sender,
        sender_address,
        brand_domain,
        subject: messages
            .first()
            .map(|m| m.subject.clone())
            .unwrap_or_default(),
        snippet: latest.map(|m| m.snippet.clone()).unwrap_or_default(),
        timestamp_ms: latest.map_or(0, |m| m.timestamp_ms),
        message_count: messages.len(),
        unread: labels.iter().any(|l| l == "UNREAD"),
        starred: labels.iter().any(|l| l == "STARRED"),
        labels,
        message_labels,
        senders: messages
            .iter()
            .map(|m| m.from.address.trim().to_lowercase())
            .collect(),
        people,
    }
}

/// A thread's id: a hash of its first message's Message-ID (hex, so it is a safe id).
fn thread_id(root: &str) -> String {
    let digest = Sha256::digest(root.trim().as_bytes());
    digest.iter().take(12).map(|b| format!("{b:02x}")).collect()
}

fn is_thread_id(id: &str) -> bool {
    id.len() == 24 && id.bytes().all(|b| b.is_ascii_hexdigit())
}

/// A user label's id: "f" and its folder's name in hex.
fn label_id(folder: &str) -> String {
    let hex: String = folder.bytes().map(|b| format!("{b:02x}")).collect();
    format!("f{hex}")
}

fn folder_of_label(id: &str) -> Result<String> {
    let hex = id.strip_prefix('f').context("unexpected label id")?;
    let name = from_hex(hex).context("unexpected label id")?;
    if !folder_name_ok(&name) {
        bail!("unexpected label id");
    }
    Ok(name)
}

/// A message's key: folder (hex), the folder's UIDVALIDITY and the UID. Attachment and
/// draft ids are these.
fn message_key(folder: &str, validity: u32, uid: u32) -> String {
    let hex: String = folder.bytes().map(|b| format!("{b:02x}")).collect();
    format!("{hex}.{validity}.{uid}")
}

fn parse_key(key: &str) -> Result<(String, u32, u32)> {
    let mut parts = key.split('.');
    let (Some(hex), Some(validity), Some(uid), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        bail!("unexpected message id");
    };
    let folder = from_hex(hex).context("unexpected message id")?;
    if !folder_name_ok(&folder) {
        bail!("unexpected message id");
    }
    Ok((
        folder,
        validity.parse().context("unexpected message id")?,
        uid.parse().context("unexpected message id")?,
    ))
}

fn from_hex(hex: &str) -> Option<String> {
    if hex.is_empty() || !hex.len().is_multiple_of(2) || hex.len() > 1000 {
        return None;
    }
    let bytes: Option<Vec<u8>> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(hex.get(i..i + 2)?, 16).ok())
        .collect();
    String::from_utf8(bytes?).ok()
}

/// A folder name the server gave (or one built here) that is safe to put in a command:
/// no line breaks or other control characters.
fn folder_name_ok(name: &str) -> bool {
    !name.is_empty() && name.len() <= 1000 && !name.chars().any(char::is_control)
}

/// What a listed folder is for, from its special-use attributes first, then its name.
/// `None` for one that is not a folder of its own: not selectable, or one that shows
/// messages kept elsewhere again (Gmail's All Mail, Starred and Important).
fn role_of(name: &str, attributes: &[imap_proto::NameAttribute<'_>], gmail: bool) -> Option<Role> {
    use imap_proto::NameAttribute as A;
    let extension = |wanted: &str| {
        attributes
            .iter()
            .any(|a| matches!(a, A::Extension(e) if e.eq_ignore_ascii_case(wanted)))
    };
    if attributes.iter().any(|a| matches!(a, A::NoSelect)) || extension("\\NonExistent") {
        return None;
    }
    if name.eq_ignore_ascii_case("INBOX") {
        return Some(Role::Inbox);
    }
    // Gmail's Important (RFC 8457's \Important) only shows mail kept elsewhere; on other
    // servers it can be a real folder.
    if gmail && extension("\\Important") {
        return None;
    }
    let special = attributes.iter().find_map(|a| match a {
        A::Sent => Some(Some(Role::Sent)),
        A::Drafts => Some(Some(Role::Drafts)),
        A::Trash => Some(Some(Role::Trash)),
        A::Junk => Some(Some(Role::Junk)),
        A::Archive => Some(Some(Role::Archive)),
        A::All | A::Flagged => Some(None),
        _ => None,
    });
    special.unwrap_or_else(|| Some(role_by_name(name)))
}

fn role_by_name(name: &str) -> Role {
    let last = name
        .rsplit(['/', '.'])
        .next()
        .unwrap_or(name)
        .to_ascii_lowercase();
    match last.as_str() {
        "sent" | "sent items" | "sent messages" | "sent mail" => Role::Sent,
        "drafts" | "draft" => Role::Drafts,
        "trash" | "deleted items" | "deleted messages" | "bin" => Role::Trash,
        "junk" | "spam" | "junk e-mail" | "junk email" | "bulk mail" => Role::Junk,
        "archive" | "archives" => Role::Archive,
        _ => Role::Label,
    }
}

/// An IMAP quoted string, refusing what cannot be in one.
fn quote(text: &str) -> Result<String> {
    if text.chars().any(|c| c == '\r' || c == '\n' || c == '\0') {
        bail!("That cannot be searched for.");
    }
    Ok(format!(
        "\"{}\"",
        text.replace('\\', "\\\\").replace('"', "\\\"")
    ))
}

/// IMAP SEARCH criteria from the words typed: from:, to:, subject:, is:unread, is:starred
/// and plain words (in the text), all of which must match.
fn search_criteria(query: &str) -> Result<String> {
    let query = query.trim();
    if query.is_empty() || query.len() > 500 {
        bail!("Type something to search for.");
    }
    let mut parts = Vec::new();
    for word in query.split_whitespace() {
        let (key, value) = word.split_once(':').unwrap_or(("", word));
        let value = value.trim_matches('"');
        let part = match key.to_ascii_lowercase().as_str() {
            "from" => format!("FROM {}", quote(value)?),
            "to" => format!("TO {}", quote(value)?),
            "cc" => format!("CC {}", quote(value)?),
            "subject" => format!("SUBJECT {}", quote(value)?),
            "is" if value.eq_ignore_ascii_case("unread") => "UNSEEN".to_string(),
            "is" if value.eq_ignore_ascii_case("read") => "SEEN".to_string(),
            "is" if value.eq_ignore_ascii_case("starred") => "FLAGGED".to_string(),
            _ => format!("TEXT {}", quote(word.trim_matches('"'))?),
        };
        parts.push(part);
    }
    Ok(parts.join(" "))
}

/// The Message-ID header of a raw message.
/// Adds a message to those kept in memory, dropping the oldest past the count or the size.
fn keep_raw(kept: &mut VecDeque<(String, Arc<Vec<u8>>)>, key: &str, raw: Arc<Vec<u8>>) {
    kept.push_back((key.to_string(), raw));
    let mut size: usize = kept.iter().map(|(_, raw)| raw.len()).sum();
    while kept.len() > RAW_KEPT || (kept.len() > 1 && size > RAW_KEPT_BYTES) {
        if let Some((_, oldest)) = kept.pop_front() {
            size -= oldest.len();
        }
    }
}

fn header_message_id(raw: &[u8]) -> Option<String> {
    crate::mime::headers(raw)
        .map(|h| h.message_id)
        .filter(|id| crate::mail::is_message_id(id))
}

/// Modified UTF-7 (RFC 3501 5.1.3), the form folder names take on the wire.
fn encode_utf7(text: &str) -> String {
    use base64::Engine as _;
    let engine = base64::engine::general_purpose::STANDARD_NO_PAD;
    let mut out = String::new();
    let mut pending: Vec<u16> = Vec::new();
    let flush = |pending: &mut Vec<u16>, out: &mut String| {
        if pending.is_empty() {
            return;
        }
        let bytes: Vec<u8> = pending.iter().flat_map(|u| u.to_be_bytes()).collect();
        out.push('&');
        out.push_str(&engine.encode(bytes).replace('/', ","));
        out.push('-');
        pending.clear();
    };
    for c in text.chars() {
        if (' '..='~').contains(&c) {
            flush(&mut pending, &mut out);
            if c == '&' {
                out.push_str("&-");
            } else {
                out.push(c);
            }
        } else {
            let mut units = [0u16; 2];
            pending.extend_from_slice(c.encode_utf16(&mut units));
        }
    }
    flush(&mut pending, &mut out);
    out
}

fn decode_utf7(text: &str) -> String {
    use base64::Engine as _;
    let engine = base64::engine::general_purpose::STANDARD_NO_PAD;
    let mut out = String::new();
    let mut rest = text;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        let after = &rest[at + 1..];
        let Some(end) = after.find('-') else {
            out.push_str(&rest[at..]);
            return out;
        };
        let encoded = &after[..end];
        if encoded.is_empty() {
            out.push('&');
        } else {
            match engine.decode(encoded.replace(',', "/")) {
                Ok(bytes) if bytes.len().is_multiple_of(2) => {
                    let units: Vec<u16> = bytes
                        .chunks(2)
                        .map(|p| u16::from_be_bytes([p[0], p[1]]))
                        .collect();
                    out.push_str(&String::from_utf16_lossy(&units));
                }
                _ => out.push_str(&rest[at..at + 1 + end + 1]),
            }
        }
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    out
}

/// Checks that an account's IMAP server takes its password (or token), for setting it up. The mail
/// is not looked at.
pub fn check_login(servers: &Servers, credential: Credential) -> Result<()> {
    let client = Client::new(String::new(), String::new(), servers.clone(), credential);
    let mut connection = client.open()?;
    let _ = connection.session.logout();
    Ok(())
}

impl From<SignedOut> for MayHaveArrived {
    fn from(_: SignedOut) -> Self {
        MayHaveArrived
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kept_raw_messages_stay_under_the_size_budget() {
        let mut kept = VecDeque::new();
        for n in 0..4 {
            keep_raw(
                &mut kept,
                &n.to_string(),
                Arc::new(vec![0; RAW_KEPT_BYTES / 3]),
            );
        }
        let size: usize = kept.iter().map(|(_, raw)| raw.len()).sum();
        assert!(size <= RAW_KEPT_BYTES, "{size}");
    }

    #[test]
    fn the_newest_raw_message_is_kept_even_when_larger_than_the_budget() {
        let mut kept = VecDeque::new();
        keep_raw(&mut kept, "old", Arc::new(vec![0; 10]));
        keep_raw(&mut kept, "big", Arc::new(vec![0; RAW_KEPT_BYTES + 1]));
        let keys: Vec<_> = kept.iter().map(|(key, _)| key.as_str()).collect();
        assert_eq!(keys, ["big"]);
    }

    /// A server that answers with what it was given, keeping what it is sent where the test
    /// can see it after the stream is gone.
    struct Scripted {
        answers: std::io::Cursor<Vec<u8>>,
        sent: Arc<Mutex<Vec<u8>>>,
    }

    impl Read for Scripted {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.answers.read(buf)
        }
    }

    impl Write for Scripted {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.sent.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn scripted_sign_in(answers: &str, secret: &Secret) -> (Result<()>, String) {
        // STARTTLS servers: no greeting is read here (`starttls` read it).
        let servers = Servers {
            username: "ana@outlook.com".into(),
            imap: crate::servers::Server::new("imap.example.com", 143, Security::StartTls),
            smtp: crate::servers::Server::new("smtp.example.com", 587, Security::StartTls),
        };
        scripted_sign_in_to(&servers, answers, secret)
    }

    fn scripted_sign_in_to(
        servers: &Servers,
        answers: &str,
        secret: &Secret,
    ) -> (Result<()>, String) {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let stream = Scripted {
            answers: std::io::Cursor::new(answers.as_bytes().to_vec()),
            sent: sent.clone(),
        };
        let result = sign_in(servers, secret, "acct", stream).map(|_| ());
        let sent = String::from_utf8(sent.lock().unwrap().clone()).unwrap();
        (result, sent)
    }

    #[test]
    fn a_token_signs_in_with_authenticate_xoauth2() {
        use base64::Engine as _;
        let b64 = |text: &str| base64::engine::general_purpose::STANDARD.encode(text);
        const CAPS: &str = "* CAPABILITY IMAP4rev1 AUTH=PLAIN AUTH=XOAUTH2\r\na1 OK done\r\n";
        let token = Secret::Bearer("EwBtoken".into());
        let initial = b64("user=ana@outlook.com\x01auth=Bearer EwBtoken\x01\x01");

        // Both forms of the empty challenge, "+ " and "+".
        for go_ahead in ["+ \r\n", "+\r\n"] {
            let (result, sent) = scripted_sign_in(
                &format!("{CAPS}{go_ahead}a2 OK AUTHENTICATE completed.\r\n"),
                &token,
            );
            assert!(result.is_ok(), "{result:?}");
            assert_eq!(
                sent,
                format!("a1 CAPABILITY\r\na2 AUTHENTICATE XOAUTH2\r\n{initial}\r\n")
            );
        }

        // Refused: the JSON challenge is answered with an empty line, then NO is SignedOut.
        let challenge = b64(r#"{"status":"401","schemes":"Bearer","scope":"x"}"#);
        let (result, sent) = scripted_sign_in(
            &format!("{CAPS}+ \r\n+ {challenge}\r\na2 NO AUTHENTICATE failed.\r\n"),
            &token,
        );
        let error = result.unwrap_err();
        assert!(
            error
                .downcast_ref::<SignedOut>()
                .is_some_and(|e| e.account == "acct")
        );
        assert!(sent.ends_with(&format!("{initial}\r\n\r\n")), "{sent:?}");
        assert!(!format!("{error:#}").contains("EwBtoken"));

        // Not offered: nothing is sent but the question.
        let (result, sent) = scripted_sign_in(
            "* CAPABILITY IMAP4rev1 AUTH=PLAIN\r\na1 OK done\r\n",
            &token,
        );
        assert!(result.is_err_and(|e| !e.is::<SignedOut>()));
        assert_eq!(sent, "a1 CAPABILITY\r\n");

        // A password still goes with PLAIN.
        let (result, sent) = scripted_sign_in(
            &format!("{CAPS}+ \r\na2 OK done\r\n"),
            &Secret::Password("pw".into()),
        );
        assert!(result.is_ok());
        assert!(
            sent.contains("AUTHENTICATE PLAIN") && sent.contains(&b64("\0ana@outlook.com\0pw"))
        );
    }

    const ASP_REQUIRED: &str = "+ \r\na2 NO [ALERT] Application-specific password required: https://support.google.com/accounts/answer/185833 (Failure)\r\n";

    #[test]
    fn another_server_asking_for_an_app_password_is_only_signed_out() {
        let caps = "* CAPABILITY IMAP4rev1 AUTH=PLAIN\r\na1 OK done\r\n";
        let (result, _) = scripted_sign_in(
            &format!("{caps}{ASP_REQUIRED}"),
            &Secret::Password("pw".into()),
        );
        let error = result.unwrap_err();
        assert!(error.is::<SignedOut>());
        assert!(!error.is::<crate::mail::NeedsAppPassword>());
    }

    #[test]
    fn gmails_own_password_with_two_step_verification_asks_for_an_app_password() {
        let caps =
            "* OK Gimap ready\r\n* CAPABILITY IMAP4rev1 AUTH=PLAIN AUTH=XOAUTH2\r\na1 OK done\r\n";
        let (result, _) = scripted_sign_in_to(
            &crate::servers::gmail("jo@gmail.com"),
            &format!("{caps}{ASP_REQUIRED}"),
            &Secret::Password("typed-secret".into()),
        );
        let error = result.unwrap_err();
        assert!(error.is::<crate::mail::NeedsAppPassword>(), "{error:#}");
        assert!(
            error
                .downcast_ref::<SignedOut>()
                .is_some_and(|e| e.account == "acct")
        );
        assert!(!format!("{error:#}").contains("typed-secret"));
    }

    #[test]
    fn a_wrong_app_password_is_only_signed_out() {
        let caps = "* CAPABILITY IMAP4rev1 AUTH=PLAIN AUTH=XOAUTH2\r\na1 OK done\r\n";
        let (result, _) = scripted_sign_in(
            &format!("{caps}+ \r\na2 NO [AUTHENTICATIONFAILED] Invalid credentials (Failure)\r\n"),
            &Secret::Password("wrongwrongwrongw".into()),
        );
        let error = result.unwrap_err();
        assert!(error.is::<SignedOut>());
        assert!(!error.is::<crate::mail::NeedsAppPassword>());
    }

    #[test]
    fn an_important_folder_elsewhere_is_a_label() {
        use imap_proto::NameAttribute as A;
        let important = [A::Extension("\\Important".into())];
        assert_eq!(role_of("Important", &important, false), Some(Role::Label));
    }

    #[test]
    fn gmails_virtual_folders_are_not_labels() {
        use imap_proto::NameAttribute as A;
        let important = [A::NoInferiors, A::Extension("\\Important".into())];
        for (name, attributes) in [
            ("[Gmail]/All Mail", &[A::All][..]),
            ("[Gmail]/Starred", &[A::Flagged][..]),
            ("[Gmail]/Important", &important[..]),
            ("[Gmail]", &[A::NoSelect][..]),
        ] {
            assert_eq!(role_of(name, attributes, true), None, "{name}");
        }
        assert_eq!(
            role_of("[Gmail]/Sent Mail", &[A::Sent], true),
            Some(Role::Sent)
        );
        assert_eq!(role_of("[Gmail]/Spam", &[A::Junk], true), Some(Role::Junk));
        assert_eq!(role_of("INBOX", &[], true), Some(Role::Inbox));
        assert_eq!(role_of("Receipts", &[], true), Some(Role::Label));
    }

    #[test]
    fn folder_names_go_to_and_from_modified_utf7() {
        for name in [
            "INBOX",
            "Archive/2026",
            "Rechnungen & Belege",
            "Входящие",
            "日本語",
            "a&b",
        ] {
            let wire = encode_utf7(name);
            assert!(wire.is_ascii(), "{wire}");
            assert_eq!(decode_utf7(&wire), name);
        }
        assert_eq!(encode_utf7("&"), "&-");
        assert_eq!(decode_utf7("&ZeVnLIqe-"), "日本語");
        // Not valid: kept as it is rather than lost.
        assert_eq!(decode_utf7("odd&"), "odd&");
    }

    #[test]
    fn ids_handed_back_are_parsed_strictly() {
        let key = message_key("INBOX", 7, 42);
        assert_eq!(parse_key(&key).unwrap(), ("INBOX".to_string(), 7, 42));
        for bad in [
            "",
            "zz.1.2",
            "494e424f58.1",
            "494e424f58.x.2",
            "494e424f580a.1.2",
            "494e424f58.1.2.3",
        ] {
            assert!(parse_key(bad).is_err(), "{bad}");
        }
        let label = label_id("Work/Clients");
        assert_eq!(folder_of_label(&label).unwrap(), "Work/Clients");
        assert!(folder_of_label("f0a0d").is_err());
        assert!(folder_of_label("INBOX").is_err());
        assert!(is_thread_id(&thread_id("<a@b.co>")));
        assert!(!is_thread_id("../../etc"));
    }

    #[test]
    fn search_words_cannot_carry_a_command() {
        assert_eq!(
            search_criteria("from:ana invoice \"due\"").unwrap(),
            "FROM \"ana\" TEXT \"invoice\" TEXT \"due\""
        );
        assert_eq!(search_criteria("is:unread").unwrap(), "UNSEEN");
        // Line breaks only ever separate words: none reaches the command.
        let typed = search_criteria("x\r\nA1 DELETE INBOX").unwrap();
        assert!(!typed.contains(['\r', '\n']));
        assert_eq!(
            typed,
            "TEXT \"x\" TEXT \"A1\" TEXT \"DELETE\" TEXT \"INBOX\""
        );
        assert!(quote("a\r\nb").is_err());
        assert_eq!(quote("a\"b\\c").unwrap(), "\"a\\\"b\\\\c\"");
        assert!(search_criteria("   ").is_err());
    }

    #[test]
    fn uid_sets_are_ranges() {
        assert_eq!(uid_set(&[5, 1, 2, 3, 9, 10]), "1:3,5,9:10");
        assert_eq!(uid_set(&[]), "");
    }

    #[test]
    fn folders_without_special_use_are_known_by_name() {
        assert_eq!(role_by_name("Sent Items"), Role::Sent);
        assert_eq!(role_by_name("INBOX.Trash"), Role::Trash);
        assert_eq!(role_by_name("Deleted Messages"), Role::Trash);
        assert_eq!(role_by_name("Spam"), Role::Junk);
        assert_eq!(role_by_name("Clients"), Role::Label);
    }

    #[test]
    fn a_folder_where_nothing_moved_is_skipped_only_with_condstore() {
        let known = Indexed {
            uid_next: 50,
            exists: Some(20),
            mod_seq: Some(900),
            ..Default::default()
        };
        let now = Seen {
            next: 50,
            exists: 20,
            mod_seq: Some(900),
        };
        assert!(unchanged(&known, now));
        // A flag changed, a message came, one went.
        for moved in [
            Seen {
                mod_seq: Some(901),
                ..now
            },
            Seen { next: 51, ..now },
            Seen { exists: 19, ..now },
        ] {
            assert!(!unchanged(&known, moved), "{moved:?}");
        }
        // Without CONDSTORE (or before the first look with it) a flag change shows nowhere.
        let plain = Seen {
            mod_seq: None,
            ..now
        };
        let unknown = Indexed {
            mod_seq: None,
            ..known.clone()
        };
        assert!(!unchanged(&known, plain));
        assert!(!unchanged(&unknown, plain));
        assert!(!unchanged(&unknown, now));
    }

    #[test]
    fn the_count_says_when_messages_may_have_gone() {
        // 20, then 2 came: 22 means none went, 21 that one did.
        assert!(!may_have_gone(Some(20), 2, 22));
        assert!(may_have_gone(Some(20), 2, 21));
        assert!(may_have_gone(Some(20), 0, 19));
        // More than counted (one came after the count): nothing to look for.
        assert!(!may_have_gone(Some(20), 0, 21));
        // Not known (an index saved before counts were): look.
        assert!(may_have_gone(None, 0, 20));
        // No overflow at the top.
        assert!(may_have_gone(Some(u32::MAX), 1, u32::MAX));
    }

    #[test]
    fn an_index_saved_before_condstore_still_loads() {
        let old = r#"{"uid_validity":7,"uid_next":12,"oldest":1,"complete":true,"messages":{}}"#;
        let known: Indexed = serde_json::from_str(old).unwrap();
        assert_eq!((known.uid_validity, known.uid_next), (7, 12));
        assert_eq!((known.mod_seq, known.exists), (None, None));
    }

    #[test]
    fn idle_wakes_for_changes_to_the_mailbox_only() {
        use ::imap::types::UnsolicitedResponse as U;
        assert!(announces_change(&U::Exists(3)));
        assert!(announces_change(&U::Expunge(2)));
        assert!(announces_change(&U::Vanished {
            earlier: false,
            uids: vec![4..=6, 9..=9],
        }));
        assert!(!announces_change(&U::Recent(1)));
        // Dovecot's "* OK Still here" while idling.
        assert!(!announces_change(&U::Ok {
            code: None,
            information: Some("Still here".into()),
        }));
    }

    #[test]
    fn retries_wait_longer_each_time_up_to_a_limit() {
        let mut wait = RETRY_FIRST;
        let mut waits = Vec::new();
        for _ in 0..10 {
            waits.push(wait.as_secs());
            wait = next_retry(wait);
        }
        assert_eq!(waits, [5, 10, 20, 40, 80, 160, 300, 300, 300, 300]);
        assert!(IDLE_RENEW < Duration::from_secs(25 * 60));
    }

    #[test]
    fn a_change_wakes_a_wait_once_and_a_stop_ends_it() {
        let client = offline_client();
        let watch = client.watch.clone();
        // Not signed in yet, or no IDLE: returns at once.
        assert!(!client.wait_for_change(Duration::from_secs(5)));
        {
            let mut state = watch.state.lock().unwrap();
            state.can_idle = Some(true);
            // As if the thread were running (none is started in a unit test).
            state.started = true;
        }
        let announcer = watch.clone();
        let thread = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            announcer.announce();
        });
        let began = Instant::now();
        assert!(client.wait_for_change(Duration::from_secs(10)));
        assert!(began.elapsed() < Duration::from_secs(5));
        thread.join().unwrap();
        // Seen: the next wait times out.
        assert!(!client.wait_for_change(Duration::from_millis(50)));
        // Gone: the wait (and the thread's pauses) end.
        drop(client);
        assert!(watch.stopped());
        assert!(!watch.pause(Duration::from_secs(10)));
    }

    fn offline_client() -> Client {
        let servers = Servers {
            username: "me".into(),
            imap: crate::servers::Server::new("localhost", 1, Security::Tls),
            smtp: crate::servers::Server::new("localhost", 1, Security::Tls),
        };
        Client::new(
            String::new(),
            String::new(),
            servers,
            Credential::Password(String::new()),
        )
    }

    fn entry(id: &str, thread: &str, at: i64, seen: bool) -> Entry {
        Entry {
            message_id: id.into(),
            thread: thread.into(),
            from: Person {
                name: "Ana".into(),
                address: "ana@example.com".into(),
            },
            to: vec![],
            cc: vec![],
            subject: "Trip".into(),
            timestamp_ms: at,
            snippet: format!("snippet {id}"),
            seen,
            flagged: false,
            dmarc_domain: None,
        }
    }

    #[test]
    fn a_message_in_two_folders_is_one_message_with_two_labels() {
        let inbox = Folder {
            name: "INBOX".into(),
            role: Role::Inbox,
        };
        let work = Folder {
            name: "Work".into(),
            role: Role::Label,
        };
        let sent = Folder {
            name: "Sent".into(),
            role: Role::Sent,
        };
        let a = entry("<a@x>", "t", 1, false);
        let a_copy = entry("<a@x>", "t", 1, true);
        let reply = entry("<b@x>", "t", 2, true);
        let row = summary(
            "t",
            &[(&inbox, &a), (&work, &a_copy), (&sent, &reply)],
            false,
        );
        assert_eq!(row.message_count, 2);
        // Read in one folder is read: IMAP flags are per copy, the app's are per message.
        assert!(!row.unread);
        assert!(row.labels.contains(&"INBOX".to_string()));
        assert!(row.labels.contains(&label_id("Work")));
        assert!(row.labels.contains(&"SENT".to_string()));
        assert_eq!(row.snippet, "snippet <b@x>");
        assert_eq!(row.timestamp_ms, 2);
        // Done holds what is in no inbox: this thread is not.
        assert!(!View::Done.takes(&row, None) || !row.labels.contains(&"INBOX".to_string()));
    }
}

/// Against real servers, when asked for (`cargo test -- --ignored live`): IMAP on
/// localhost:10993 and SMTP on localhost:10587 (STARTTLS), any user with password "pass",
/// their CA in NIMBRA_TEST_CA. See tasks/todo.md for the containers.
#[cfg(test)]
mod live {
    use super::*;
    use crate::servers::Server;

    fn client(user: &str) -> Client {
        let servers = Servers {
            username: user.to_string(),
            imap: Server::new("localhost", 10993, Security::Tls),
            smtp: Server::new("localhost", 10587, Security::StartTls),
        };
        Client::new(
            "acct".into(),
            user.to_string(),
            servers,
            Credential::Password("pass".into()),
        )
    }

    fn put(client: &Client, folder: &str, raw: &str, seen: bool) {
        client
            .with(false, |c| {
                let flags = if seen {
                    vec![::imap::types::Flag::Seen]
                } else {
                    vec![]
                };
                c.session
                    .append(folder, raw.as_bytes())
                    .flags(flags)
                    .finish()?;
                Ok(())
            })
            .unwrap();
    }

    fn mail(id: &str, subject: &str, extra: &str, body: &str) -> String {
        format!(
            "From: Ana <ana@example.com>\r\nTo: me@example.org\r\nSubject: {subject}\r\n\
             Date: Mon, 23 Nov 2026 10:00:00 +0000\r\nMessage-ID: {id}\r\n{extra}\
             MIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n{body}\r\n"
        )
    }

    #[test]
    #[ignore]
    fn live_people_of_sent_and_received_mail_a_page_at_a_time() {
        let user = format!("p{}@example.org", std::process::id());
        let c = client(&user);
        for i in 0..PEOPLE_PAGE + 5 {
            let raw = format!(
                "From: {user}\r\nTo: \"Lima, Ana\" <ana{i}@example.com>\r\nCc: Bo <bo@example.com>\r\n\
                 Subject: s\r\nDate: Mon, 23 Nov 2026 10:00:00 +0000\r\nMessage-ID: <s{i}@x>\r\n\r\nHi\r\n"
            );
            put(&c, "Sent", &raw, true);
        }
        put(
            &c,
            "INBOX",
            &mail("<r1@x>", "Hello", "Cc: Cy <cy@example.com>\r\n", "Hi"),
            false,
        );

        let (first, next) = c.people_page(true, None).unwrap();
        assert_eq!(first.len(), PEOPLE_PAGE);
        assert!(first.iter().all(|m| m.sent));
        assert_eq!(first[0].to[0].name, "Lima, Ana");
        assert_eq!(first[0].cc[0].address, "bo@example.com");
        assert!(first[0].timestamp_ms > 0);
        let (rest, after) = c.people_page(true, next.as_deref()).unwrap();
        assert_eq!(rest.len(), 5);
        assert_eq!(after, None);
        let mut every: Vec<String> = first
            .iter()
            .chain(&rest)
            .map(|m| m.to[0].address.clone())
            .collect();
        every.sort();
        every.dedup();
        assert_eq!(
            every.len(),
            PEOPLE_PAGE + 5,
            "no message twice, none left out"
        );

        let (received, next) = c.people_page(false, None).unwrap();
        assert_eq!(next, None);
        assert_eq!(received.len(), 1);
        assert!(!received[0].sent);
        assert_eq!(received[0].from.address, "ana@example.com");
        assert_eq!(received[0].cc[0].address, "cy@example.com");
        // Read without marking it read.
        let (rows, _) = c.threads_page(View::Inbox, None, 30, None).unwrap();
        assert!(rows[0].unread);
        assert_eq!(rows[0].people[0].cc[0].address, "cy@example.com");
        assert!(c.people_page(true, Some("not a uid")).is_err());
    }

    #[test]
    #[ignore]
    fn live_a_whole_mailbox() {
        let user = format!("t{}@example.org", std::process::id());
        let c = client(&user);
        assert!(check_login(&c.servers, Credential::Password("pass".into())).is_ok());
        assert!(
            check_login(&c.servers, Credential::Password("wrong".into()))
                .is_err_and(|e| e.is::<SignedOut>()),
            "a wrong password is a sign-in to fix"
        );
        let (email, start) = c.profile().unwrap();
        assert_eq!(email, user);

        // Two messages of one thread in the inbox, one unread; a reply in Sent.
        put(
            &c,
            "INBOX",
            &mail("<1@x>", "Trip", "", "Shall we go?"),
            true,
        );
        put(
            &c,
            "INBOX",
            &mail(
                "<2@x>",
                "Re: Trip",
                "In-Reply-To: <1@x>\r\nReferences: <1@x>\r\n",
                "Yes, Friday.",
            ),
            false,
        );
        put(
            &c,
            "Sent",
            &mail(
                "<3@x>",
                "Re: Trip",
                "In-Reply-To: <2@x>\r\nReferences: <1@x> <2@x>\r\n",
                "Great.",
            ),
            true,
        );
        put(
            &c,
            "INBOX",
            &mail("<4@x>", "Invoice", "", "Due soon."),
            true,
        );

        let (rows, _) = c.threads_page(View::Inbox, None, 30, None).unwrap();
        assert_eq!(
            rows.len(),
            2,
            "{:?}",
            rows.iter().map(|r| &r.subject).collect::<Vec<_>>()
        );
        let trip = rows.iter().find(|r| r.subject == "Trip").unwrap();
        assert_eq!(trip.message_count, 3);
        assert!(trip.unread);
        assert!(trip.labels.contains(&"SENT".to_string()));
        assert_eq!(trip.snippet, "Great.");
        let messages = c.thread(&trip.id).unwrap();
        assert_eq!(messages.len(), 3);
        assert_eq!(messages[0].message_id, "<1@x>");

        // The feed sees a new unread message arriving.
        let changes = c.history(&start).unwrap();
        let at = changes.latest.clone();
        put(
            &c,
            "INBOX",
            &mail(
                "<5@x>",
                "Re: Trip",
                "In-Reply-To: <3@x>\r\nReferences: <1@x> <3@x>\r\n",
                "See you.",
            ),
            false,
        );
        let changes = c.history(&at).unwrap();
        assert_eq!(changes.new_unread_inbox, vec![trip.id.clone()]);

        // Read, star, archive (Done), back.
        c.change(&trip.id, Change::MarkRead).unwrap();
        c.change(&trip.id, Change::Star).unwrap();
        let row = c.summary(&trip.id, false).unwrap();
        assert!(!row.unread && row.starred);
        c.change(&trip.id, Change::Archive).unwrap();
        let (inbox, _) = c.threads_page(View::Inbox, None, 30, None).unwrap();
        assert!(!inbox.iter().any(|r| r.id == trip.id));
        let (done, _) = c.threads_page(View::Done, None, 30, None).unwrap();
        assert!(
            done.iter().any(|r| r.id == trip.id),
            "archived mail is in Done"
        );
        c.change(&trip.id, Change::Unarchive).unwrap();
        let (inbox, _) = c.threads_page(View::Inbox, None, 30, None).unwrap();
        assert!(inbox.iter().any(|r| r.id == trip.id));
        let (starred, _) = c.threads_page(View::Starred, None, 30, None).unwrap();
        assert!(starred.iter().any(|r| r.id == trip.id));

        // Back from a snooze: out of Done into the inbox, unread; the reply stays in Sent
        // only, and nothing is left behind in Archive.
        c.change(&trip.id, Change::Archive).unwrap();
        c.relabel(&trip.id, &["INBOX", "UNREAD"], &[]).unwrap();
        let row = c.summary(&trip.id, false).unwrap();
        assert!(row.unread && row.labels.contains(&"INBOX".to_string()));
        let (done, _) = c.threads_page(View::Done, None, 30, None).unwrap();
        assert!(
            !done.iter().any(|r| r.id == trip.id),
            "a copy stayed in Archive"
        );
        let copied = c
            .with(true, |conn| {
                conn.selected = None;
                conn.session.examine("INBOX")?;
                Ok(conn
                    .session
                    .uid_search("HEADER Message-ID \"<3@x>\"")?
                    .len())
            })
            .unwrap();
        assert_eq!(copied, 0, "the user's own reply was copied into the inbox");

        // Labels are folders.
        let label = c.create_label("Reisen & Pläne").unwrap();
        assert!(
            c.labels()
                .unwrap()
                .iter()
                .any(|l| l.name == "Reisen & Pläne")
        );
        c.add_label(&trip.id, &label.id).unwrap();
        let row = c.summary(&trip.id, false).unwrap();
        assert!(row.labels.contains(&label.id) && row.labels.contains(&"INBOX".to_string()));
        let (in_label, _) = c
            .threads_page(View::Label(0), Some(&label.id), 30, None)
            .unwrap();
        assert!(in_label.iter().any(|r| r.id == trip.id));
        c.remove_label(&trip.id, &label.id).unwrap();
        assert!(
            !c.summary(&trip.id, false)
                .unwrap()
                .labels
                .contains(&label.id)
        );
        c.rename_label(&label.id, "Travel").unwrap();
        let travel = c
            .labels()
            .unwrap()
            .into_iter()
            .find(|l| l.name == "Travel")
            .unwrap();
        c.delete_label(&travel.id).unwrap();
        assert!(c.labels().unwrap().is_empty());

        // Trash and back to where it was.
        let invoice = inbox
            .iter()
            .find(|r| r.subject == "Invoice")
            .unwrap()
            .id
            .clone();
        c.change(&invoice, Change::Trash).unwrap();
        let (trash, _) = c.threads_page(View::Trash, None, 30, None).unwrap();
        assert!(trash.iter().any(|r| r.id == invoice));
        c.change(&invoice, Change::Untrash).unwrap();
        let (inbox, _) = c.threads_page(View::Inbox, None, 30, None).unwrap();
        assert!(inbox.iter().any(|r| r.id == invoice));

        // A draft: saved, saved over, read back, deleted.
        let draft = Outgoing {
            to: "bo@example.com".into(),
            bcc: "hidden@example.com".into(),
            subject: "Plans".into(),
            body: "First go".into(),
            ..Default::default()
        };
        let first = c.save_draft(None, &draft).unwrap();
        let second = c
            .save_draft(
                Some(&first),
                &Outgoing {
                    body: "Second go".into(),
                    ..draft.clone()
                },
            )
            .unwrap();
        let (drafts, _) = c.threads_page(View::Drafts, None, 30, None).unwrap();
        assert_eq!(drafts.len(), 1);
        let read = c.draft_for_thread(&drafts[0].id).unwrap();
        assert_eq!(read.id, second);
        assert!(read.body.contains("Second go"));
        assert!(read.bcc.contains("hidden@example.com"));
        c.delete_draft(&second).unwrap();
        let (drafts, _) = c.threads_page(View::Drafts, None, 30, None).unwrap();
        assert!(drafts.is_empty());

        // Sending: SMTP, then a copy in Sent without its Bcc.
        let sent = Outgoing {
            to: "bo@example.com".into(),
            bcc: "hidden@example.com".into(),
            subject: "Hello from IMAP".into(),
            body: "Sent over SMTP".into(),
            ..Default::default()
        };
        c.send_message(&sent).unwrap();
        let (rows, _) = c.threads_page(View::Sent, None, 30, None).unwrap();
        let row = rows
            .iter()
            .find(|r| r.subject == "Hello from IMAP")
            .expect("filed in Sent");
        let message = &c.thread(&row.id).unwrap()[0];
        assert!(!message.others.iter().any(|a| a.contains("hidden")));

        // Search.
        let (found, _) = c
            .threads_page(View::Search, Some("Friday"), 30, None)
            .unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id, trip.id);
        let (found, _) = c
            .threads_page(View::Search, Some("from:ana invoice"), 30, None)
            .unwrap();
        assert_eq!(found.len(), 1);

        // Counts, and the index kept over a new connection.
        let counts = c.counts(&["INBOX".to_string(), "DRAFT".to_string()]);
        assert!(counts.contains_key("INBOX"));
    }

    /// Runs a command on `client`'s own connection, with INBOX selected: what another
    /// mail app on the same account would do.
    fn elsewhere(client: &Client, command: impl Fn(&mut Session) -> ::imap::Result<()>) {
        client
            .with(false, |c| {
                Client::select(c, "INBOX")?;
                command(&mut c.session)?;
                Ok(())
            })
            .unwrap();
    }

    #[test]
    #[ignore]
    fn live_blocked_senders() {
        use crate::blocking;
        let user = format!("b{}@example.org", std::process::id());
        let c = client(&user);
        let from = |who: &str, id: &str, subject: &str| {
            format!(
                "From: {who}\r\nTo: me@example.org\r\nSubject: {subject}\r\n\
                 Date: Mon, 23 Nov 2026 10:00:00 +0000\r\nMessage-ID: {id}\r\n\
                 MIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\nHi\r\n"
            )
        };
        // Spark's Blocked folder, with one sender in it already.
        let label = c.create_label("Blocked").unwrap();
        put(
            &c,
            &label.name,
            &from("Old Ads <old@ads.example>", "<b0@x>", "Old"),
            true,
        );
        put(
            &c,
            "INBOX",
            &from("Old Ads <OLD@ads.example>", "<b1@x>", "Left"),
            false,
        );
        put(
            &c,
            "INBOX",
            &from("Ana <ana@example.com>", "<b2@x>", "Lunch"),
            false,
        );
        let store = crate::store::Store::temp();

        // The first look learns the sender and moves what it left in the inbox.
        assert_eq!(blocking::sweep(&c, &store), 1);
        assert_eq!(blocking::load(&store).senders, ["old@ads.example"]);
        let (inbox, _) = c.threads_page(View::Inbox, None, 30, None).unwrap();
        assert_eq!(inbox.len(), 1);
        assert_eq!(inbox[0].subject, "Lunch");
        let (blocked, _) = c
            .threads_page(View::Label(0), Some(&label.id), 30, None)
            .unwrap();
        assert!(blocked.iter().any(|t| t.subject == "Left" && !t.unread));

        // New mail: a blocked sender's is moved and not given back to notify about.
        assert!(blocking::set(&store, "Spam@Ads.example", true).unwrap());
        let (_, start) = c.profile().unwrap();
        put(
            &c,
            "INBOX",
            &from("Spam <spam@ads.example>", "<b3@x>", "Sale"),
            false,
        );
        put(
            &c,
            "INBOX",
            &from("Ana <ana@example.com>", "<b4@x>", "Dinner"),
            false,
        );
        let fresh = c.history(&start).unwrap().new_unread_inbox;
        assert_eq!(fresh.len(), 2);
        let kept = blocking::screen(&c, &store, fresh);
        assert_eq!(kept.len(), 1);
        assert_eq!(c.summary(&kept[0], false).unwrap().subject, "Dinner");
        let (inbox, _) = c.threads_page(View::Inbox, None, 30, None).unwrap();
        assert!(!inbox.iter().any(|t| t.subject == "Sale"));

        // Unblocked: their mail stays in the inbox again.
        assert!(blocking::set(&store, "spam@ads.example", false).unwrap());
        let (_, start) = c.profile().unwrap();
        put(
            &c,
            "INBOX",
            &from("Spam <spam@ads.example>", "<b5@x>", "Again"),
            false,
        );
        let fresh = c.history(&start).unwrap().new_unread_inbox;
        assert_eq!(blocking::screen(&c, &store, fresh).len(), 1);
    }

    #[test]
    #[ignore]
    fn live_changes_elsewhere_by_condstore_and_idle() {
        let user = format!("c{}@example.org", std::process::id());
        let c = client(&user);
        let other = client(&user);
        for (n, subject) in ["Lunch", "Report", "Party"].iter().enumerate() {
            put(
                &other,
                "INBOX",
                &mail(&format!("<c{n}@x>"), subject, "", "Hi"),
                false,
            );
        }
        let (_, start) = c.profile().unwrap();
        let (rows, _) = c.threads_page(View::Inbox, None, 30, None).unwrap();
        assert_eq!(rows.len(), 3);
        let id = |subject: &str| {
            rows.iter()
                .find(|r| r.subject == subject)
                .unwrap()
                .id
                .clone()
        };
        let at = c.history(&start).unwrap().latest;
        {
            let state = c.state.lock().unwrap();
            let inbox = &state.folders["INBOX"];
            assert!(inbox.mod_seq.is_some(), "Dovecot has CONDSTORE");
            assert_eq!(inbox.exists, Some(3));
        }

        // Nothing moved: the feed stays where it is.
        assert_eq!(c.history(&at).unwrap().latest, at);

        // Read elsewhere: found by CHANGEDSINCE.
        let uid_of = |subject: &str| {
            let state = c.state.lock().unwrap();
            let thread = id(subject);
            *state.folders["INBOX"]
                .messages
                .iter()
                .find(|(_, e)| e.thread == thread)
                .unwrap()
                .0
        };
        let lunch = uid_of("Lunch");
        elsewhere(&other, |s| {
            s.uid_store(lunch.to_string(), "+FLAGS.SILENT (\\Seen)")
                .map(drop)
        });
        let changes = c.history(&at).unwrap();
        assert_eq!(changes.threads, vec![id("Lunch")]);
        assert!(!c.summary(&id("Lunch"), false).unwrap().unread);
        let at = changes.latest;

        // Deleted elsewhere: noticed by the count, found by UID SEARCH.
        let report = uid_of("Report");
        elsewhere(&other, |s| {
            s.uid_store(report.to_string(), "+FLAGS.SILENT (\\Deleted)")?;
            s.uid_expunge(report.to_string()).map(drop)
        });
        let changes = c.history(&at).unwrap();
        assert_eq!(changes.threads, vec![id("Report")]);
        let (rows, _) = c.threads_page(View::Inbox, None, 30, None).unwrap();
        assert_eq!(rows.len(), 2);
        let at = changes.latest;

        // New mail elsewhere wakes a wait at once (IDLE), well before it would time out.
        // The first wait starts the IDLE thread; nothing has changed for it to see.
        assert!(!c.wait_for_change(Duration::from_secs(3)));
        let began = Instant::now();
        let sender = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(500));
            put(&other, "INBOX", &mail("<c9@x>", "News", "", "Fresh"), false);
        });
        assert!(c.wait_for_change(Duration::from_secs(30)));
        assert!(
            began.elapsed() < Duration::from_secs(10),
            "{:?}",
            began.elapsed()
        );
        sender.join().unwrap();
        let changes = c.history(&at).unwrap();
        assert_eq!(changes.new_unread_inbox.len(), 1);
        // Looking does not wake it again.
        assert!(!c.wait_for_change(Duration::from_secs(3)));

        // The client gone, the thread ends (and lets go of what it shared).
        let watch = c.watch.clone();
        drop(c);
        let began = Instant::now();
        while Arc::strong_count(&watch) > 1 && began.elapsed() < Duration::from_secs(10) {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert_eq!(Arc::strong_count(&watch), 1, "the IDLE thread stopped");
    }
}
