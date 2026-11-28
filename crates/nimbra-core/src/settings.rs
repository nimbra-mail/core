//! Preferences, kept in a small JSON file next to the mail store (not in it: they are not
//! mail, and they stay when you sign out).

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// The one plain-text signature of earlier versions, one line per line. Read only to
    /// make it each account's first signature (`migrate`), then emptied.
    pub signature: String,
    /// Every account's signatures, in the order they were made. Their HTML is always
    /// `signature::clean`ed before it is kept here.
    pub signatures: Vec<Signature>,
    /// Each account's default signature, by account id: a signature's id, or "" for none.
    /// An account not in here (or whose default was deleted) starts with its first one.
    pub default_signature: std::collections::HashMap<String, String>,
    /// Notify about new mail in the inbox.
    pub notifications: bool,
    /// Open mail in its original formatting (the web view) rather than the reader.
    pub original_view: bool,
    /// Show remote images in the original view.
    pub load_images: bool,
    /// In dark theme, give light emails a dark page in the original view.
    pub dark_emails: bool,
    /// Light, dark, or follow the system.
    pub theme: ThemeChoice,
    /// The Gmail accounts signed in on this Mac (ids and addresses; the sign-ins themselves
    /// are in the keychain).
    pub accounts: Vec<AccountRef>,
    /// The account shown.
    pub active: String,
    /// The account that is yours by default: its profile at the bottom of the sidebar, and
    /// new messages are from it. `None`, or one signed out since: the first account.
    pub default_account: Option<String>,
    /// Sidebar sections folded away ("split", "mailbox", "labels").
    pub collapsed: Vec<String>,
    /// The sidebar's order, by section ("split", "mailbox", "labels:<account>"): mailbox
    /// names or label ids, as dragged (`keyboard::Sidebar::section`).
    pub sidebar_order: std::collections::HashMap<String, Vec<String>>,
    /// Mailboxes hidden from the sidebar, by name (`keyboard::view_name`).
    pub sidebar_hidden: Vec<String>,
    /// The sidebar was left in auto-hide (⌘B).
    pub sidebar_auto_hide: bool,
    /// The sidebar's width, as its right edge was dragged to (docked and floating alike).
    pub sidebar_width: f32,
    /// The mail list's width, as its right edge was dragged to (the Mac app).
    pub list_width: f32,
    /// A conversation shows its latest message first and the older ones under it, newest
    /// to oldest, rather than oldest first and the latest last.
    pub newest_first: bool,
    /// A list row shows the subject and the start of the email on lines of their own,
    /// rather than side by side. On unless it was turned off (settings kept before it too).
    pub subject_own_line: bool,
    /// The last few searches, newest first.
    pub recent_searches: Vec<String>,
    /// When an opened thread counts as read.
    pub mark_read: MarkRead,
    /// How often to check Gmail for new mail, in seconds.
    pub check_every: u32,
    /// How long a sent message can still be taken back, in seconds (0: sent at once).
    pub undo_send: u32,
    /// Replies and forwards include the original message (folded behind •••).
    pub quote_replies: bool,
    /// New-mail notifications play a sound.
    pub notify_sound: bool,
    /// The first screen's hello has played (it plays once, ever).
    #[serde(default)]
    pub welcomed: bool,
    /// The Dock icon shows the inbox's unread count.
    pub dock_badge: bool,
    /// The size of mail text in the reader (the Mac app sizes its list and HTML view by it too).
    pub reader_text: TextSize,
    /// Count launches anonymously (`usage.rs`).
    pub usage_counts: bool,
    /// Look for new versions of Nimbra and get them ready (`update.rs`).
    pub auto_update: bool,
    /// The version of Nimbra that ran last, so the first run of a new one can open its
    /// release notes. Empty until a version that keeps it has run.
    #[serde(default)]
    pub last_version: String,
    /// How large the whole interface is drawn, in percent (`ZOOM_STEPS`); read it through
    /// `zoom`, which keeps it to a step.
    #[serde(default = "full_size")]
    pub interface_zoom: u16,
}

/// The interface sizes on offer, in percent.
pub const ZOOM_STEPS: [u16; 4] = [90, 100, 110, 125];

fn full_size() -> u16 {
    100
}

impl Settings {
    /// The interface's scale (1 is its own size): the step nearest to what was saved, so a
    /// value edited by hand can't draw it at a size it was never laid out for.
    pub fn zoom(&self) -> f32 {
        let step = ZOOM_STEPS
            .into_iter()
            .min_by_key(|step| step.abs_diff(self.interface_zoom))
            .unwrap_or(100);
        f32::from(step) / 100.
    }
}

/// One of an account's signatures.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Signature {
    /// Random, and never reused.
    pub id: String,
    /// The account it belongs to (its id; the first account's is "").
    pub account: String,
    pub name: String,
    pub html: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MarkRead {
    /// As soon as it is opened.
    Open,
    /// After it has been open for two seconds.
    Delay,
    /// Only with Mark as read (or U).
    Never,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TextSize {
    Small,
    Default,
    Large,
    /// Saved as "extralarge".
    ExtraLarge,
}

impl TextSize {
    /// Body text size and line height in the reader, in points.
    pub fn metrics(self) -> (f32, f32) {
        match self {
            TextSize::Small => (13.5, 23.),
            TextSize::Default => (15., 26.),
            TextSize::Large => (17., 29.),
            TextSize::ExtraLarge => (19., 32.),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AccountRef {
    pub id: String,
    pub email: String,
    /// For an account that is not Gmail: its IMAP and SMTP servers (its password is in
    /// the keychain). None for Gmail, which is all an older settings file has.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub servers: Option<crate::servers::Servers>,
    /// For an account with servers that signs in with its provider rather than a password:
    /// "microsoft" (its sign-in is in the keychain). None for a password.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ThemeChoice {
    System,
    Light,
    Dark,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            signature: String::new(),
            signatures: Vec::new(),
            default_signature: Default::default(),
            notifications: true,
            original_view: true,
            load_images: true,
            dark_emails: true,
            theme: ThemeChoice::System,
            accounts: Vec::new(),
            active: String::new(),
            default_account: None,
            collapsed: Vec::new(),
            sidebar_order: Default::default(),
            sidebar_hidden: Vec::new(),
            sidebar_auto_hide: false,
            sidebar_width: 236.,
            list_width: 452.,
            newest_first: false,
            subject_own_line: true,
            recent_searches: Vec::new(),
            mark_read: MarkRead::Open,
            check_every: 30,
            undo_send: 6,
            quote_replies: true,
            notify_sound: true,
            welcomed: false,
            dock_badge: true,
            reader_text: TextSize::Default,
            usage_counts: true,
            auto_update: true,
            last_version: String::new(),
            interface_zoom: full_size(),
        }
    }
}

impl Settings {
    /// Moves an account to another place in the list. The default account stays the
    /// default: without one chosen it is the first, so it is pinned before anything moves.
    /// Returns whether anything moved.
    pub fn move_account(&mut self, id: &str, to: usize) -> bool {
        let Some(from) = self.accounts.iter().position(|a| a.id == id) else {
            return false;
        };
        let to = to.min(self.accounts.len() - 1);
        if from == to {
            return false;
        }
        if self.default_account.is_none() {
            self.default_account = self.default_account().map(str::to_string);
        }
        let account = self.accounts.remove(from);
        self.accounts.insert(to, account);
        true
    }

    /// The default account's id, when any account is signed in. The first account's id is
    /// "", so this is never tested for emptiness.
    pub fn default_account(&self) -> Option<&str> {
        self.default_account
            .as_deref()
            .filter(|id| self.accounts.iter().any(|a| a.id == *id))
            .or_else(|| self.accounts.first().map(|a| a.id.as_str()))
    }

    /// The default account's address.
    pub fn default_email(&self) -> Option<&str> {
        let id = self.default_account()?;
        self.accounts
            .iter()
            .find(|a| a.id == id)
            .map(|a| a.email.as_str())
    }
}

/// The old signature could be a few lines; anything longer is cut.
pub const SIGNATURE_LIMIT: usize = 2000;
/// An account can have this many signatures.
pub const SIGNATURES_PER_ACCOUNT: usize = 20;

impl Settings {
    /// An account's signatures, in order.
    pub fn signatures_of<'a>(&'a self, account: &'a str) -> impl Iterator<Item = &'a Signature> {
        self.signatures.iter().filter(move |s| s.account == account)
    }

    pub fn signature(&self, id: &str) -> Option<&Signature> {
        self.signatures.iter().find(|s| s.id == id)
    }

    /// The signature new messages from `account` start with: the one chosen, or with
    /// none chosen (or the chosen one deleted) its first. `None`: no signature.
    pub fn default_signature<'a>(&'a self, account: &'a str) -> Option<&'a Signature> {
        match self.default_signature.get(account).map(String::as_str) {
            Some("") => None,
            Some(id) => self
                .signature(id)
                .filter(|s| s.account == account)
                .or_else(|| self.signatures_of(account).next()),
            None => self.signatures_of(account).next(),
        }
    }

    /// Makes `id` (or, with `None`, no signature) the account's default.
    pub fn set_default_signature(&mut self, account: &str, id: Option<&str>) {
        self.default_signature
            .insert(account.to_string(), id.unwrap_or("").to_string());
    }

    /// Adds an empty signature to the account and returns its id (`None` once the account
    /// has as many as it may). Its name is "Signature", numbered when that is taken.
    pub fn add_signature(&mut self, account: &str) -> Option<String> {
        if self.signatures_of(account).count() >= SIGNATURES_PER_ACCOUNT {
            return None;
        }
        let taken: Vec<&str> = self
            .signatures_of(account)
            .map(|s| s.name.as_str())
            .collect();
        let name = std::iter::once("Signature".to_string())
            .chain((2..).map(|n| format!("Signature {n}")))
            .find(|name| !taken.contains(&name.as_str()))?;
        let id = self.new_signature_id();
        self.signatures.push(Signature {
            id: id.clone(),
            account: account.to_string(),
            name,
            html: String::new(),
        });
        Some(id)
    }

    /// Deletes a signature. When it was its account's default, the account falls back to
    /// its first one (or none, with none left).
    pub fn delete_signature(&mut self, id: &str) {
        self.signatures.retain(|s| s.id != id);
        self.default_signature.retain(|_, chosen| chosen != id);
    }

    /// Forgets the signatures of an account that was removed.
    pub fn forget_signatures(&mut self, account: &str) {
        self.signatures.retain(|s| s.account != account);
        self.default_signature.remove(account);
    }

    fn new_signature_id(&self) -> String {
        let mut n = self.signatures.len();
        loop {
            let id = crate::mail::random_hex(6).unwrap_or_else(|_| {
                n += 1;
                format!("s{n}")
            });
            if self.signature(&id).is_none() {
                return id;
            }
        }
    }

    /// Settings from before signatures belonged to accounts: the one plain-text signature
    /// becomes each account's first (and default) signature. Done once, when there are
    /// accounts to give it to; the old text is emptied so a signature deleted later stays
    /// deleted.
    pub fn migrate(&mut self) {
        let old = self.signature.trim_end();
        if old.trim().is_empty() || !self.signatures.is_empty() || self.accounts.is_empty() {
            return;
        }
        let html = crate::signature::clean(&crate::rich::text_to_html(old));
        let accounts: Vec<String> = self.accounts.iter().map(|a| a.id.clone()).collect();
        for account in accounts {
            let id = self.new_signature_id();
            self.signatures.push(Signature {
                id: id.clone(),
                account: account.clone(),
                name: "Signature".into(),
                html: html.clone(),
            });
            self.set_default_signature(&account, Some(&id));
        }
        self.signature.clear();
    }
}

fn path() -> Option<PathBuf> {
    if let Some(dir) = crate::paths::data_dir() {
        return Some(dir.join("settings.json"));
    }
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join("Library/Application Support/Nimbra/settings.json"))
}

/// The saved settings, or the defaults.
pub fn load() -> Settings {
    let mut settings: Settings = path()
        .and_then(|path| std::fs::read(path).ok())
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default();
    settings.migrate();
    settings
}

/// Saves the settings on a writer thread and returns at once. Changes that come faster than
/// the disk are written as one, the newest; `flush` waits for it.
pub fn save(settings: &Settings) -> Result<()> {
    writer().put(settings.clone());
    Ok(())
}

/// Waits until the last settings saved are on disk (quitting), for a few seconds at most.
/// Whether they are.
pub fn flush() -> bool {
    writer().flush(Instant::now() + Duration::from_secs(3))
}

fn writer() -> &'static Arc<Latest<Settings>> {
    static WRITER: OnceLock<Arc<Latest<Settings>>> = OnceLock::new();
    WRITER.get_or_init(|| Latest::new(write))
}

fn write(settings: &Settings) -> Result<()> {
    let path = path().context("no home folder")?;
    let mut settings = settings.clone();
    settings.signature = settings.signature.chars().take(SIGNATURE_LIMIT).collect();
    // Cleaned and cut as they were made; a file edited by hand is held to the same.
    for signature in &mut settings.signatures {
        signature.name = crate::signature::clean_name(&signature.name);
        if signature.html.len() > crate::signature::HTML_LIMIT {
            signature.html = crate::signature::clean(&signature.html);
        }
    }
    write_atomically(&path, &serde_json::to_vec_pretty(&settings)?)
}

/// Written next to the file, flushed to the disk and then moved over it, so that neither a
/// crash nor a power cut leaves half a file.
fn write_atomically(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = path.parent().context("no settings folder")?;
    std::fs::create_dir_all(dir)?;
    let partial = path.with_extension("json.partial");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(&partial)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&partial, path)?;
    if let Ok(dir) = std::fs::File::open(dir) {
        let _ = dir.sync_all();
    }
    Ok(())
}

/// Writes the newest of what it is given on a thread of its own, one at a time.
struct Latest<T> {
    state: Mutex<Waiting<T>>,
    changed: Condvar,
    write: fn(&T) -> Result<()>,
}

struct Waiting<T> {
    next: Option<T>,
    /// How many were given, and how many of those are written (or replaced by a newer one
    /// that is).
    given: u64,
    written: u64,
    started: bool,
}

impl<T: Send + 'static> Latest<T> {
    fn new(write: fn(&T) -> Result<()>) -> Arc<Self> {
        Arc::new(Latest {
            state: Mutex::new(Waiting {
                next: None,
                given: 0,
                written: 0,
                started: false,
            }),
            changed: Condvar::new(),
            write,
        })
    }

    fn lock(&self) -> MutexGuard<'_, Waiting<T>> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn put(self: &Arc<Self>, value: T) {
        let mut state = self.lock();
        state.next = Some(value);
        state.given += 1;
        if !state.started {
            let latest = self.clone();
            state.started = std::thread::Builder::new()
                .name("nimbra-settings".into())
                .spawn(move || latest.run())
                .is_ok();
            if !state.started {
                // No thread to write on: written here rather than lost.
                let value = state.next.take();
                let given = state.given;
                drop(state);
                if let Some(value) = value {
                    self.write_one(&value, given);
                }
                return;
            }
        }
        self.changed.notify_all();
    }

    fn run(&self) {
        loop {
            let (value, given) = {
                let mut state = self.lock();
                while state.next.is_none() {
                    state = self
                        .changed
                        .wait(state)
                        .unwrap_or_else(PoisonError::into_inner);
                }
                (state.next.take(), state.given)
            };
            if let Some(value) = value {
                self.write_one(&value, given);
            }
        }
    }

    fn write_one(&self, value: &T, given: u64) {
        if let Err(error) = (self.write)(value) {
            eprintln!("nimbra: could not save settings: {error:#}");
        }
        let mut state = self.lock();
        state.written = state.written.max(given);
        self.changed.notify_all();
    }

    fn flush(&self, deadline: Instant) -> bool {
        let state = self.lock();
        let given = state.given;
        let left = deadline.saturating_duration_since(Instant::now());
        let (state, _) = self
            .changed
            .wait_timeout_while(state, left, |state| state.written < given)
            .unwrap_or_else(PoisonError::into_inner);
        state.written >= given
    }
}

#[cfg(test)]
mod tests {

    fn three() -> Settings {
        let account = |id: &str| AccountRef {
            id: id.into(),
            email: format!("{id}@example.com"),
            servers: None,
            oauth: None,
        };
        Settings {
            accounts: vec![account("a"), account("b"), account("c")],
            ..Settings::default()
        }
    }

    fn order(settings: &Settings) -> Vec<&str> {
        settings.accounts.iter().map(|a| a.id.as_str()).collect()
    }

    #[test]
    fn an_account_moves_to_where_it_is_dropped() {
        let mut settings = three();
        assert!(settings.move_account("a", 2));
        assert_eq!(order(&settings), ["b", "c", "a"]);
        assert!(settings.move_account("a", 0));
        assert_eq!(order(&settings), ["a", "b", "c"]);
        assert!(settings.move_account("c", 1));
        assert_eq!(order(&settings), ["a", "c", "b"]);
    }

    #[test]
    fn moving_the_first_account_keeps_it_the_default() {
        let mut settings = three();
        assert_eq!(settings.default_account(), Some("a"));
        settings.move_account("b", 0);
        assert_eq!(order(&settings), ["b", "a", "c"]);
        assert_eq!(settings.default_account(), Some("a"));
    }

    #[test]
    fn a_move_to_the_same_place_or_of_an_unknown_account_changes_nothing() {
        let mut settings = three();
        assert!(!settings.move_account("b", 1));
        assert!(!settings.move_account("z", 0));
        assert!(!settings.move_account("c", 9));
        assert_eq!(order(&settings), ["a", "b", "c"]);
        assert_eq!(settings.default_account, None);
    }

    use super::*;

    #[test]
    fn the_zoom_is_always_one_of_the_steps() {
        let with = |percent| Settings {
            interface_zoom: percent,
            ..Settings::default()
        };
        assert_eq!(Settings::default().zoom(), 1.);
        assert_eq!(with(125).zoom(), 1.25);
        assert_eq!(with(90).zoom(), 0.9);
        // Saved by hand, or by a later version with other steps: the nearest one.
        assert_eq!(with(300).zoom(), 1.25);
        assert_eq!(with(0).zoom(), 0.9);
        assert_eq!(with(104).zoom(), 1.);
        // A settings file from before the option opens at full size.
        let old: Settings = serde_json::from_str("{}").unwrap();
        assert_eq!(old.zoom(), 1.);
    }

    #[test]
    fn the_reading_choices_for_settings_kept_before_them() {
        // Oldest first, and the subject on its own line.
        let old: Settings = serde_json::from_str(r#"{"list_width":500}"#).unwrap();
        assert!(!old.newest_first);
        assert!(old.subject_own_line);
        let set = Settings {
            newest_first: true,
            subject_own_line: false,
            ..Settings::default()
        };
        let back: Settings = serde_json::from_str(&serde_json::to_string(&set).unwrap()).unwrap();
        assert!(back.newest_first && !back.subject_own_line);
    }

    #[test]
    fn text_sizes_grow_in_order_and_are_saved_by_name() {
        let sizes = [
            TextSize::Small,
            TextSize::Default,
            TextSize::Large,
            TextSize::ExtraLarge,
        ];
        for pair in sizes.windows(2) {
            assert!(pair[0].metrics().0 < pair[1].metrics().0);
            assert!(pair[0].metrics().1 < pair[1].metrics().1);
        }
        assert_eq!(
            serde_json::to_string(&TextSize::ExtraLarge).unwrap(),
            "\"extralarge\""
        );
        let large: TextSize = serde_json::from_str("\"large\"").unwrap();
        assert_eq!(large, TextSize::Large);
    }
    use std::sync::mpsc;

    /// What a test writer saw, and a gate that holds up the first write.
    struct Probe {
        seen: Mutex<Vec<u32>>,
        entered: Mutex<Option<mpsc::Sender<()>>>,
        gate: Mutex<Option<mpsc::Receiver<()>>>,
    }

    fn probe_write(value: &(u32, Arc<Probe>)) -> Result<()> {
        if let Some(entered) = value.1.entered.lock().unwrap().take() {
            entered.send(()).unwrap();
            let gate = value.1.gate.lock().unwrap().take().unwrap();
            gate.recv().ok();
        }
        value.1.seen.lock().unwrap().push(value.0);
        Ok(())
    }

    #[test]
    fn changes_made_while_one_is_written_are_written_as_the_newest_only() {
        let (entered, has_entered) = mpsc::channel();
        let (release, gate) = mpsc::channel();
        let probe = Arc::new(Probe {
            seen: Mutex::new(Vec::new()),
            entered: Mutex::new(Some(entered)),
            gate: Mutex::new(Some(gate)),
        });
        let latest = Latest::new(probe_write);
        latest.put((1, probe.clone()));
        has_entered.recv().unwrap();
        for n in 2..=4 {
            latest.put((n, probe.clone()));
        }
        assert!(
            !latest.flush(Instant::now()),
            "the first is still being written"
        );
        release.send(()).unwrap();
        assert!(latest.flush(Instant::now() + Duration::from_secs(30)));
        assert_eq!(*probe.seen.lock().unwrap(), [1, 4]);
    }

    #[test]
    fn flushing_waits_for_the_last_change() {
        let probe = Arc::new(Probe {
            seen: Mutex::new(Vec::new()),
            entered: Mutex::new(None),
            gate: Mutex::new(None),
        });
        let latest = Latest::new(probe_write);
        for n in 1..=50 {
            latest.put((n, probe.clone()));
            if n % 10 == 0 {
                assert!(latest.flush(Instant::now() + Duration::from_secs(30)));
                assert_eq!(probe.seen.lock().unwrap().last(), Some(&n));
            }
        }
    }

    #[test]
    fn settings_are_moved_into_place_whole_and_private() {
        let dir = std::env::temp_dir().join(format!("nimbra-settings-{}", std::process::id()));
        let path = dir.join("settings.json");
        write_atomically(&path, b"{\"signature\":\"one\"}").unwrap();
        write_atomically(&path, b"{\"signature\":\"two\"}").unwrap();
        let back: Settings = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(back.signature, "two");
        assert!(!path.with_extension("json.partial").exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn missing_fields_take_their_defaults() {
        let settings: Settings = serde_json::from_str(r#"{"signature":"Luan"}"#).unwrap();
        assert_eq!(settings.signature, "Luan");
        assert!(settings.notifications && settings.original_view);
        // The sidebar starts docked until it has been put in auto-hide.
        assert!(!settings.sidebar_auto_hide);
        let hidden: Settings = serde_json::from_str(r#"{"sidebar_auto_hide":true}"#).unwrap();
        assert!(hidden.sidebar_auto_hide);
        // On for settings saved before it existed; turning it off sticks.
        assert!(settings.dark_emails);
        let off: Settings = serde_json::from_str(r#"{"dark_emails":false}"#).unwrap();
        assert!(!off.dark_emails);
        assert_eq!(settings.theme, ThemeChoice::System);
        assert_eq!(settings.default_account, None);
    }

    fn two() -> Settings {
        Settings {
            accounts: vec![
                AccountRef {
                    id: String::new(),
                    email: "a@example.com".into(),
                    servers: None,
                    oauth: None,
                },
                AccountRef {
                    id: "bbbbbbbbbbbb".into(),
                    email: "b@example.com".into(),
                    servers: None,
                    oauth: None,
                },
            ],
            ..Settings::default()
        }
    }

    #[test]
    fn the_default_account_is_the_chosen_one_or_else_the_first() {
        let mut settings = two();
        // Never chosen: the first, whose id is "".
        assert_eq!(settings.default_account(), Some(""));
        assert_eq!(settings.default_email(), Some("a@example.com"));
        settings.default_account = Some("bbbbbbbbbbbb".into());
        assert_eq!(settings.default_account(), Some("bbbbbbbbbbbb"));
        assert_eq!(settings.default_email(), Some("b@example.com"));
        // Chosen and then signed out: the first again.
        settings.accounts.pop();
        assert_eq!(settings.default_account(), Some(""));
        // Choosing the first one is kept as such ("" is an id, not "none").
        settings.default_account = Some(String::new());
        assert_eq!(settings.default_account(), Some(""));
        settings.accounts.clear();
        assert_eq!(settings.default_account(), None);
        // Saved and read back.
        let mut chosen = two();
        chosen.default_account = Some("bbbbbbbbbbbb".into());
        let back: Settings = serde_json::from_slice(&serde_json::to_vec(&chosen).unwrap()).unwrap();
        assert_eq!(back.default_account(), Some("bbbbbbbbbbbb"));
    }

    #[test]
    fn the_old_signature_becomes_each_accounts_first() {
        let mut settings: Settings =
            serde_json::from_str(r#"{"signature":"Luan <UX>\n\nNimbra"}"#).unwrap();
        // Nothing to give it to yet: kept for later.
        settings.migrate();
        assert!(settings.signatures.is_empty());
        assert_eq!(settings.signature, "Luan <UX>\n\nNimbra");
        settings.accounts = two().accounts;
        settings.migrate();
        assert_eq!(settings.signatures.len(), 2);
        assert!(settings.signature.is_empty());
        for (signature, account) in settings.signatures.iter().zip(["", "bbbbbbbbbbbb"]) {
            assert_eq!(signature.account, account);
            assert_eq!(signature.name, "Signature");
            assert_eq!(
                signature.html,
                "<div>Luan &lt;UX&gt;</div><div><br></div><div>Nimbra</div>"
            );
            assert_eq!(
                settings.default_signature(account).map(|s| &s.id),
                Some(&signature.id)
            );
        }
        assert_ne!(settings.signatures[0].id, settings.signatures[1].id);
        // Once only: deleting them all does not bring it back.
        let before = settings.clone();
        settings.migrate();
        assert_eq!(settings, before);
        for id in before.signatures.iter().map(|s| s.id.clone()) {
            settings.delete_signature(&id);
        }
        settings.migrate();
        assert!(settings.signatures.is_empty());
        // Saved and read back.
        let back: Settings = serde_json::from_slice(&serde_json::to_vec(&before).unwrap()).unwrap();
        assert_eq!(back, before);
    }

    #[test]
    fn a_default_signature_is_the_chosen_one_the_first_or_none() {
        let mut settings = two();
        assert!(settings.default_signature("").is_none());
        let first = settings.add_signature("").unwrap();
        let second = settings.add_signature("").unwrap();
        let other = settings.add_signature("bbbbbbbbbbbb").unwrap();
        assert_eq!(settings.signature(&second).unwrap().name, "Signature 2");
        assert_eq!(settings.signature(&other).unwrap().name, "Signature");
        // None chosen: the first.
        assert_eq!(settings.default_signature("").unwrap().id, first);
        settings.set_default_signature("", Some(&second));
        assert_eq!(settings.default_signature("").unwrap().id, second);
        // Another account's signature is never this one's default.
        settings.set_default_signature("", Some(&other));
        assert_eq!(settings.default_signature("").unwrap().id, first);
        // None, on purpose.
        settings.set_default_signature("", None);
        assert!(settings.default_signature("").is_none());
        // The default deleted: the first again.
        settings.set_default_signature("", Some(&second));
        settings.delete_signature(&second);
        assert_eq!(settings.default_signature("").unwrap().id, first);
        assert_eq!(settings.signatures_of("").count(), 1);
        settings.forget_signatures("bbbbbbbbbbbb");
        assert!(settings.default_signature("bbbbbbbbbbbb").is_none());
        while settings.add_signature("").is_some() {}
        assert_eq!(settings.signatures_of("").count(), SIGNATURES_PER_ACCOUNT);
    }

    #[test]
    fn an_account_says_how_it_signs_in_only_when_it_is_not_a_password() {
        let mut settings = two();
        let plain = serde_json::to_string(&settings).unwrap();
        assert!(!plain.contains("oauth"));
        settings.accounts[1].oauth = Some("microsoft".into());
        let back: Settings =
            serde_json::from_slice(&serde_json::to_vec(&settings).unwrap()).unwrap();
        assert_eq!(back.accounts[1].oauth.as_deref(), Some("microsoft"));
        assert_eq!(back.accounts[0].oauth, None);
    }
}
