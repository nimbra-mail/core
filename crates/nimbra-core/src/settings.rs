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
    /// Added under new messages, replies and forwards. Plain text, one line per line.
    pub signature: String,
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
    /// The sidebar was left in auto-hide (⌘B).
    pub sidebar_auto_hide: bool,
    /// The sidebar's width, as its right edge was dragged to (docked and floating alike).
    pub sidebar_width: f32,
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
    /// The Dock icon shows the inbox's unread count.
    pub dock_badge: bool,
    /// The size of text in the reader.
    pub reader_text: TextSize,
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
}

impl TextSize {
    /// Body text size and line height in the reader, in points.
    pub fn metrics(self) -> (f32, f32) {
        match self {
            TextSize::Small => (13.5, 23.),
            TextSize::Default => (15., 26.),
            TextSize::Large => (17., 29.),
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
            notifications: true,
            original_view: true,
            load_images: true,
            dark_emails: true,
            theme: ThemeChoice::System,
            accounts: Vec::new(),
            active: String::new(),
            default_account: None,
            collapsed: Vec::new(),
            sidebar_auto_hide: false,
            sidebar_width: 236.,
            recent_searches: Vec::new(),
            mark_read: MarkRead::Open,
            check_every: 30,
            undo_send: 6,
            quote_replies: true,
            notify_sound: true,
            dock_badge: true,
            reader_text: TextSize::Default,
        }
    }
}

impl Settings {
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

/// The signature can be a few lines; anything longer is cut.
pub const SIGNATURE_LIMIT: usize = 2000;

fn path() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join("Library/Application Support/Nimbra/settings.json"))
}

/// The saved settings, or the defaults.
pub fn load() -> Settings {
    path()
        .and_then(|path| std::fs::read(path).ok())
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
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
    use super::*;
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
