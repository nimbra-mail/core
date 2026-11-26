//! The local mail store: what Nimbra has already fetched, kept on disk so the app opens
//! straight into your mail instead of waiting on Gmail.
//!
//! Everything is encrypted (ChaCha20-Poly1305) with a 256-bit key that is generated on
//! first use and kept only in the system keychain, so the files on disk (and in backups)
//! are unreadable on their own. Each record is one file, written atomically (temporary file
//! then rename) with permissions limited to the user. Signing out deletes both the files
//! and the key.
//!
//! The main thread never writes or waits: it hands records to one writer thread
//! (`save_soon`, `update_soon`), which writes them in the order they were handed over, the
//! newest copy of a record only. Reads wait for what was handed over before them, and
//! quitting waits for all of it (`flush`). What the writer has of a record is shared by
//! every `Store` of its account (keyed by its path), as one account often has two at once.

use std::cell::Cell;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, LazyLock, Mutex, MutexGuard, OnceLock, PoisonError, mpsc};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, anyhow, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use serde::Serialize;
use serde::de::DeserializeOwned;

const KEYCHAIN_SERVICE: &str = "nimbra";
const KEYCHAIN_USER: &str = "store-key";
/// Bumped whenever the stored shapes change; older stores are discarded, not misread.
const FORMAT: u8 = 2;
/// The size of a saved empty list: format, nonce, `[]`, and the cipher's tag.
const EMPTY_LIST: u64 = 1 + 12 + 2 + 16;

/// One key is made at a time: a second would replace the one just written with.
static MAKING_KEY: Mutex<()> = Mutex::new(());
/// The accounts whose key could not be read when it was last asked for.
static UNREADABLE: Mutex<Option<HashSet<String>>> = Mutex::new(None);
/// The writer's lane for what changes every record (no record has an empty name).
const EVERY_RECORD: &str = "";
/// How long a read waits for the writer before it reads what is on disk all the same.
const READ_WAIT: Duration = Duration::from_secs(10);

static LANES: LazyLock<Mutex<HashMap<PathBuf, Lane>>> = LazyLock::new(Default::default);
/// Held while a record is written, so that a change reads the copy before it.
static RECORDS: LazyLock<Mutex<HashMap<PathBuf, Arc<Mutex<()>>>>> = LazyLock::new(Default::default);
/// The snapshot each record saved with `save_newest` has.
static NEWEST: LazyLock<Mutex<HashMap<PathBuf, u64>>> = LazyLock::new(Default::default);
static SNAPSHOTS: AtomicU64 = AtomicU64::new(0);

thread_local! {
    static ON_WRITER: Cell<bool> = const { Cell::new(false) };
}

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

type Task = Box<dyn FnOnce() + Send>;

/// One thread that does the stores' writes, in the order they were asked for.
struct Writer {
    queue: Mutex<Option<mpsc::Sender<Task>>>,
    /// Tasks handed over, and tasks done.
    counts: Mutex<(u64, u64)>,
    done: Condvar,
}

impl Writer {
    fn new() -> Arc<Self> {
        Arc::new(Writer {
            queue: Mutex::new(None),
            counts: Mutex::new((0, 0)),
            done: Condvar::new(),
        })
    }

    fn global() -> Arc<Self> {
        static WRITER: OnceLock<Arc<Writer>> = OnceLock::new();
        WRITER.get_or_init(Writer::new).clone()
    }

    #[cfg(test)]
    fn hand_over(self: &Arc<Self>, task: Task) {
        self.hand_over_marked(|_| {}, task);
    }

    /// Hands a task over, after `mark` is told its place in the queue.
    fn hand_over_marked(self: &Arc<Self>, mark: impl FnOnce(u64), task: Task) {
        let mut queue = locked(&self.queue);
        let ticket = {
            let mut counts = locked(&self.counts);
            counts.0 += 1;
            counts.0
        };
        mark(ticket);
        if queue.is_none() {
            let (sender, tasks) = mpsc::channel::<Task>();
            let writer = Arc::downgrade(self);
            let started = std::thread::Builder::new()
                .name("nimbra-store".into())
                .spawn(move || {
                    ON_WRITER.set(true);
                    for task in tasks {
                        // A task that panics must not take the writes after it down too.
                        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(task));
                        if let Some(writer) = writer.upgrade() {
                            locked(&writer.counts).1 += 1;
                            writer.done.notify_all();
                        }
                    }
                });
            if started.is_ok() {
                *queue = Some(sender);
            }
        }
        let task = match queue.as_ref() {
            Some(sender) => match sender.send(task) {
                Ok(()) => return,
                Err(mpsc::SendError(task)) => task,
            },
            None => task,
        };
        drop(queue);
        // No thread to write on: written here rather than lost.
        task();
        locked(&self.counts).1 += 1;
        self.done.notify_all();
    }

    /// Waits until everything handed over so far is written, or `deadline`. Whether it was.
    fn flush(&self, deadline: Instant) -> bool {
        let asked = locked(&self.counts).0;
        self.wait_for(asked, Some(deadline))
    }

    /// Waits until the task with this place in the queue is done, or `deadline`.
    fn wait_for(&self, ticket: u64, deadline: Option<Instant>) -> bool {
        let counts = locked(&self.counts);
        let behind = |counts: &mut (u64, u64)| counts.1 < ticket;
        let counts = match deadline {
            Some(deadline) => {
                let left = deadline.saturating_duration_since(Instant::now());
                self.done
                    .wait_timeout_while(counts, left, behind)
                    .unwrap_or_else(PoisonError::into_inner)
                    .0
            }
            None => self
                .done
                .wait_while(counts, behind)
                .unwrap_or_else(PoisonError::into_inner),
        };
        counts.1 >= ticket
    }
}

/// Quitting: waits until every record handed to the writer is on disk, or `deadline`.
/// Whether everything was.
pub fn flush(deadline: Instant) -> bool {
    Writer::global().flush(deadline)
}

/// `flush` for the writer of one store (tests have writers of their own).
#[cfg(test)]
pub fn flush_store(store: &Store, deadline: Instant) -> bool {
    store.writer.flush(deadline)
}

/// What the writer has of one record.
struct Lane {
    /// Handed over and not written yet.
    waiting: usize,
    /// The newest whole copy handed over, and the newest change or read.
    saved: u64,
    changed: u64,
    /// The writer of the last task handed over, and its place in that writer's queue.
    last: (Arc<Writer>, u64),
}

/// Runs `work` while holding the record at `key`, for every store of the process.
fn holding<R>(key: &Path, work: impl FnOnce() -> R) -> R {
    let record = locked(&RECORDS)
        .entry(key.to_path_buf())
        .or_default()
        .clone();
    let result = {
        let _writing = locked(&record);
        work()
    };
    let mut records = locked(&RECORDS);
    drop(record);
    if records
        .get(key)
        .is_some_and(|record| Arc::strong_count(record) == 1)
    {
        records.remove(key);
    }
    result
}

pub struct Store {
    dir: PathBuf,
    cipher: ChaCha20Poly1305,
    writer: Arc<Writer>,
}

impl Store {
    /// Opens the store, creating the key (in the keychain) and the folder on first use.
    /// Blocking: may wait on the keychain. Call from a background thread.
    /// `account` is the account id ("" for the first account, as stored before accounts).
    pub fn open(account: &str) -> Result<Self> {
        let dir = default_dir(account)?;
        let key = load_or_create_key(account);
        let mut unreadable = locked(&UNREADABLE);
        let unreadable = unreadable.get_or_insert_default();
        match &key {
            Ok(_) => unreadable.remove(account),
            Err(_) => unreadable.insert(account.to_string()),
        };
        Self::open_at(dir, &key?)
    }

    /// The same for work nobody is waiting on. It does not ask the keychain again once that
    /// has said no, as macOS would put up its question every time.
    pub fn open_quietly(account: &str) -> Result<Self> {
        if Self::unreadable(account) {
            bail!("the key of this account's store could not be read");
        }
        Self::open(account)
    }

    /// Whether the account's key could not be read when it was last asked for, so that
    /// nothing of it can be kept.
    pub fn unreadable(account: &str) -> bool {
        locked(&UNREADABLE)
            .as_ref()
            .is_some_and(|all| all.contains(account))
    }

    fn open_at(dir: PathBuf, key: &[u8; 32]) -> Result<Self> {
        Self::open_with(dir, key, Writer::global())
    }

    fn open_with(dir: PathBuf, key: &[u8; 32], writer: Arc<Writer>) -> Result<Self> {
        std::fs::create_dir_all(&dir).context("creating the mail store folder")?;
        restrict(&dir, 0o700);
        remove_stale_writes(&dir);
        Ok(Self {
            dir,
            cipher: ChaCha20Poly1305::new(Key::from_slice(key)),
            writer,
        })
    }

    /// A store in a fresh temporary folder, for tests elsewhere.
    #[cfg(test)]
    pub fn temp() -> Self {
        let mut id = [0u8; 8];
        getrandom::getrandom(&mut id).unwrap();
        let name: String = id.iter().map(|b| format!("{b:02x}")).collect();
        Self::open_at(
            std::env::temp_dir().join(format!("nimbra-test-{name}")),
            &[7; 32],
        )
        .unwrap()
    }

    /// A store in a fresh temporary folder with a writer of its own, which waits to start
    /// until the sender is used or dropped.
    #[cfg(test)]
    pub fn temp_held() -> (Arc<Self>, mpsc::Sender<()>) {
        let dir = std::env::temp_dir().join(format!("nimbra-test-{}", random_suffix().unwrap()));
        let store = Arc::new(Store::open_with(dir, &[9; 32], Writer::new()).unwrap());
        let (release, held) = mpsc::channel::<()>();
        store.writer.hand_over(Box::new(move || {
            held.recv().ok();
        }));
        (store, release)
    }

    /// Another store over the same folder and key, with nothing handed to its writer: what
    /// a later launch would read.
    #[cfg(test)]
    pub fn temp_like(other: &Store) -> Self {
        Store::open_with(other.dir.clone(), &[9; 32], Writer::new()).unwrap()
    }

    /// Saves a record under `name`, replacing any previous one, after what was handed to
    /// the writer for it. Blocking.
    pub fn save<T: Serialize>(&self, name: &str, value: &T) -> Result<()> {
        self.wait_for_writer(name, None);
        holding(&self.key(name), || self.write(name, value))
    }

    fn write<T: Serialize>(&self, name: &str, value: &T) -> Result<()> {
        let path = self.path(name)?;
        let plain = serde_json::to_vec(value)?;
        let mut nonce = [0u8; 12];
        getrandom::getrandom(&mut nonce).map_err(|e| anyhow!("no secure random source: {e}"))?;
        // The record name is bound in as associated data, so one record cannot be swapped
        // in for another.
        let sealed = self
            .cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                chacha20poly1305::aead::Payload {
                    msg: &plain,
                    aad: name.as_bytes(),
                },
            )
            .map_err(|_| anyhow!("encrypting the mail store failed"))?;
        let mut file = Vec::with_capacity(1 + nonce.len() + sealed.len());
        file.push(FORMAT);
        file.extend_from_slice(&nonce);
        file.extend_from_slice(&sealed);
        // A temporary file of its own: two writes of a record never share one.
        let temp = path.with_extension(format!("{}.tmp", random_suffix()?));
        let written = std::fs::write(&temp, &file)
            .and_then(|()| {
                restrict(&temp, 0o600);
                std::fs::rename(&temp, &path)
            })
            .context("writing the mail store");
        if written.is_err() {
            let _ = std::fs::remove_file(&temp);
        }
        written
    }

    /// Reads a record, after what was handed to the writer for it. Anything missing, from an
    /// older format, or that fails to decrypt (tampered with, or written with another key)
    /// reads as nothing. Blocking.
    pub fn load<T: DeserializeOwned>(&self, name: &str) -> Option<T> {
        if !self.wait_for_writer(name, Some(READ_WAIT)) {
            eprintln!("nimbra: read “{name}” before the writer got to it");
        }
        self.read(name)
    }

    fn read<T: DeserializeOwned>(&self, name: &str) -> Option<T> {
        let file = std::fs::read(self.path(name).ok()?).ok()?;
        if file.len() < 13 || file[0] != FORMAT {
            return None;
        }
        let plain = self
            .cipher
            .decrypt(
                Nonce::from_slice(&file[1..13]),
                chacha20poly1305::aead::Payload {
                    msg: &file[13..],
                    aad: name.as_bytes(),
                },
            )
            .ok()?;
        serde_json::from_slice(&plain).ok()
    }

    /// Numbers a copy that is about to be saved in the background, for `save_newest`.
    pub fn snapshot(&self) -> u64 {
        SNAPSHOTS.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Saves a copy unless a newer one already is: background saves land in any order.
    pub fn save_newest<T: Serialize>(&self, name: &str, value: &T, taken: u64) -> Result<()> {
        self.wait_for_writer(name, None);
        let key = self.key(name);
        holding(&key, || {
            if locked(&NEWEST)
                .get(&key)
                .is_some_and(|saved| *saved > taken)
            {
                return Ok(());
            }
            self.write(name, value)?;
            locked(&NEWEST).insert(key.clone(), taken);
            Ok(())
        })
    }

    /// Changes a record as it now is on disk. Blocking.
    pub fn update<T: Serialize + DeserializeOwned + Default>(
        &self,
        name: &str,
        change: impl FnOnce(&mut T),
    ) -> Result<T> {
        self.wait_for_writer(name, None);
        holding(&self.key(name), || {
            let mut value: T = self.read(name).unwrap_or_default();
            change(&mut value);
            self.write(name, &value)?;
            Ok(value)
        })
    }

    /// Hands a copy of a record to the writer and returns at once. A newer copy handed over
    /// before this one is written replaces it.
    pub fn save_soon<T: Serialize + Send + 'static>(self: &Arc<Self>, name: &str, value: T) {
        let taken = self.snapshot();
        self.hand_over(
            name,
            |lane| lane.saved = taken,
            move |store, name| {
                let replaced = store
                    .lane(name, |lane| lane.saved > taken && lane.changed < taken)
                    .unwrap_or(false);
                if !replaced && let Err(error) = store.write(name, &value) {
                    eprintln!("nimbra: could not save “{name}”: {error:#}");
                }
            },
        );
    }

    /// Hands a change of a record to the writer, which makes it to the record as it is by
    /// then. The answer says what `change` returned, once it is on disk.
    pub fn update_soon<T, R>(
        self: &Arc<Self>,
        name: &str,
        change: impl FnOnce(&mut T) -> R + Send + 'static,
    ) -> futures::channel::oneshot::Receiver<Result<R>>
    where
        T: Serialize + DeserializeOwned + Default,
        R: Send + 'static,
    {
        let (answer, answered) = futures::channel::oneshot::channel();
        let taken = self.snapshot();
        self.hand_over(
            name,
            |lane| lane.changed = taken,
            move |store, name| {
                let mut value: T = store.read(name).unwrap_or_default();
                let said = change(&mut value);
                let written = store.write(name, &value).map(|()| said);
                if let Err(error) = &written {
                    eprintln!("nimbra: could not save “{name}”: {error:#}");
                }
                answer.send(written).ok();
            },
        );
        answered
    }

    /// Reads a record on the writer, after everything handed to it before, whichever store
    /// of the account it was handed to.
    pub fn read_soon<T: DeserializeOwned + Send + 'static>(
        self: &Arc<Self>,
        name: &str,
    ) -> futures::channel::oneshot::Receiver<Option<T>> {
        let (answer, answered) = futures::channel::oneshot::channel();
        let taken = self.snapshot();
        // Marked as a change, so that a copy handed over before it is written, not replaced.
        self.hand_over(
            name,
            |lane| lane.changed = taken,
            move |store, name| {
                answer.send(store.read(name)).ok();
            },
        );
        answered
    }

    /// Deletes every stored record (keeps the key, so the store can be reused), after what
    /// was handed to the writer before.
    pub fn clear_soon(self: &Arc<Self>) {
        self.hand_over(EVERY_RECORD, |_| {}, |store, _| store.clear());
    }

    fn hand_over(
        self: &Arc<Self>,
        name: &str,
        mark: impl FnOnce(&mut Lane),
        work: impl FnOnce(&Store, &str) + Send + 'static,
    ) {
        let key = self.key(name);
        let writer = self.writer.clone();
        let (store, name, landing) = (self.clone(), name.to_string(), key.clone());
        self.writer.hand_over_marked(
            move |ticket| {
                let mut lanes = locked(&LANES);
                let lane = lanes.entry(key).or_insert_with(|| Lane {
                    waiting: 0,
                    saved: 0,
                    changed: 0,
                    last: (writer.clone(), ticket),
                });
                lane.waiting += 1;
                lane.last = (writer, ticket);
                mark(lane);
            },
            Box::new(move || {
                // Counted as written however the work ends, or the lane would stay forever.
                struct Landed<'a>(&'a Path);
                impl Drop for Landed<'_> {
                    fn drop(&mut self) {
                        let mut lanes = locked(&LANES);
                        if let Some(lane) = lanes.get_mut(self.0) {
                            lane.waiting -= 1;
                            if lane.waiting == 0 {
                                lanes.remove(self.0);
                            }
                        }
                    }
                }
                let _landed = Landed(&landing);
                holding(&landing, || work(&store, &name));
            }),
        );
    }

    /// Where the writer keeps what it has of a record, for every store of the process.
    fn key(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    fn lane<R>(&self, name: &str, look: impl FnOnce(&Lane) -> R) -> Option<R> {
        locked(&LANES).get(&self.key(name)).map(look)
    }

    /// Waits until what was handed to a writer for `name`, by any store of the account, is
    /// written, or `patience` runs out. Whether it was.
    fn wait_for_writer(&self, name: &str, patience: Option<Duration>) -> bool {
        // On the writer, everything handed over before is written already.
        if ON_WRITER.get() {
            return true;
        }
        let waits: Vec<(Arc<Writer>, u64)> = {
            let lanes = locked(&LANES);
            [self.key(name), self.key(EVERY_RECORD)]
                .iter()
                .filter_map(|key| lanes.get(key).map(|lane| lane.last.clone()))
                .collect()
        };
        let deadline = patience.map(|patience| Instant::now() + patience);
        waits
            .iter()
            .all(|(writer, ticket)| writer.wait_for(*ticket, deadline))
    }

    /// The records whose name starts with `prefix`.
    pub fn names(&self, prefix: &str) -> Vec<String> {
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return Vec::new();
        };
        entries
            .flatten()
            .filter_map(|entry| {
                let file = entry.file_name();
                let name = file.to_str()?.strip_suffix(".bin")?;
                name.starts_with(prefix).then(|| name.to_string())
            })
            .collect()
    }

    /// Claims a record for this process for as long as the file returned is open. `None`
    /// while someone has it.
    pub fn claim(&self, name: &str) -> Option<std::fs::File> {
        let path = self.path(name).ok()?.with_extension("lock");
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(false);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let file = options.open(path).ok()?;
        file.try_lock().ok()?;
        Some(file)
    }

    /// Deletes a record and its claim.
    pub fn remove(&self, name: &str) {
        if let Ok(path) = self.path(name) {
            let _ = std::fs::remove_file(&path);
            let _ = std::fs::remove_file(path.with_extension("lock"));
        }
    }

    /// Whether the list saved under `name` is empty, as far as can be told without the key
    /// (which waits on the keychain): from its size. Good for choosing what to draw until
    /// the store is open and `load` has the real answer, and for nothing else.
    pub fn saved_empty(account: &str, name: &str) -> bool {
        default_dir(account).is_ok_and(|dir| empty_list_at(&dir, name))
    }

    fn clear(&self) {
        if let Ok(entries) = std::fs::read_dir(&self.dir) {
            for entry in entries.flatten() {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }

    fn path(&self, name: &str) -> Result<PathBuf> {
        record_path(&self.dir, name)
    }
}

/// What a write that never finished (the app was killed) left behind. Not a write of
/// another copy of Nimbra that is under way: those are seconds old at most.
fn remove_stale_writes(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let stale = |entry: &std::fs::DirEntry| {
        entry
            .metadata()
            .and_then(|meta| meta.modified())
            .is_ok_and(|at| {
                at.elapsed()
                    .is_ok_and(|age| age > Duration::from_secs(3600))
            })
    };
    for entry in entries.flatten() {
        if entry
            .file_name()
            .to_str()
            .is_some_and(|n| n.ends_with(".tmp"))
            && stale(&entry)
        {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

fn random_suffix() -> Result<String> {
    let mut id = [0u8; 6];
    getrandom::getrandom(&mut id).map_err(|e| anyhow!("no secure random source: {e}"))?;
    Ok(id.iter().map(|b| format!("{b:02x}")).collect())
}

fn record_path(dir: &Path, name: &str) -> Result<PathBuf> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        bail!("bad record name");
    }
    Ok(dir.join(format!("{name}.bin")))
}

fn empty_list_at(dir: &Path, name: &str) -> bool {
    let Ok(path) = record_path(dir, name) else {
        return false;
    };
    // The size first: a full mailbox is megabytes, and this runs before the first frame.
    std::fs::metadata(&path).is_ok_and(|file| file.is_file() && file.len() == EMPTY_LIST)
        && std::fs::read(&path).is_ok_and(|file| file.first() == Some(&FORMAT))
}

/// Signing out: removes the stored mail and the key that protects it.
pub fn wipe(account: &str) {
    if let Ok(dir) = default_dir(account) {
        let _ = std::fs::remove_dir_all(dir);
    }
    if let Ok(user) = key_user(account)
        && let Ok(entry) = keyring::Entry::new(KEYCHAIN_SERVICE, &user)
    {
        let _ = entry.delete_credential();
    }
}

/// The keychain entry of an account's store key.
fn key_user(account: &str) -> Result<String> {
    if !crate::mail::is_account_id(account) {
        bail!("unexpected account id");
    }
    Ok(if account.is_empty() {
        KEYCHAIN_USER.to_string()
    } else {
        format!("{KEYCHAIN_USER}-{account}")
    })
}

fn default_dir(account: &str) -> Result<PathBuf> {
    if !crate::mail::is_account_id(account) {
        bail!("unexpected account id");
    }
    let folder = if account.is_empty() {
        "store".to_string()
    } else {
        format!("store-{account}")
    };
    Ok(base_dir()?.join(folder))
}

fn base_dir() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").ok_or_else(|| anyhow!("no home folder"))?;
    let base = if cfg!(target_os = "macos") {
        PathBuf::from(home).join("Library/Application Support/Nimbra")
    } else {
        PathBuf::from(home).join(".local/share/nimbra")
    };
    Ok(base)
}

fn load_or_create_key(account: &str) -> Result<[u8; 32]> {
    let entry = keyring::Entry::new(KEYCHAIN_SERVICE, &key_user(account)?)
        .context("opening the system keychain")?;
    if let Some(key) = key_in(entry.get_password())? {
        return Ok(key);
    }
    let _making = locked(&MAKING_KEY);
    if let Some(key) = key_in(entry.get_password())? {
        return Ok(key); // made meanwhile
    }
    let mut key = [0u8; 32];
    getrandom::getrandom(&mut key).map_err(|e| anyhow!("no secure random source: {e}"))?;
    entry
        .set_password(&STANDARD.encode(key))
        .context("saving the mail store key to the keychain")?;
    // A new key cannot read anything written with the old one.
    if let Ok(dir) = default_dir(account) {
        let _ = std::fs::remove_dir_all(dir);
    }
    Ok(key)
}

/// The key in a keychain's answer. `None` only when there certainly is none: a read that
/// failed (denied, locked) is an error, as making a key then would delete what the real one
/// protects.
fn key_in(read: keyring::Result<String>) -> Result<Option<[u8; 32]>> {
    match read {
        Ok(saved) => Ok(STANDARD
            .decode(saved.trim())
            .ok()
            .and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok())),
        Err(keyring::Error::NoEntry | keyring::Error::BadEncoding(_)) => Ok(None),
        Err(error) => Err(error).context("reading the mail store key from the keychain"),
    }
}

#[cfg(unix)]
fn restrict(path: &std::path::Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
}

#[cfg(not(unix))]
fn restrict(_path: &std::path::Path, _mode: u32) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store(key: u8) -> Store {
        let mut dir = std::env::temp_dir();
        let mut id = [0u8; 8];
        getrandom::getrandom(&mut id).unwrap();
        dir.push(format!(
            "nimbra-store-test-{}",
            STANDARD.encode(id).replace(['/', '+', '='], "")
        ));
        Store::open_at(dir, &[key; 32]).unwrap()
    }

    fn held_store() -> (Arc<Store>, mpsc::Sender<()>) {
        Store::temp_held()
    }

    /// Counts how often it is written out.
    #[derive(Clone)]
    struct Counted(u32, Arc<AtomicU64>);

    impl Serialize for Counted {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            self.1.fetch_add(1, Ordering::SeqCst);
            self.0.serialize(serializer)
        }
    }

    #[test]
    fn only_the_newest_copy_handed_over_is_written() {
        let (store, release) = held_store();
        let writes = Arc::new(AtomicU64::new(0));
        for n in 1..=5 {
            store.save_soon("outbox", Counted(n, writes.clone()));
        }
        release.send(()).unwrap();
        assert_eq!(store.load::<u32>("outbox"), Some(5));
        assert_eq!(writes.load(Ordering::SeqCst), 1);
        std::fs::remove_dir_all(&store.dir).unwrap();
    }

    #[test]
    fn a_change_handed_over_after_a_copy_is_made_to_that_copy() {
        let (store, release) = held_store();
        store.save_soon("snoozed", vec![1]);
        let changed = store.update_soon("snoozed", |list: &mut Vec<u32>| {
            list.push(2);
            list.len()
        });
        store.save_soon("other", vec![7]);
        release.send(()).unwrap();
        assert_eq!(futures::executor::block_on(changed).unwrap().unwrap(), 2);
        assert_eq!(store.load::<Vec<u32>>("snoozed").unwrap(), [1, 2]);
        assert!(flush_store(
            &store,
            Instant::now() + Duration::from_secs(30)
        ));
        std::fs::remove_dir_all(&store.dir).unwrap();
    }

    /// Two stores over one folder, sharing a writer: one account's store that a background
    /// check holds, and the one opened when that account is switched to.
    fn two_stores_of_one_account() -> (Arc<Store>, Arc<Store>) {
        let writer = Writer::new();
        let dir = std::env::temp_dir().join(format!("nimbra-test-{}", random_suffix().unwrap()));
        let open = || Arc::new(Store::open_with(dir.clone(), &[9; 32], writer.clone()).unwrap());
        (open(), open())
    }

    #[test]
    fn a_change_on_one_store_of_an_account_waits_for_one_queued_on_another() {
        let (shown, away) = two_stores_of_one_account();
        shown.save("snoozed", &vec![1u32]).unwrap();
        let (entered, has_entered) = mpsc::channel();
        let (go, gate) = mpsc::channel::<()>();
        let added = shown.update_soon("snoozed", move |list: &mut Vec<u32>| {
            entered.send(()).unwrap();
            gate.recv().ok();
            list.push(2);
        });
        has_entered.recv().unwrap();
        let (removed, has_removed) = mpsc::channel();
        let woken = std::thread::spawn({
            let away = away.clone();
            move || {
                let done = away.update("snoozed", |list: &mut Vec<u32>| list.retain(|n| *n != 1));
                removed.send(()).ok();
                done
            }
        });
        // Time for a change that does not wait to land first.
        has_removed.recv_timeout(Duration::from_millis(200)).ok();
        go.send(()).unwrap();
        futures::executor::block_on(added).unwrap().unwrap();
        assert_eq!(woken.join().unwrap().unwrap(), [2]);
        assert_eq!(
            Store::temp_like(&shown)
                .load::<Vec<u32>>("snoozed")
                .unwrap(),
            [2]
        );
        std::fs::remove_dir_all(&shown.dir).unwrap();
    }

    #[test]
    fn a_store_opened_again_reads_after_what_the_earlier_one_queued() {
        let (old, release) = held_store();
        drop(old.update_soon("snoozed", |list: &mut Vec<u32>| list.push(5)));
        let fresh = Store::open_with(old.dir.clone(), &[9; 32], old.writer.clone()).unwrap();
        let (read, has_read) = mpsc::channel();
        std::thread::spawn(move || read.send(fresh.load::<Vec<u32>>("snoozed")).unwrap());
        let early = has_read.recv_timeout(Duration::from_millis(200)).ok();
        release.send(()).unwrap();
        let read = early.unwrap_or_else(|| has_read.recv().unwrap());
        assert_eq!(read, Some(vec![5]));
        std::fs::remove_dir_all(&old.dir).unwrap();
    }

    #[test]
    fn a_read_between_two_saves_sees_the_first() {
        let (store, release) = held_store();
        store.save_soon("outbox", vec![1u32]);
        let read = store.read_soon::<Vec<u32>>("outbox");
        store.save_soon("outbox", vec![2u32]);
        release.send(()).unwrap();
        assert_eq!(futures::executor::block_on(read).unwrap(), Some(vec![1]));
        assert_eq!(store.load::<Vec<u32>>("outbox"), Some(vec![2]));
        std::fs::remove_dir_all(&store.dir).unwrap();
    }

    #[test]
    fn a_read_or_a_blocking_change_waits_for_what_was_handed_over() {
        let (store, release) = held_store();
        store.save_soon("outbox", vec![1]);
        let reader = {
            let store = store.clone();
            std::thread::spawn(move || store.update("outbox", |list: &mut Vec<u32>| list.push(2)))
        };
        release.send(()).unwrap();
        assert_eq!(reader.join().unwrap().unwrap(), [1, 2]);
        std::fs::remove_dir_all(&store.dir).unwrap();
    }

    #[test]
    fn flushing_waits_until_everything_handed_over_is_on_disk() {
        let (store, release) = held_store();
        store.save_soon("outbox", vec![3]);
        assert!(
            !store.writer.flush(Instant::now()),
            "held up: not written yet"
        );
        release.send(()).unwrap();
        assert!(store.writer.flush(Instant::now() + Duration::from_secs(30)));
        // On disk: another store over the same folder, with nothing handed over, reads it.
        let other = Store::open_with(store.dir.clone(), &[9; 32], Writer::new()).unwrap();
        assert_eq!(other.load::<Vec<u32>>("outbox").unwrap(), [3]);
        std::fs::remove_dir_all(&store.dir).unwrap();
    }

    #[test]
    fn clearing_comes_after_what_was_handed_over_before_it_and_before_what_after() {
        let (store, release) = held_store();
        store.save_soon("view-0", vec![1]);
        store.clear_soon();
        store.save_soon("view-1", vec![2]);
        release.send(()).unwrap();
        assert_eq!(store.load::<Vec<u32>>("view-0"), None);
        assert_eq!(store.load::<Vec<u32>>("view-1").unwrap(), [2]);
        std::fs::remove_dir_all(&store.dir).unwrap();
    }

    #[test]
    fn a_write_that_panics_does_not_stop_the_writer() {
        let (store, release) = held_store();
        store.writer.hand_over(Box::new(|| panic!("a bad record")));
        store.save_soon("meta", 4);
        release.send(()).unwrap();
        assert_eq!(store.load::<u32>("meta"), Some(4));
        std::fs::remove_dir_all(&store.dir).unwrap();
    }

    #[test]
    fn a_claimed_record_cannot_be_claimed_again_until_let_go() {
        let store = temp_store(5);
        store.save("sending-1", &1).unwrap();
        store.save("view-0", &2).unwrap();
        assert_eq!(store.names("sending-"), ["sending-1"]);
        let claim = store.claim("sending-1").unwrap();
        assert!(store.claim("sending-1").is_none());
        drop(claim);
        assert!(store.claim("sending-1").is_some());
        store.remove("sending-1");
        assert!(store.names("sending-").is_empty());
        std::fs::remove_dir_all(&store.dir).unwrap();
    }

    #[test]
    fn a_key_is_only_made_when_there_is_none() {
        use keyring::Error;
        let failed = || Box::new(std::io::Error::other("denied"));
        assert!(key_in(Err(Error::PlatformFailure(failed()))).is_err());
        assert!(key_in(Err(Error::NoStorageAccess(failed()))).is_err());
        assert_eq!(key_in(Err(Error::NoEntry)).unwrap(), None);
        assert_eq!(key_in(Ok("not a key".into())).unwrap(), None);
        let saved = STANDARD.encode([4; 32]);
        assert_eq!(key_in(Ok(saved)).unwrap(), Some([4; 32]));
    }

    #[test]
    fn updates_at_the_same_time_all_land() {
        let store = temp_store(6);
        std::thread::scope(|scope| {
            for n in 0..8 {
                let store = &store;
                scope.spawn(move || store.update::<Vec<u32>>("list", |list| list.push(n)));
            }
        });
        assert_eq!(store.load::<Vec<u32>>("list").unwrap().len(), 8);
        std::fs::remove_dir_all(&store.dir).unwrap();
    }

    #[test]
    fn saves_at_the_same_time_all_work_and_the_newest_stays() {
        let store = temp_store(8);
        let (older, newer) = (store.snapshot(), store.snapshot());
        store.save_newest("view-0", &"newer", newer).unwrap();
        store.save_newest("view-0", &"older", older).unwrap();
        assert_eq!(store.load::<String>("view-0").as_deref(), Some("newer"));
        std::thread::scope(|scope| {
            for n in 0..16 {
                let store = &store;
                scope.spawn(move || store.save("meta", &vec![n; 20_000]).unwrap());
            }
        });
        assert_eq!(store.load::<Vec<u32>>("meta").unwrap().len(), 20_000);
        std::fs::remove_dir_all(&store.dir).unwrap();
    }

    #[test]
    fn round_trip_and_files_are_not_plaintext() {
        let store = temp_store(7);
        store
            .save("view-0", &vec!["Quarterly report", "secret words"])
            .unwrap();
        let back: Vec<String> = store.load("view-0").unwrap();
        assert_eq!(back, ["Quarterly report", "secret words"]);
        let raw = std::fs::read(store.dir.join("view-0.bin")).unwrap();
        assert!(!String::from_utf8_lossy(&raw).contains("secret words"));
        std::fs::remove_dir_all(&store.dir).unwrap();
    }

    #[test]
    fn wrong_key_tampering_and_swapped_records_read_as_nothing() {
        let store = temp_store(1);
        store.save("a", &"hello").unwrap();
        store.save("b", &"other").unwrap();
        let other_key = Store::open_at(store.dir.clone(), &[2; 32]).unwrap();
        assert_eq!(other_key.load::<String>("a"), None);
        // Flip one byte of the ciphertext.
        let path = store.dir.join("a.bin");
        let mut raw = std::fs::read(&path).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 1;
        std::fs::write(&path, &raw).unwrap();
        assert_eq!(store.load::<String>("a"), None);
        // A record copied under another name does not decrypt.
        std::fs::copy(store.dir.join("b.bin"), store.dir.join("c.bin")).unwrap();
        assert_eq!(store.load::<String>("c"), None);
        assert_eq!(store.load::<String>("b").as_deref(), Some("other"));
        std::fs::remove_dir_all(&store.dir).unwrap();
    }

    #[test]
    fn an_empty_list_is_known_without_the_key() {
        let store = temp_store(5);
        let empty = || empty_list_at(&store.dir, "view-0");
        assert!(!empty(), "never saved");
        store.save("view-0", &Vec::<String>::new()).unwrap();
        assert!(empty());
        // The shortest list that has anything in it.
        store.save("view-0", &vec![0]).unwrap();
        assert!(!empty());
        store.save("view-0", &Vec::<String>::new()).unwrap();
        let path = store.dir.join("view-0.bin");
        let mut raw = std::fs::read(&path).unwrap();
        raw[0] = FORMAT + 1;
        std::fs::write(&path, &raw).unwrap();
        assert!(!empty(), "another format");
        assert!(!empty_list_at(&store.dir, "../view-0"));
        std::fs::remove_dir_all(&store.dir).unwrap();
    }

    #[test]
    fn record_names_cannot_escape_the_folder() {
        let store = temp_store(3);
        for bad in ["../x", "a/b", "", "a.b", &"x".repeat(65)] {
            assert!(store.save(bad, &1).is_err(), "{bad:?}");
        }
        std::fs::remove_dir_all(&store.dir).unwrap();
    }
}
