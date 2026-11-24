//! The local mail store: what Nimbra has already fetched, kept on disk so the app opens
//! straight into your mail instead of waiting on Gmail.
//!
//! Everything is encrypted (ChaCha20-Poly1305) with a 256-bit key that is generated on
//! first use and kept only in the system keychain, so the files on disk (and in backups)
//! are unreadable on their own. Each record is one file, written atomically (temporary file
//! then rename) with permissions limited to the user. Signing out deletes both the files
//! and the key.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

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
/// One `update` at a time, so that none writes over what another just did.
static UPDATING: Mutex<()> = Mutex::new(());
/// One file is written at a time: two saves of a record shared their temporary file, and
/// one failed or both were mixed.
static WRITING: Mutex<()> = Mutex::new(());
/// The accounts whose key could not be read when it was last asked for.
static UNREADABLE: Mutex<Option<HashSet<String>>> = Mutex::new(None);

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

pub struct Store {
    dir: PathBuf,
    cipher: ChaCha20Poly1305,
    snapshots: AtomicU64,
    /// The snapshot each record saved with `save_newest` has.
    newest: Mutex<HashMap<String, u64>>,
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
        std::fs::create_dir_all(&dir).context("creating the mail store folder")?;
        restrict(&dir, 0o700);
        Ok(Self {
            dir,
            cipher: ChaCha20Poly1305::new(Key::from_slice(key)),
            snapshots: AtomicU64::new(0),
            newest: Mutex::new(HashMap::new()),
        })
    }

    /// A store in a fresh temporary folder, for tests elsewhere.
    #[cfg(test)]
    pub fn temp() -> Self {
        let mut id = [0u8; 8];
        getrandom::getrandom(&mut id).unwrap();
        let name: String = id.iter().map(|b| format!("{b:02x}")).collect();
        Self::open_at(std::env::temp_dir().join(format!("nimbra-test-{name}")), &[7; 32]).unwrap()
    }

    /// Saves a record under `name`, replacing any previous one.
    pub fn save<T: Serialize>(&self, name: &str, value: &T) -> Result<()> {
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
        let _writing = locked(&WRITING);
        let temp = path.with_extension("tmp");
        std::fs::write(&temp, &file).context("writing the mail store")?;
        restrict(&temp, 0o600);
        std::fs::rename(&temp, &path).context("writing the mail store")?;
        Ok(())
    }

    /// Reads a record. Anything missing, from an older format, or that fails to decrypt
    /// (tampered with, or written with another key) reads as nothing.
    pub fn load<T: DeserializeOwned>(&self, name: &str) -> Option<T> {
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
        self.snapshots.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Saves a copy unless a newer one already is: background saves land in any order.
    pub fn save_newest<T: Serialize>(&self, name: &str, value: &T, taken: u64) -> Result<()> {
        let mut newest = locked(&self.newest);
        if newest.get(name).is_some_and(|saved| *saved > taken) {
            return Ok(());
        }
        self.save(name, value)?;
        newest.insert(name.to_string(), taken);
        Ok(())
    }

    /// Changes a record as it now is on disk. Blocking.
    pub fn update<T: Serialize + DeserializeOwned + Default>(
        &self,
        name: &str,
        change: impl FnOnce(&mut T),
    ) -> Result<T> {
        let _updating = locked(&UPDATING);
        let mut value: T = self.load(name).unwrap_or_default();
        change(&mut value);
        self.save(name, &value)?;
        Ok(value)
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

    /// Deletes every stored record (keeps the key, so the store can be reused).
    pub fn clear(&self) {
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
