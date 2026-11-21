//! The local mail store: what Nimbra has already fetched, kept on disk so the app opens
//! straight into your mail instead of waiting on Gmail.
//!
//! Everything is encrypted (ChaCha20-Poly1305) with a 256-bit key that is generated on
//! first use and kept only in the system keychain, so the files on disk (and in backups)
//! are unreadable on their own. Each record is one file, written atomically (temporary file
//! then rename) with permissions limited to the user. Signing out deletes both the files
//! and the key.

use std::path::PathBuf;

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

pub struct Store {
    dir: PathBuf,
    cipher: ChaCha20Poly1305,
}

impl Store {
    /// Opens the store, creating the key (in the keychain) and the folder on first use.
    /// Blocking: may wait on the keychain. Call from a background thread.
    /// `account` is the account id ("" for the first account, as stored before accounts).
    pub fn open(account: &str) -> Result<Self> {
        let dir = default_dir(account)?;
        Self::open_at(dir, &load_or_create_key(account)?)
    }

    fn open_at(dir: PathBuf, key: &[u8; 32]) -> Result<Self> {
        std::fs::create_dir_all(&dir).context("creating the mail store folder")?;
        restrict(&dir, 0o700);
        Ok(Self {
            dir,
            cipher: ChaCha20Poly1305::new(Key::from_slice(key)),
        })
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

    /// Deletes every stored record (keeps the key, so the store can be reused).
    pub fn clear(&self) {
        if let Ok(entries) = std::fs::read_dir(&self.dir) {
            for entry in entries.flatten() {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }

    fn path(&self, name: &str) -> Result<PathBuf> {
        if name.is_empty()
            || name.len() > 64
            || !name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            bail!("bad record name");
        }
        Ok(self.dir.join(format!("{name}.bin")))
    }
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
    if !crate::gmail::is_account_id(account) {
        bail!("unexpected account id");
    }
    Ok(if account.is_empty() {
        KEYCHAIN_USER.to_string()
    } else {
        format!("{KEYCHAIN_USER}-{account}")
    })
}

fn default_dir(account: &str) -> Result<PathBuf> {
    if !crate::gmail::is_account_id(account) {
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
    if let Ok(saved) = entry.get_password()
        && let Ok(bytes) = STANDARD.decode(saved.trim())
        && let Ok(key) = <[u8; 32]>::try_from(bytes.as_slice())
    {
        return Ok(key);
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
    fn record_names_cannot_escape_the_folder() {
        let store = temp_store(3);
        for bad in ["../x", "a/b", "", "a.b", &"x".repeat(65)] {
            assert!(store.save(bad, &1).is_err(), "{bad:?}");
        }
        std::fs::remove_dir_all(&store.dir).unwrap();
    }
}
