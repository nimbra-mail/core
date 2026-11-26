//! Pictures in signatures (a logo, mostly), so the composer and Settings can show them.
//! This is the cache; drawing them natively is the app's (`signature_images` there).
//!
//! A signature points to its images by web address, and that is what is sent. To show them,
//! Nimbra downloads each one once (through `rich::fetch_image`: https on a public host only,
//! checked at every redirect, with a timeout, the format read from the bytes) and keeps it
//! in `~/Library/Caches/Nimbra/signature-images`. The composer and Settings then show that
//! copy: nothing there loads anything from the internet. An image is fetched again only
//! when it is missing from the cache, at most once a run, or when the user asks.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Result, bail};
use sha2::{Digest, Sha256};

use crate::rich::{ImageKind, sniff};

/// The largest picture kept: a signature's logo is a few kilobytes.
const MAX_BYTES: usize = 1024 * 1024;

/// Addresses already tried this run (whatever came of it), so a broken one is not asked
/// for every time a composer opens.
static TRIED: Mutex<Option<HashSet<String>>> = Mutex::new(None);

/// A kept picture: its format and bytes.
pub type Kept = (ImageKind, Arc<Vec<u8>>);

thread_local! {
    /// Images read from the cache, by address, so they are read from disk once.
    static LOADED: std::cell::RefCell<HashMap<String, Option<Kept>>> = Default::default();
}

fn dir() -> Option<PathBuf> {
    if let Some(dir) = crate::paths::cache_dir() {
        return Some(dir.join("signature-images"));
    }
    let home = std::env::var_os("HOME")?;
    Some(Path::new(&home).join("Library/Caches/Nimbra/signature-images"))
}

/// The cached file for `url`: named by the address's hash, so no part of it reaches the
/// file system.
fn path(url: &str) -> Option<PathBuf> {
    let hash: String = Sha256::digest(url.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    Some(dir()?.join(hash))
}

fn mime(kind: &ImageKind) -> &'static str {
    match kind {
        ImageKind::Png => "image/png",
        ImageKind::Jpeg => "image/jpeg",
        ImageKind::Gif => "image/gif",
        ImageKind::Webp => "image/webp",
    }
}

/// The kept copy of `url`, if there is one (checked again as it is read).
pub fn cached(url: &str) -> Option<Kept> {
    LOADED.with(|loaded| {
        if let Some(found) = loaded.borrow().get(url) {
            return found.clone();
        }
        let found = path(url)
            .and_then(|path| std::fs::read(path).ok())
            .filter(|bytes| bytes.len() <= MAX_BYTES)
            .and_then(|bytes| Some((sniff(&bytes)?, Arc::new(bytes))));
        // A miss is not remembered: the download may still arrive.
        if found.is_some() {
            loaded.borrow_mut().insert(url.to_string(), found.clone());
        }
        found
    })
}

/// The kept copy as a `data:` address, for the composer's web view.
pub fn data_uri(url: &str) -> Option<String> {
    use base64::Engine as _;
    let (kind, bytes) = cached(url)?;
    Some(format!(
        "data:{};base64,{}",
        mime(&kind),
        base64::engine::general_purpose::STANDARD.encode(bytes.as_slice())
    ))
}

/// Downloads `url` and keeps it (blocking: run it in the background).
pub fn fetch(url: &str) -> Result<()> {
    let (_, bytes) = crate::rich::fetch_image(url)?;
    if bytes.len() > MAX_BYTES {
        bail!("image is too large");
    }
    let path = path(url).ok_or_else(|| anyhow::anyhow!("no cache folder"))?;
    let dir = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("no cache folder"))?;
    std::fs::create_dir_all(dir)?;
    // Written whole, then renamed into place: a half-written file is never read.
    let partial = path.with_extension("partial");
    std::fs::write(&partial, &bytes)?;
    std::fs::rename(&partial, &path)?;
    Ok(())
}

/// Of `urls`, those with no kept copy that were not tried yet this run (now marked tried).
pub fn wanted(urls: &[String]) -> Vec<String> {
    let mut tried = TRIED.lock().unwrap_or_else(|e| e.into_inner());
    let tried = tried.get_or_insert_with(HashSet::new);
    urls.iter()
        .filter(|url| cached(url).is_none() && tried.insert((*url).clone()))
        .cloned()
        .collect()
}

/// Forgets the kept copies of `urls`, so the next download (the app's `ensure`) fetches them again (the
/// "Refresh images" button, after a logo changed).
pub fn forget(urls: &[String]) {
    let mut tried = TRIED.lock().unwrap_or_else(|e| e.into_inner());
    let tried = tried.get_or_insert_with(HashSet::new);
    for url in urls {
        tried.remove(url);
        LOADED.with(|loaded| loaded.borrow_mut().remove(url));
        if let Some(path) = path(url) {
            let _ = std::fs::remove_file(path);
        }
    }
}
