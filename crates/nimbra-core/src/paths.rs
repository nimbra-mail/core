//! Where the engine keeps its files: the settings, each account's encrypted store, and the
//! cache of signature images.
//!
//! The macOS app uses the folders it always has (`~/Library/Application Support/Nimbra`
//! and `~/Library/Caches/Nimbra`), which each module knows. Any other front end says where
//! its own folders are before it opens anything (`set`): the iOS app passes its sandbox's
//! Application Support and Caches folders. Once set, they stay for the life of the process.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use anyhow::{Result, bail};

struct Dirs {
    data: PathBuf,
    cache: PathBuf,
}

static DIRS: OnceLock<Dirs> = OnceLock::new();

/// Sets the folders for this process: `data` for settings and stores, `cache` for what can
/// be downloaded again. Both must be absolute. Setting the same ones again is fine; other
/// ones are refused, as files are already open in the first.
pub fn set(data: &Path, cache: &Path) -> Result<()> {
    if !data.is_absolute() || !cache.is_absolute() {
        bail!("The engine's folders must be absolute paths.");
    }
    let dirs = DIRS.get_or_init(|| Dirs {
        data: data.to_path_buf(),
        cache: cache.to_path_buf(),
    });
    if dirs.data != data || dirs.cache != cache {
        bail!("The engine's folders were already set to others in this process.");
    }
    Ok(())
}

/// The folder for settings and stores, when a front end set one.
pub fn data_dir() -> Option<&'static Path> {
    DIRS.get().map(|dirs| dirs.data.as_path())
}

/// The folder for caches, when a front end set one.
pub fn cache_dir() -> Option<&'static Path> {
    DIRS.get().map(|dirs| dirs.cache.as_path())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_folders_are_refused() {
        assert!(set(Path::new("relative"), Path::new("/tmp")).is_err());
    }
}
