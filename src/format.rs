//! On-disk store format (version 2) and the durable, crash-safe persistence helpers.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

use crate::config::{KdfRepr, LockMode};
use crate::crypto::{rand_u64, SALT_LEN};
use crate::error::{Error, Result};

/// Magic string at the head of every store file, used to reject foreign files.
pub(crate) const MAGIC: &str = "microkv";

/// Current on-disk format version.
pub(crate) const FORMAT_VERSION: u8 = 3;

/// Plaintext sealed under the derived key (with the header as associated data) to form a
/// password verifier and authenticate the header.
pub(crate) const VERIFIER_PLAINTEXT: &[u8] = b"microkv/verify/v3";

/// A single stored entry: a per-value nonce and AEAD ciphertext bound to its
/// `(namespace, key)`. The plaintext payload carries the value plus any expiry, so the
/// expiry is encrypted and authenticated rather than sitting in the clear.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Entry {
    pub(crate) nonce: [u8; 12],
    pub(crate) data: Vec<u8>,
}

/// One namespace's keyspace.
pub(crate) type Bucket = IndexMap<String, Entry>;

/// The whole store: namespace name -> bucket. The empty string is the default namespace.
pub(crate) type Store = IndexMap<String, Bucket>;

/// Borrowed view of the store written to disk.
#[derive(Serialize)]
pub(crate) struct StoreFileRef<'a> {
    pub(crate) magic: &'a str,
    pub(crate) version: u8,
    pub(crate) kdf: &'a KdfRepr,
    pub(crate) salt: &'a [u8; SALT_LEN],
    pub(crate) verifier: &'a Entry,
    pub(crate) trees: &'a Store,
}

/// Owned store read back from disk.
#[derive(Deserialize)]
pub(crate) struct StoreFile {
    pub(crate) magic: String,
    pub(crate) version: u8,
    pub(crate) kdf: KdfRepr,
    pub(crate) salt: [u8; SALT_LEN],
    pub(crate) verifier: Entry,
    pub(crate) trees: Store,
}

/// Seconds since the Unix epoch.
pub(crate) fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The sidecar lock-file path for a store path.
pub(crate) fn lock_path_for(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(".lock");
    PathBuf::from(s)
}

/// Acquire a cross-process file lock on the store's `.lock` sidecar, returning the held
/// handle (kept alive for the store's lifetime). `LockMode::None` is a no-op.
pub(crate) fn acquire_lock(path: &Path, mode: LockMode, read_only: bool) -> Result<Option<File>> {
    if matches!(mode, LockMode::None) {
        return Ok(None);
    }
    let lock_path = lock_path_for(path);
    if let Some(parent) = lock_path.parent() {
        if !parent.as_os_str().is_empty() && !parent.is_dir() {
            fs::create_dir_all(parent)?;
        }
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)?;

    // std's native file locking (stable since 1.89). `try_lock` is the exclusive variant.
    let result = if read_only || matches!(mode, LockMode::Shared) {
        file.try_lock_shared()
    } else {
        file.try_lock()
    };
    result.map_err(|_| Error::Locked)?;
    Ok(Some(file))
}

/// Durably write `bytes` to `path` via a same-directory temp file + fsync + atomic rename
/// + parent-dir fsync. A crash leaves either the old or the new complete file.
pub(crate) fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    if !dir.is_dir() {
        fs::create_dir_all(dir)?;
    }

    let file_name = path
        .file_name()
        .ok_or_else(|| Error::CorruptStore("store path has no file name".to_string()))?;
    let mut tmp_name = file_name.to_os_string();
    tmp_name.push(format!(".tmp.{}.{:016x}", std::process::id(), rand_u64()?));
    let tmp_path = dir.join(tmp_name);

    let write_result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(())
    })();
    if let Err(e) = write_result {
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }

    if let Err(e) = fs::rename(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(e.into());
    }

    if let Ok(dir_file) = File::open(dir) {
        let _ = dir_file.sync_all();
    }
    Ok(())
}
