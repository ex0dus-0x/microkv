//! The database handle ([`MicroKV`]), its shared internal state, and the store-wide
//! operations: opening (via [`Config`]), persistence, transactions, and key rotation.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{Duration, Instant};

use serde::de::DeserializeOwned;
use serde::Serialize;
use zeroize::Zeroize;

use crate::codec::{decode, encode};
use crate::config::{credential_key, derive_pwd, AutoSave, Config, Credential, KdfParams, KdfRepr};
use crate::crypto::{aead_decrypt, aead_encrypt, gen_salt, header_aad, value_aad, SecretKey};
use crate::error::{Error, Result};
use crate::format::{
    acquire_lock, atomic_write, lock_path_for, now_secs, Entry, Store, StoreFile, StoreFileRef,
    FORMAT_VERSION, MAGIC, VERIFIER_PLAINTEXT,
};
use crate::secret::SecretString;
use crate::tree::Tree;
use crate::txn::Txn;

/// Crypto state behind its own lock, so `rekey` can swap it.
struct Crypto {
    key: SecretKey,
    kdf: KdfRepr,
    salt: [u8; crate::crypto::SALT_LEN],
    verifier: Entry,
}

/// Shared, reference-counted store state. Every [`MicroKV`] clone points at one `Inner`.
pub(crate) struct Inner {
    pub(crate) storage: RwLock<Store>,
    crypto: RwLock<Crypto>,
    path: Option<PathBuf>,
    autosave: AutoSave,
    read_only: bool,
    commit_lock: Mutex<()>,
    dirty: AtomicBool,
    last_save: Mutex<Instant>,
    // held for the store's lifetime to keep the cross-process lock; never read.
    _file_lock: Option<File>,
}

/// The database handle. Cheap to clone (`Arc`-backed); all clones share one store.
///
/// Operations on the default namespace (`get`, `put`, `keys`, …) are available directly
/// via `Deref` to the default [`Tree`]; store-wide operations (`namespace`,
/// `transaction`, `save`, `rekey`, …) are inherent methods.
#[derive(Clone)]
pub struct MicroKV {
    pub(crate) inner: Arc<Inner>,
    default: Tree,
}

impl std::ops::Deref for MicroKV {
    type Target = Tree;
    fn deref(&self) -> &Tree {
        &self.default
    }
}

// Redacted debug output: never prints the key, salt, verifier, or stored values.
impl std::fmt::Debug for MicroKV {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MicroKV")
            .field("path", &self.inner.path)
            .field("read_only", &self.inner.read_only)
            .finish_non_exhaustive()
    }
}

/* ============================ Constructors ============================ */

enum OpenMode {
    OpenOrCreate,
    MustExist,
    MustCreate,
}

impl MicroKV {
    /// Caches a default-namespace tree so `MicroKV` can `Deref` to it.
    fn from_inner(inner: Arc<Inner>) -> Self {
        let default = Tree::new(Arc::clone(&inner), String::new());
        MicroKV { inner, default }
    }

    pub fn in_memory(cred: Credential) -> Result<Self> {
        Self::build(None, OpenMode::OpenOrCreate, cred, Config::default())
    }

    pub fn in_memory_with(cred: Credential, config: Config) -> Result<Self> {
        Self::build(None, OpenMode::OpenOrCreate, cred, config)
    }

    /// Open, creating the store if it doesn't exist.
    pub fn open(path: impl AsRef<Path>, cred: Credential) -> Result<Self> {
        Self::build(
            Some(to_path(path)),
            OpenMode::OpenOrCreate,
            cred,
            Config::default(),
        )
    }

    /// [`MicroKV::open`] with explicit [`Config`].
    pub fn open_with(path: impl AsRef<Path>, cred: Credential, config: Config) -> Result<Self> {
        Self::build(Some(to_path(path)), OpenMode::OpenOrCreate, cred, config)
    }

    /// Fails if the store doesn't exist.
    pub fn open_existing(path: impl AsRef<Path>, cred: Credential) -> Result<Self> {
        Self::build(
            Some(to_path(path)),
            OpenMode::MustExist,
            cred,
            Config::default(),
        )
    }

    /// [`MicroKV::open_existing`] with explicit [`Config`].
    pub fn open_existing_with(
        path: impl AsRef<Path>,
        cred: Credential,
        config: Config,
    ) -> Result<Self> {
        Self::build(Some(to_path(path)), OpenMode::MustExist, cred, config)
    }

    /// Fails if the store already exists.
    pub fn create_new(path: impl AsRef<Path>, cred: Credential) -> Result<Self> {
        Self::build(
            Some(to_path(path)),
            OpenMode::MustCreate,
            cred,
            Config::default(),
        )
    }

    /// [`MicroKV::create_new`] with explicit [`Config`].
    pub fn create_new_with(
        path: impl AsRef<Path>,
        cred: Credential,
        config: Config,
    ) -> Result<Self> {
        Self::build(Some(to_path(path)), OpenMode::MustCreate, cred, config)
    }

    /// Enforce the mode, then read or create.
    fn build(
        path: Option<PathBuf>,
        mode: OpenMode,
        cred: Credential,
        config: Config,
    ) -> Result<Self> {
        let exists = path.as_ref().map(|p| p.is_file()).unwrap_or(false);

        match mode {
            OpenMode::MustExist if !exists => {
                return Err(Error::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "store does not exist",
                )));
            }
            OpenMode::MustCreate if exists => return Err(Error::AlreadyExists),
            _ => {}
        }

        if exists {
            Self::open_existing_file(path.expect("existing path implies Some"), cred, config)
        } else {
            Self::create(path, cred, config)
        }
    }

    fn open_existing_file(path: PathBuf, cred: Credential, config: Config) -> Result<Self> {
        let file_lock = acquire_lock(&path, config.lock_mode, config.read_only)?;

        let raw = std::fs::read(&path)?;
        let sf: StoreFile = rmp_serde::from_slice(&raw)
            .map_err(|e| Error::CorruptStore(format!("cannot deserialize store: {e}")))?;

        if sf.magic != MAGIC {
            return Err(Error::CorruptStore(
                "not a microkv store (bad magic)".to_string(),
            ));
        }
        if sf.version != FORMAT_VERSION {
            return Err(Error::UnsupportedStoreVersion {
                found: sf.version,
                expected: FORMAT_VERSION,
            });
        }

        let mut key_bytes = credential_key(&cred, &sf.kdf, &sf.salt)?;
        let secret = SecretKey::new(key_bytes)?;
        key_bytes.zeroize();

        // Verify the credential (and authenticate the header) via the verifier.
        let header = header_aad(&sf.kdf, &sf.salt)?;
        let plaintext = aead_decrypt(
            &secret.cipher(),
            &header,
            &sf.verifier.nonce,
            &sf.verifier.data,
        )
        .map_err(|_| Error::WrongPassword)?;
        if plaintext != VERIFIER_PLAINTEXT {
            return Err(Error::WrongPassword);
        }

        Ok(MicroKV::from_inner(Arc::new(Inner {
            storage: RwLock::new(sf.trees),
            crypto: RwLock::new(Crypto {
                key: secret,
                kdf: sf.kdf,
                salt: sf.salt,
                verifier: sf.verifier,
            }),
            path: Some(path),
            autosave: config.autosave,
            read_only: config.read_only,
            commit_lock: Mutex::new(()),
            dirty: AtomicBool::new(false),
            last_save: Mutex::new(Instant::now()),
            _file_lock: file_lock,
        })))
    }

    fn create(path: Option<PathBuf>, cred: Credential, config: Config) -> Result<Self> {
        let kdf = config.kdf.0.clone();
        let salt = gen_salt()?;

        let mut key_bytes = credential_key(&cred, &kdf, &salt)?;
        let secret = SecretKey::new(key_bytes)?;
        key_bytes.zeroize();

        // Mint the verifier, binding the header into its associated data.
        let header = header_aad(&kdf, &salt)?;
        let (nonce, data) = aead_encrypt(&secret.cipher(), &header, VERIFIER_PLAINTEXT)?;
        let verifier = Entry { nonce, data };

        let file_lock = match &path {
            Some(p) => acquire_lock(p, config.lock_mode, config.read_only)?,
            None => None,
        };

        let db = MicroKV::from_inner(Arc::new(Inner {
            storage: RwLock::new(Store::new()),
            crypto: RwLock::new(Crypto {
                key: secret,
                kdf,
                salt,
                verifier,
            }),
            path,
            autosave: config.autosave,
            read_only: config.read_only,
            commit_lock: Mutex::new(()),
            dirty: AtomicBool::new(false),
            last_save: Mutex::new(Instant::now()),
            _file_lock: file_lock,
        }));

        // Materialize a new store on disk immediately so the header exists.
        if db.inner.path.is_some() && !config.read_only {
            db.inner.persist()?;
        }

        Ok(db)
    }

    /* ============================ Trees / namespaces ============================ */

    /// An isolated namespace: keys never collide across namespaces, and each value's
    /// ciphertext is bound to its namespace. `MicroKV` derefs to the default (`""`) one.
    pub fn namespace(&self, name: impl AsRef<str>) -> Tree {
        Tree::new(Arc::clone(&self.inner), name.as_ref().to_string())
    }

    /// Namespaces that currently hold data.
    pub fn tree_names(&self) -> Result<Vec<String>> {
        let g = self.inner.read_store()?;
        Ok(g.keys().cloned().collect())
    }

    /* ============================ Transactions ============================ */

    /// Run ops under one write lock against a working copy: commit on `Ok`, roll back on
    /// `Err`. Namespaces are explicit (`""` is the default).
    pub fn transaction<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&mut Txn) -> Result<R>,
    {
        self.inner.ensure_writable()?;

        let mut guard = self.inner.write_store()?;
        let mut working = guard.clone();
        let mut txn = Txn::new(&mut working, self);

        match f(&mut txn) {
            Ok(result) => {
                *guard = working;
                drop(guard);
                self.inner.after_write()?;
                Ok(result)
            }
            Err(e) => Err(e), // working discarded; guard left unchanged
        }
    }

    /* ============================ Security / admin ============================ */

    pub fn kdf_params(&self) -> KdfParams {
        self.inner
            .crypto
            .read()
            .map(|c| KdfParams(c.kdf.clone()))
            .unwrap_or_else(|_| KdfParams::interactive())
    }

    /// Verify `old`, then re-key everything under `new`.
    pub fn change_password(&self, old: impl Into<String>, new: impl Into<String>) -> Result<()> {
        let old = SecretString::new(old.into());
        {
            let c = self.inner.crypto.read().map_err(|_| Error::Locked)?;
            let mut probe = derive_pwd(old.as_bytes(), &c.kdf, &c.salt)?;
            let probe_key = SecretKey::new(probe)?;
            probe.zeroize();
            let header = header_aad(&c.kdf, &c.salt)?;
            let ok = aead_decrypt(
                &probe_key.cipher(),
                &header,
                &c.verifier.nonce,
                &c.verifier.data,
            )
            .map(|p| p == VERIFIER_PLAINTEXT)
            .unwrap_or(false);
            if !ok {
                return Err(Error::WrongPassword);
            }
        }
        self.rekey(Credential::Password(SecretString::new(new.into())))
    }

    /// Re-derive the key from `new` (fresh salt) and re-encrypt every entry + the verifier.
    pub fn rekey(&self, new: Credential) -> Result<()> {
        self.inner.ensure_writable()?;
        let new_salt = gen_salt()?;

        {
            let mut sg = self.inner.storage.write().map_err(|_| Error::Locked)?;
            let mut cg = self.inner.crypto.write().map_err(|_| Error::Locked)?;

            let new_kdf = cg.kdf.clone();
            let mut key_bytes = credential_key(&new, &new_kdf, &new_salt)?;
            let new_secret = SecretKey::new(key_bytes)?;
            key_bytes.zeroize();

            let old_cipher = cg.key.cipher();
            let new_cipher = new_secret.cipher();

            for (ns, bucket) in sg.iter_mut() {
                for (key, entry) in bucket.iter_mut() {
                    let aad = value_aad(ns, key);
                    let mut pt = aead_decrypt(&old_cipher, &aad, &entry.nonce, &entry.data)?;
                    let (nonce, data) = aead_encrypt(&new_cipher, &aad, &pt)?;
                    pt.zeroize();
                    entry.nonce = nonce;
                    entry.data = data;
                }
            }

            let header = header_aad(&new_kdf, &new_salt)?;
            let (vn, vd) = aead_encrypt(&new_cipher, &header, VERIFIER_PLAINTEXT)?;

            cg.key = new_secret;
            cg.salt = new_salt;
            cg.kdf = new_kdf;
            cg.verifier = Entry {
                nonce: vn,
                data: vd,
            };
        }

        self.inner.after_write()
    }

    /* ============================ Persistence ============================ */

    /// Persist to the store's path; errors ([`Error::NoPath`]) for in-memory stores.
    pub fn save(&self) -> Result<()> {
        self.inner.save()
    }

    /// Persist a copy elsewhere, leaving the store's own path unchanged.
    pub fn save_as(&self, path: impl AsRef<Path>) -> Result<()> {
        let bytes = self.inner.serialize()?;
        atomic_write(path.as_ref(), &bytes)
    }

    /// The encrypted store as bytes (no filesystem access).
    pub fn export(&self) -> Result<Vec<u8>> {
        self.inner.serialize()
    }

    /// Clear all data and delete the file + its `.lock` sidecar.
    pub fn destroy(self) -> Result<()> {
        self.inner.ensure_writable()?;
        {
            let mut g = self.inner.write_store()?;
            g.clear();
        }
        if let Some(path) = &self.inner.path {
            if path.exists() {
                std::fs::remove_file(path)?;
            }
            let lock = lock_path_for(path);
            if lock.exists() {
                let _ = std::fs::remove_file(lock);
            }
        }
        Ok(())
    }

    /// Drop every expired entry, returning the count. Entries are authenticated before
    /// their (encrypted) expiry is trusted, so a tampered expiry errors instead of
    /// dropping a live value.
    pub fn sweep_expired(&self) -> Result<usize> {
        self.inner.ensure_writable()?;
        let removed = {
            let mut g = self.inner.write_store()?;
            let mut stale: Vec<(String, String)> = Vec::new();
            for (ns, bucket) in g.iter() {
                for (key, entry) in bucket.iter() {
                    if !self.inner.is_live(ns, key, entry)? {
                        stale.push((ns.clone(), key.clone()));
                    }
                }
            }
            for (ns, key) in &stale {
                if let Some(bucket) = g.get_mut(ns) {
                    bucket.shift_remove(key);
                }
            }
            stale.len()
        };
        if removed > 0 {
            self.inner.after_write()?;
        }
        Ok(removed)
    }
}

impl Inner {
    pub(crate) fn ensure_writable(&self) -> Result<()> {
        if self.read_only {
            Err(Error::ReadOnly)
        } else {
            Ok(())
        }
    }

    pub(crate) fn save(&self) -> Result<()> {
        if self.read_only {
            return Err(Error::ReadOnly);
        }
        self.persist()?;
        self.dirty.store(false, Ordering::Release);
        if let Ok(mut last) = self.last_save.lock() {
            *last = Instant::now();
        }
        Ok(())
    }

    /// Apply the auto-save policy after a successful mutation.
    pub(crate) fn after_write(&self) -> Result<()> {
        self.dirty.store(true, Ordering::Release);
        match self.autosave {
            AutoSave::OnEveryWrite => self.save(),
            AutoSave::Periodic(d) => {
                let elapsed = self
                    .last_save
                    .lock()
                    .map(|l| l.elapsed())
                    .unwrap_or(Duration::ZERO);
                if elapsed >= d {
                    self.save()
                } else {
                    Ok(())
                }
            }
            AutoSave::Manual | AutoSave::OnDrop => Ok(()),
        }
    }

    pub(crate) fn read_store(&self) -> Result<RwLockReadGuard<'_, Store>> {
        self.storage.read().map_err(|_| Error::Locked)
    }

    pub(crate) fn write_store(&self) -> Result<RwLockWriteGuard<'_, Store>> {
        self.storage.write().map_err(|_| Error::Locked)
    }

    /// Decrypt + deserialize an entry, honoring its authenticated expiry.
    pub(crate) fn read_value<V: DeserializeOwned>(
        &self,
        ns: &str,
        key: &str,
        entry: &Entry,
    ) -> Result<Option<V>> {
        match self.open_entry(ns, key, entry)? {
            Some(bytes) => Ok(Some(decode(bytes)?)),
            None => Ok(None),
        }
    }

    fn serialize(&self) -> Result<Vec<u8>> {
        // lock order: storage, then crypto (matches rekey).
        let store = self.read_store()?;
        let crypto = self.crypto.read().map_err(|_| Error::Locked)?;
        let file = StoreFileRef {
            magic: MAGIC,
            version: FORMAT_VERSION,
            kdf: &crypto.kdf,
            salt: &crypto.salt,
            verifier: &crypto.verifier,
            trees: &store,
        };
        rmp_serde::to_vec(&file).map_err(|e| Error::Serialization(e.to_string()))
    }

    fn persist(&self) -> Result<()> {
        let path = self.path.clone().ok_or(Error::NoPath)?;
        let _guard = self.commit_lock.lock().map_err(|_| Error::Locked)?;
        let bytes = self.serialize()?;
        atomic_write(&path, &bytes)
    }

    /// Seal a value, bound to `(ns, key)`. Expiry is framed into the plaintext, so it's
    /// encrypted and authenticated too.
    pub(crate) fn seal(
        &self,
        ns: &str,
        key: &str,
        value: &[u8],
        ttl: Option<Duration>,
    ) -> Result<Entry> {
        let crypto = self.crypto.read().map_err(|_| Error::Locked)?;
        let expires_at = ttl.map(|d| now_secs().saturating_add(d.as_secs()));
        let mut framed = frame(expires_at, value);
        let aad = value_aad(ns, key);
        let (nonce, data) = aead_encrypt(&crypto.key.cipher(), &aad, &framed)?;
        framed.zeroize();
        Ok(Entry { nonce, data })
    }

    /// Authenticate + decrypt, then apply expiry (`None` if expired). Decrypting before
    /// checking expiry means a tampered expiry fails auth rather than passing silently.
    pub(crate) fn open_entry(&self, ns: &str, key: &str, entry: &Entry) -> Result<Option<Vec<u8>>> {
        let crypto = self.crypto.read().map_err(|_| Error::Locked)?;
        let aad = value_aad(ns, key);
        let mut framed = aead_decrypt(&crypto.key.cipher(), &aad, &entry.nonce, &entry.data)?;
        let result = unframe(&framed).map(|(expires_at, value)| {
            if expires_at.is_some_and(|exp| now_secs() >= exp) {
                None
            } else {
                Some(value)
            }
        });
        framed.zeroize();
        result
    }

    /// Present and not expired, without exposing the value.
    pub(crate) fn is_live(&self, ns: &str, key: &str, entry: &Entry) -> Result<bool> {
        match self.open_entry(ns, key, entry)? {
            Some(mut value) => {
                value.zeroize();
                Ok(true)
            }
            None => Ok(false),
        }
    }
}

/// Frame a value with its optional expiry for sealing: `[flag][expiry_le?] ++ value`.
fn frame(expires_at: Option<u64>, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(9 + value.len());
    match expires_at {
        Some(ts) => {
            out.push(1);
            out.extend_from_slice(&ts.to_le_bytes());
        }
        None => out.push(0),
    }
    out.extend_from_slice(value);
    out
}

/// Inverse of [`frame`]; a malformed frame counts as a crypto failure.
fn unframe(buf: &[u8]) -> Result<(Option<u64>, Vec<u8>)> {
    match buf.first() {
        Some(0) => Ok((None, buf[1..].to_vec())),
        Some(1) if buf.len() >= 9 => {
            let mut ts = [0u8; 8];
            ts.copy_from_slice(&buf[1..9]);
            Ok((Some(u64::from_le_bytes(ts)), buf[9..].to_vec()))
        }
        _ => Err(Error::Crypto),
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        let should_flush = matches!(self.autosave, AutoSave::OnDrop | AutoSave::Periodic(_));
        if should_flush
            && self.path.is_some()
            && !self.read_only
            && self.dirty.load(Ordering::Acquire)
        {
            let _ = self.persist();
        }
        // _file_lock is released as its File drops.
    }
}

/* ============================ Shared store operations ============================ */

fn to_path(p: impl AsRef<Path>) -> PathBuf {
    p.as_ref().to_path_buf()
}

pub(crate) fn fetch(store: &Store, ns: &str, key: &str) -> Option<Entry> {
    store.get(ns).and_then(|b| b.get(key)).cloned()
}

/// Returns whether the key existed; preserves the order of remaining keys.
pub(crate) fn remove_from(store: &mut Store, ns: &str, key: &str) -> bool {
    store
        .get_mut(ns)
        .map(|b| b.shift_remove(key).is_some())
        .unwrap_or(false)
}

/// Encode + seal + insert under `(ns, key)`.
pub(crate) fn seal_into<V: Serialize>(
    inner: &Inner,
    store: &mut Store,
    ns: &str,
    key: &str,
    value: &V,
    ttl: Option<Duration>,
) -> Result<()> {
    let mut plaintext = encode(value)?;
    let entry = inner.seal(ns, key, &plaintext, ttl)?;
    plaintext.zeroize();
    store
        .entry(ns.to_string())
        .or_default()
        .insert(key.to_string(), entry);
    Ok(())
}
