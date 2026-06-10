//! The database handle ([`MicroKV`]), its shared internal state, the [`Builder`], and
//! the store-wide operations: opening, persistence, transactions, and key rotation.

use std::fs::File;
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{Duration, Instant};

use serde::de::DeserializeOwned;
use serde::Serialize;
use zeroize::Zeroize;

use crate::codec::{decode, encode};
use crate::config::{
    credential_key, derive_pwd, AutoSave, Credential, KdfParams, KdfRepr, LockMode,
};
use crate::crypto::{aead_decrypt, aead_encrypt, gen_salt, header_aad, value_aad, SecretKey};
use crate::error::{Error, Result};
use crate::format::{
    acquire_lock, atomic_write, lock_path_for, now_secs, Entry, Store, StoreFile, StoreFileRef,
    FORMAT_VERSION, MAGIC, VERIFIER_PLAINTEXT,
};
use crate::secret::{Secret, SecretString};
use crate::tree::Tree;
use crate::txn::Txn;

/// Mutable cryptographic state, behind its own lock so password rotation can swap it.
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
#[derive(Clone)]
pub struct MicroKV {
    pub(crate) inner: Arc<Inner>,
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

/* ============================ Builder ============================ */

enum OpenMode {
    OpenOrCreate,
    MustExist,
    MustCreate,
}

/// Configures and opens a [`MicroKV`] store. Configuration is infallible and
/// reorderable; the single fallible act is [`Builder::open`].
pub struct Builder {
    path: Option<PathBuf>,
    kdf: KdfParams,
    autosave: AutoSave,
    lock_mode: LockMode,
    read_only: bool,
    mode: OpenMode,
}

impl Default for Builder {
    fn default() -> Self {
        Builder {
            path: None,
            kdf: KdfParams::default(),
            autosave: AutoSave::Manual,
            lock_mode: LockMode::None,
            read_only: false,
            mode: OpenMode::OpenOrCreate,
        }
    }
}

impl Builder {
    /// Persist to `path`. Absent ⇒ in-memory only.
    pub fn path(mut self, path: impl AsRef<Path>) -> Self {
        self.path = Some(path.as_ref().to_path_buf());
        self
    }

    /// KDF parameters stamped into *new* stores (ignored when opening an existing one).
    pub fn kdf(mut self, kdf: KdfParams) -> Self {
        self.kdf = kdf;
        self
    }

    /// Auto-save policy.
    pub fn autosave(mut self, policy: AutoSave) -> Self {
        self.autosave = policy;
        self
    }

    /// Cross-process file lock to acquire on open.
    pub fn lock_mode(mut self, mode: LockMode) -> Self {
        self.lock_mode = mode;
        self
    }

    /// Open read-only: all writes return [`Error::ReadOnly`].
    pub fn read_only(mut self, yes: bool) -> Self {
        self.read_only = yes;
        self
    }

    /// Open (or create) the store with the given credential. The one fallible call.
    pub fn open(self, cred: Credential) -> Result<MicroKV> {
        let exists = self.path.as_ref().map(|p| p.is_file()).unwrap_or(false);

        match self.mode {
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
            self.open_existing_file(cred)
        } else {
            self.create(cred)
        }
    }

    fn open_existing_file(self, cred: Credential) -> Result<MicroKV> {
        let path = self.path.clone().expect("existing path implies Some");
        let file_lock = acquire_lock(&path, self.lock_mode, self.read_only)?;

        let raw = std::fs::read(&path)?;
        let sf: StoreFile = rmp_serde::from_slice(&raw)
            .map_err(|e| Error::Corrupt(format!("cannot deserialize store: {e}")))?;

        if sf.magic != MAGIC {
            return Err(Error::Corrupt(
                "not a microkv store (bad magic)".to_string(),
            ));
        }
        if sf.version != FORMAT_VERSION {
            return Err(Error::UnsupportedVersion {
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

        Ok(MicroKV {
            inner: Arc::new(Inner {
                storage: RwLock::new(sf.trees),
                crypto: RwLock::new(Crypto {
                    key: secret,
                    kdf: sf.kdf,
                    salt: sf.salt,
                    verifier: sf.verifier,
                }),
                path: Some(path),
                autosave: self.autosave,
                read_only: self.read_only,
                commit_lock: Mutex::new(()),
                dirty: AtomicBool::new(false),
                last_save: Mutex::new(Instant::now()),
                _file_lock: file_lock,
            }),
        })
    }

    fn create(self, cred: Credential) -> Result<MicroKV> {
        let kdf = self.kdf.0.clone();
        let salt = gen_salt()?;

        let mut key_bytes = credential_key(&cred, &kdf, &salt)?;
        let secret = SecretKey::new(key_bytes)?;
        key_bytes.zeroize();

        // Mint the verifier, binding the header into its associated data.
        let header = header_aad(&kdf, &salt)?;
        let (nonce, data) = aead_encrypt(&secret.cipher(), &header, VERIFIER_PLAINTEXT)?;
        let verifier = Entry { nonce, data };

        let file_lock = match &self.path {
            Some(p) => acquire_lock(p, self.lock_mode, self.read_only)?,
            None => None,
        };

        let db = MicroKV {
            inner: Arc::new(Inner {
                storage: RwLock::new(Store::new()),
                crypto: RwLock::new(Crypto {
                    key: secret,
                    kdf,
                    salt,
                    verifier,
                }),
                path: self.path.clone(),
                autosave: self.autosave,
                read_only: self.read_only,
                commit_lock: Mutex::new(()),
                dirty: AtomicBool::new(false),
                last_save: Mutex::new(Instant::now()),
                _file_lock: file_lock,
            }),
        };

        // Materialize a new store on disk immediately so the header exists.
        if db.inner.path.is_some() && !self.read_only {
            db.inner.persist()?;
        }

        Ok(db)
    }
}

/* ============================ Constructors ============================ */

impl MicroKV {
    /// Start configuring a store.
    pub fn builder() -> Builder {
        Builder::default()
    }

    /// Create an in-memory-only store (no persistence).
    pub fn in_memory(cred: Credential) -> Result<Self> {
        Builder::default().open(cred)
    }

    /// Open the store at `path`, creating it if absent.
    pub fn open(path: impl AsRef<Path>, cred: Credential) -> Result<Self> {
        Builder::default().path(path).open(cred)
    }

    /// Open the store at `path`, failing if it does not exist.
    pub fn open_existing(path: impl AsRef<Path>, cred: Credential) -> Result<Self> {
        let mut b = Builder::default().path(path);
        b.mode = OpenMode::MustExist;
        b.open(cred)
    }

    /// Create a new store at `path`, failing if it already exists.
    pub fn create_new(path: impl AsRef<Path>, cred: Credential) -> Result<Self> {
        let mut b = Builder::default().path(path);
        b.mode = OpenMode::MustCreate;
        b.open(cred)
    }

    /* ============================ Trees / namespaces ============================ */

    /// Get a handle to an isolated namespace. Keys in different namespaces never collide,
    /// and a value's ciphertext is bound to its namespace.
    pub fn namespace(&self, name: impl AsRef<str>) -> Tree {
        Tree::new(self.clone(), name.as_ref().to_string())
    }

    /// Handle to the default (unnamed) namespace.
    pub fn default_tree(&self) -> Tree {
        self.namespace("")
    }

    /// List the namespaces that currently hold data.
    pub fn tree_names(&self) -> Result<Vec<String>> {
        let g = self.inner.read_store()?;
        Ok(g.keys().cloned().collect())
    }

    /* ============================ Default-namespace forwards ============================ */

    pub fn get<V: DeserializeOwned>(&self, key: &str) -> Result<Option<V>> {
        self.default_tree().get(key)
    }
    pub fn require<V: DeserializeOwned>(&self, key: &str) -> Result<V> {
        self.default_tree().require(key)
    }
    pub fn get_secret<V: DeserializeOwned>(&self, key: &str) -> Result<Option<Secret<V>>> {
        self.default_tree().get_secret(key)
    }
    pub fn put<V: Serialize>(&self, key: &str, value: &V) -> Result<()> {
        self.default_tree().put(key, value)
    }
    pub fn put_with_ttl<V: Serialize>(&self, key: &str, value: &V, ttl: Duration) -> Result<()> {
        self.default_tree().put_with_ttl(key, value, ttl)
    }
    pub fn remove(&self, key: &str) -> Result<bool> {
        self.default_tree().remove(key)
    }
    pub fn contains(&self, key: &str) -> Result<bool> {
        self.default_tree().contains(key)
    }
    pub fn len(&self) -> Result<usize> {
        self.default_tree().len()
    }
    pub fn is_empty(&self) -> Result<bool> {
        self.default_tree().is_empty()
    }
    pub fn update<V, F>(&self, key: &str, f: F) -> Result<()>
    where
        V: Serialize + DeserializeOwned,
        F: FnOnce(Option<V>) -> Option<V>,
    {
        self.default_tree().update(key, f)
    }
    pub fn get_or_insert_with<V, F>(&self, key: &str, f: F) -> Result<V>
    where
        V: Serialize + DeserializeOwned,
        F: FnOnce() -> V,
    {
        self.default_tree().get_or_insert_with(key, f)
    }
    pub fn compare_and_swap<V: Serialize + DeserializeOwned>(
        &self,
        key: &str,
        expected: Option<&V>,
        new: Option<&V>,
    ) -> Result<bool> {
        self.default_tree().compare_and_swap(key, expected, new)
    }
    pub fn keys(&self) -> Result<Vec<String>> {
        self.default_tree().keys()
    }
    pub fn keys_sorted(&self) -> Result<Vec<String>> {
        self.default_tree().keys_sorted()
    }
    pub fn prefix<V: DeserializeOwned>(&self, prefix: &str) -> Result<Vec<(String, V)>> {
        self.default_tree().prefix(prefix)
    }
    pub fn for_each<V, F>(&self, f: F) -> Result<()>
    where
        V: DeserializeOwned,
        F: FnMut(&str, V) -> ControlFlow<()>,
    {
        self.default_tree().for_each(f)
    }

    /* ============================ Transactions ============================ */

    /// Run a sequence of operations under a single write lock. All mutations apply to a
    /// working copy; on `Ok` they are committed (and auto-saved per policy) atomically,
    /// on `Err` they are discarded (rollback). Namespaces are addressed explicitly — use
    /// `""` for the default.
    pub fn transaction<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&mut Txn) -> Result<R>,
    {
        self.ensure_writable()?;

        let mut guard = self.inner.write_store()?;
        let mut working = guard.clone();
        let mut txn = Txn::new(&mut working, self);

        match f(&mut txn) {
            Ok(result) => {
                *guard = working;
                drop(guard);
                self.after_write()?;
                Ok(result)
            }
            Err(e) => Err(e), // working discarded; guard left unchanged
        }
    }

    /* ============================ Security / admin ============================ */

    /// The KDF parameters currently in effect.
    pub fn kdf_params(&self) -> KdfParams {
        self.inner
            .crypto
            .read()
            .map(|c| KdfParams(c.kdf.clone()))
            .unwrap_or_else(|_| KdfParams::interactive())
    }

    /// Change the password: verifies `old`, then re-derives and re-encrypts everything
    /// under `new` with a fresh salt.
    pub fn change_password(&self, old: SecretString, new: SecretString) -> Result<()> {
        {
            let c = self.inner.crypto.read().map_err(|_| Error::Locked)?;
            let mut probe = derive_pwd(old.expose().as_bytes(), &c.kdf, &c.salt)?;
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
        self.rekey(Credential::Password(new))
    }

    /// Re-key the store: re-derive the key from `new` (fresh salt, same KDF params) and
    /// re-encrypt every entry and the verifier under it.
    pub fn rekey(&self, new: Credential) -> Result<()> {
        self.ensure_writable()?;
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

        self.after_write()
    }

    /* ============================ Persistence ============================ */

    /// Persist the store to its associated path (errors for in-memory stores).
    pub fn save(&self) -> Result<()> {
        if self.inner.read_only {
            return Err(Error::ReadOnly);
        }
        self.inner.persist()?;
        self.inner.dirty.store(false, Ordering::Release);
        if let Ok(mut last) = self.inner.last_save.lock() {
            *last = Instant::now();
        }
        Ok(())
    }

    /// Persist a copy to a different path without changing the store's own path.
    pub fn save_as(&self, path: impl AsRef<Path>) -> Result<()> {
        let bytes = self.inner.serialize()?;
        atomic_write(path.as_ref(), &bytes)
    }

    /// Serialize the encrypted store to bytes without touching the filesystem.
    pub fn export(&self) -> Result<Vec<u8>> {
        self.inner.serialize()
    }

    /// Clear all data and remove the persistent file (and its lock sidecar), if any.
    pub fn destroy(self) -> Result<()> {
        self.ensure_writable()?;
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

    /// Remove all expired entries across every namespace, returning how many were purged.
    /// Each entry is authenticated before its (encrypted) expiry is honored, so a tampered
    /// expiry surfaces as an error rather than causing a live value to be dropped.
    pub fn sweep_expired(&self) -> Result<usize> {
        self.ensure_writable()?;
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
            self.after_write()?;
        }
        Ok(removed)
    }

    /* ============================ Crate-internal helpers ============================ */

    pub(crate) fn ensure_writable(&self) -> Result<()> {
        if self.inner.read_only {
            Err(Error::ReadOnly)
        } else {
            Ok(())
        }
    }

    /// Run the configured auto-save policy after a successful mutation.
    pub(crate) fn after_write(&self) -> Result<()> {
        self.inner.dirty.store(true, Ordering::Release);
        match self.inner.autosave {
            AutoSave::OnEveryWrite => self.save(),
            AutoSave::Periodic(d) => {
                let elapsed = self
                    .inner
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
}

impl Inner {
    /// Acquire the storage read lock, mapping poisoning to [`Error::Locked`].
    pub(crate) fn read_store(&self) -> Result<RwLockReadGuard<'_, Store>> {
        self.storage.read().map_err(|_| Error::Locked)
    }

    /// Acquire the storage write lock, mapping poisoning to [`Error::Locked`].
    pub(crate) fn write_store(&self) -> Result<RwLockWriteGuard<'_, Store>> {
        self.storage.write().map_err(|_| Error::Locked)
    }

    /// Decrypt and deserialize an entry's value, honoring (authenticated) expiry.
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

    /// Seal a value under the current key, bound to `(ns, key)` via associated data. The
    /// expiry is framed into the plaintext, so it is encrypted and authenticated.
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

    /// Open an entry: authenticate + decrypt, then honor the (now-authenticated) expiry.
    /// Returns `None` if the entry has expired. Any tampering with the expiry shows up as
    /// an authentication failure ([`Error::Crypto`]) rather than a silent change.
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

    /// Whether an entry is present and not expired, without exposing its value.
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

/// Parse a framed plaintext back into `(expiry, value)`. A malformed frame is treated as
/// a cryptographic/corruption failure.
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

/// Clone out the entry for `(ns, key)` if present.
pub(crate) fn fetch(store: &Store, ns: &str, key: &str) -> Option<Entry> {
    store.get(ns).and_then(|b| b.get(key)).cloned()
}

/// Remove `(ns, key)`, returning whether it existed. Order of remaining keys is preserved.
pub(crate) fn remove_from(store: &mut Store, ns: &str, key: &str) -> bool {
    store
        .get_mut(ns)
        .map(|b| b.shift_remove(key).is_some())
        .unwrap_or(false)
}

/// Encode, seal, and insert a value into `store` under `(ns, key)`.
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
