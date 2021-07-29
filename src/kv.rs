//! Defines the foundational structure and API for the key-value store implementation.
//! The `kv` module should be used to spin up localized instances of the key-value store.
//!
//! ## Features
//!
//! * Database interaction operations, with sorted-key iteration possible
//! * Serialization to persistent storage
//! * Symmetric authenticated cryptography
//! * Mutual exclusion with RWlocks and mutexes
//! * Secure memory wiping
//!
//! ## Example
//!
//! ```rust
//! use microkv::MicroKV;
//!
//! let kv: MicroKV = MicroKV::new("example").with_pwd_clear("p@ssw0rd".to_string());
//!
//! // put
//! let value = 123;
//! kv.put("keyname", &value);
//!
//! // get
//! let res: i32 = kv.get_unwrap("keyname").expect("cannot retrieve value");
//! println!("{}", res);
//!
//! // delete
//! kv.delete("keyname").expect("cannot delete key");
//! ```
//!
//! width namespace
//!
//! ```rust
//! use microkv::MicroKV;
//!
//! let kv: MicroKV = MicroKV::new("example").with_pwd_clear("p@ssw0rd".to_string());
//! let namespace_custom = kv.namespace("custom");
//!
//! // put
//! let value = 123;
//! namespace_custom.put("keyname", &value);
//!
//! // get
//! let res: i32 = namespace_custom.get_unwrap("keyname").expect("cannot retrieve value");
//! println!("{}", res);
//!
//! // delete
//! namespace_custom.delete("keyname").expect("cannot delete key");
//! ```
#![allow(clippy::result_map_unit_fn)]

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use indexmap::IndexMap;
use secstr::{SecStr, SecVec};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::hash::sha256;
use sodiumoxide::crypto::secretbox::{self, Nonce};

use crate::errors::{ErrorType, KVError, Result};
use crate::namespace::NamespaceMicrokv;

/// Defines the directory path where a key-value store
/// (or multiple) can be interacted with.
const DEFAULT_WORKSPACE_PATH: &str = ".microkv/";

/// An alias to a base data structure that supports storing
/// associated types. An `IndexMap` is a strong choice due to
/// strong asymptotic performance with sorted key iteration.
type KV = IndexMap<String, SecVec<u8>>;

/// Defines the main interface structure to represent the most
/// recent state of the data store.
#[derive(Clone, Serialize, Deserialize)]
pub struct MicroKV {
    path: PathBuf,

    /// stores the actual key-value store encapsulated with a RwLock
    storage: Arc<RwLock<KV>>,

    /// pseudorandom nonce that can be publicly known
    nonce: Nonce,

    /// memory-guarded hashed password
    #[serde(skip_serializing, skip_deserializing)]
    pwd: Option<SecStr>,

    /// is auto commit
    is_auto_commit: bool,
}

impl MicroKV {
    /// New MicroKV store with store to base path
    pub fn new_with_base_path<S: AsRef<str>>(dbname: S, base_path: PathBuf) -> Self {
        let storage = Arc::new(RwLock::new(KV::new()));

        // no password, until set by `with_pwd_*` methods
        let pwd: Option<SecStr> = None;

        // initialize a new public nonce for symmetric AEAD
        let nonce: Nonce = secretbox::gen_nonce();

        // get abspath to dbname to write to.
        let path = MicroKV::get_db_path_with_base_path(dbname, base_path);

        Self {
            path,
            storage,
            nonce,
            pwd,
            is_auto_commit: false,
        }
    }

    /// Initializes a new empty and unencrypted MicroKV store with
    /// an identifying database name. This is the bare minimum that can operate as a
    /// key-value store, and can be configured using other builder methods.
    pub fn new<S: AsRef<str>>(dbname: S) -> Self {
        let mut path = MicroKV::get_home_dir();
        path.push(DEFAULT_WORKSPACE_PATH);
        Self::new_with_base_path(dbname, path)
    }

    /// Open with base path
    pub fn open_with_base_path<S: AsRef<str>>(dbname: S, base_path: PathBuf) -> Result<Self> {
        // initialize abspath to persistent db
        let path = MicroKV::get_db_path_with_base_path(dbname.as_ref(), base_path.clone());

        if path.is_file() {
            // read kv raw serialized structure to kv_raw
            let mut kv_raw: Vec<u8> = Vec::new();
            File::open(path)?.read_to_end(&mut kv_raw)?;

            // deserialize with bincode and return
            let kv: Self = bincode::deserialize(&kv_raw).unwrap();
            Ok(kv)
        } else {
            Ok(Self::new_with_base_path(dbname, base_path))
        }
    }

    /// Opens a previously instantiated and encrypted MicroKV, given a db name.
    /// The public nonce generated from a previous session is also retrieved in order to
    /// do authenticated encryption later on.
    pub fn open<S: AsRef<str>>(dbname: S) -> Result<Self> {
        let mut path = MicroKV::get_home_dir();
        path.push(DEFAULT_WORKSPACE_PATH);
        Self::open_with_base_path(dbname, path)
    }

    /// Helper that retrieves the home directory by resolving $HOME
    #[inline]
    fn get_home_dir() -> PathBuf {
        dirs::home_dir().unwrap()
    }

    /// Helper that forms an absolute path from a given database name and the default workspace path.
    #[inline]
    pub fn get_db_path<S: AsRef<str>>(name: S) -> PathBuf {
        let mut path = MicroKV::get_home_dir();
        path.push(DEFAULT_WORKSPACE_PATH);
        Self::get_db_path_with_base_path(name, path)
    }

    /// with base path
    #[inline]
    pub fn get_db_path_with_base_path<S: AsRef<str>>(name: S, mut base_path: PathBuf) -> PathBuf {
        base_path.push(name.as_ref());
        base_path.set_extension("kv");
        base_path
    }

    /*
    /// `override_path()` changes the default path for persisting the store, rather than
    /// writing/reading from the default workspace directory.
    pub fn override_path(mut self, path: PathBuf) -> io::Result<Self> {
        self.path = fs::canonicalize(Path::new(&path))?;
        Ok(self)
    }
    */

    /// Builds up the MicroKV with a cleartext password, which is hashed using
    /// the defaultly supported SHA-256 by `sodiumoxide`, in order to instantiate a 32-byte hash.
    ///
    /// Use if the password to encrypt is not naturally pseudorandom and secured in-memory,
    /// and is instead read elsewhere, like a file or stdin (developer should guarentee security when
    /// implementing such methods, as MicroKV only guarentees hashing and secure storage).
    pub fn with_pwd_clear<S: AsRef<str>>(mut self, unsafe_pwd: S) -> Self {
        let pwd: SecStr = SecVec::new(sha256::hash(unsafe_pwd.as_ref().as_bytes()).0.to_vec());
        self.pwd = Some(pwd);
        self
    }

    /// Builds up the MicroKV with a hashed buffer, which is then locked securely `for later use.
    ///
    /// Use if the password to encrypt is generated as a pseudorandom value, or previously hashed by
    /// another preferred one-way function within or outside the application.
    pub fn with_pwd_hash(mut self, _pwd: [u8; 32]) -> Self {
        let pwd: SecStr = SecVec::new(_pwd.to_vec());
        self.pwd = Some(pwd);
        self
    }

    /// Set is auto commit
    pub fn set_auto_commit(mut self, enable: bool) -> Self {
        self.is_auto_commit = enable;
        self
    }

    ///////////////////////////////////////
    // extended
    ///////////////////////////////////////

    pub(crate) fn storage(&self) -> &Arc<RwLock<KV>> {
        &self.storage
    }

    pub(crate) fn is_auto_commit(&self) -> bool {
        self.is_auto_commit
    }

    pub(crate) fn pwd(&self) -> &Option<SecStr> {
        &self.pwd
    }

    pub(crate) fn nonce(&self) -> &Nonce {
        &self.nonce
    }

    pub fn namespace(&self, namespace: impl AsRef<str>) -> NamespaceMicrokv {
        NamespaceMicrokv::new(namespace, self)
    }

    pub fn namespace_default(&self) -> NamespaceMicrokv {
        self.namespace("")
    }

    ///////////////////////////////////////
    // Primitive key-value store operations
    ///////////////////////////////////////

    /// unsafe get, may this api can change name to get_unwrap
    pub fn get_unwrap<V>(&self, key: impl AsRef<str>) -> Result<V>
    where
        V: Serialize + DeserializeOwned + 'static,
    {
        self.namespace_default().get_unwrap(key)
    }

    /// Decrypts and retrieves a value. Can return errors if lock is poisoned,
    /// ciphertext decryption doesn't work, and if parsing bytes fail.
    pub fn get<V>(&self, key: impl AsRef<str>) -> Result<Option<V>>
    where
        V: Serialize + DeserializeOwned + 'static,
    {
        self.namespace_default().get(key)
    }

    /// Encrypts and adds a new key-value pair to storage.
    pub fn put<V>(&self, key: impl AsRef<str>, value: &V) -> Result<()>
    where
        V: Serialize,
    {
        self.namespace_default().put(key, value)
    }

    /// Delete removes an entry in the key value store.
    pub fn delete(&self, key: impl AsRef<str>) -> Result<()> {
        self.namespace_default().delete(key)
    }

    //////////////////////////////////////////
    // Other key-value store helper operations
    //////////////////////////////////////////

    /// Arbitrary read-lock that encapsulates a read-only closure. Multiple concurrent readers
    /// can hold a lock and parse out data.
    pub fn lock_read<C, R>(&self, callback: C) -> Result<R>
    where
        C: Fn(&KV) -> R,
    {
        let data = self.storage.read().map_err(|_| KVError {
            error: ErrorType::PoisonError,
            msg: None,
        })?;
        Ok(callback(&data))
    }

    /// Arbitrary write-lock that encapsulates a write-only closure Single writer can hold a
    /// lock and mutate data, blocking any other readers/writers before the lock is released.
    pub fn lock_write<C, R>(&self, mut callback: C) -> Result<R>
    where
        C: FnMut(&KV) -> R,
    {
        let mut data = self.storage.write().map_err(|_| KVError {
            error: ErrorType::PoisonError,
            msg: None,
        })?;
        Ok(callback(&mut data))
    }

    /// Helper routine that acquires a reader lock and checks if a key exists.
    pub fn exists(&self, key: impl AsRef<str>) -> Result<bool> {
        self.namespace_default().exists(key)
    }

    /// Safely consumes an iterator over the keys in the `IndexMap` and returns a
    /// `Vec<String>` for further use.
    ///
    /// Note that key iteration, not value iteration, is only supported in order to preserve
    /// security guarentees.
    pub fn keys(&self) -> Result<Vec<String>> {
        self.namespace_default().keys()
    }

    /// Safely consumes an iterator over a copy of in-place sorted keys in the
    /// `IndexMap` and returns a `Vec<String>` for further use.
    ///
    /// Note that key iteration, not value iteration, is only supported in order to preserve
    /// security guarentees.
    pub fn sorted_keys(&self) -> Result<Vec<String>> {
        self.namespace_default().sorted_keys()
    }

    /// Empties out the entire underlying `IndexMap` in O(n) time, but does
    /// not delete the persistent storage file from disk. The `IndexMap` remains,
    /// and its capacity is kept the same.
    pub fn clear(&self) -> Result<()> {
        self.namespace_default().clear()
    }

    ///////////////////
    // I/O Operations
    ///////////////////

    /// Writes the IndexMap to persistent storage after encrypting with secure crypto construction.
    pub fn commit(&self) -> Result<()> {
        // initialize workspace directory if not exists
        // let mut workspace_dir = MicroKV::get_home_dir();
        // workspace_dir.push(DEFAULT_WORKSPACE_PATH);
        match self.path.parent() {
            Some(path) => {
                if !path.is_dir() {
                    fs::create_dir_all(path)?;
                }
            }
            None => {
                return Err(KVError {
                    error: ErrorType::FileError,
                    msg: Some("The store file parent path isn't sound".to_string()),
                });
            }
        }

        // check if path to db exists, if not create it
        let path = Path::new(&self.path);
        let mut file: File = OpenOptions::new().write(true).create(true).open(path)?;

        // acquire a file lock that unlocks at the end of scope
        // let _file_lock = Arc::new(Mutex::new(0));
        let ser = bincode::serialize(self).unwrap();
        file.write_all(&ser)?;
        Ok(())
    }

    /// Clears the underlying data structure for the key-value store, and deletes the database file to remove all traces.
    pub fn destruct(&self) -> Result<()> {
        unimplemented!();
    }
}

// coerce a secure zero wipe
impl Drop for MicroKV {
    fn drop(&mut self) {
        if let Some(ref mut pwd) = self.pwd {
            pwd.zero_out()
        }
    }
}
