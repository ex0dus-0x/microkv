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
//! let res: i32 = kv.get::<i32>("keyname").expect("cannot retrieve value");
//! println!("{}", res);
//!
//! // delete
//! kv.delete("keyname").expect("cannot delete key");
//! ```
#![allow(clippy::result_map_unit_fn)]

use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};

use indexmap::IndexMap;
use secstr::{SecStr, SecVec};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use sodiumoxide::crypto::hash::sha256;
use sodiumoxide::crypto::secretbox::{self, Key, Nonce};

use crate::errors::{ErrorType, KVError, Result};

/// Defines the directory path where a key-value store
/// (or multiple) can be interacted with.
const DEFAULT_WORKSPACE_PATH: &str = ".microkv/";

/// An alias to a base data structure that supports storing
/// associated types. An `IndexMap` is a strong choice due to
/// strong asymptotic performance with sorted key iteration.
type KV = IndexMap<String, SecVec<u8>>;

/// Defines the main interface structure to represent the most
/// recent state of the data store.
#[derive(Serialize, Deserialize)]
pub struct MicroKV {
    path: PathBuf,

    /// stores the actual key-value store encapsulated with a RwLock
    storage: Arc<RwLock<KV>>,

    /// pseudorandom nonce that can be publicly known
    nonce: Nonce,

    /// memory-guarded hashed password
    #[serde(skip_serializing, skip_deserializing)]
    pwd: Option<SecStr>,
}

impl MicroKV {
    /// Initializes a new empty and unencrypted MicroKV store with
    /// an identifying database name. This is the bare minimum that can operate as a
    /// key-value store, and can be configured using other builder methods.
    pub fn new(dbname: &str) -> Self {
        let storage = Arc::new(RwLock::new(KV::new()));

        // no password, until set by `with_pwd_*` methods
        let pwd: Option<SecStr> = None;

        // initialize a new public nonce for symmetric AEAD
        let nonce: Nonce = secretbox::gen_nonce();

        // get abspath to dbname to write to.
        let path = MicroKV::get_db_path(dbname);

        Self {
            path,
            storage,
            pwd,
            nonce,
        }
    }

    /// Opens a previously instantiated and encrypted MicroKV, given a db name.
    /// The public nonce generated from a previous session is also retrieved in order to
    /// do authenticated encryption later on.
    pub fn open(dbname: &str) -> Result<Self> {
        // initialize abspath to persistent db
        let path = MicroKV::get_db_path(dbname);

        // read kv raw serialized structure to kv_raw
        let mut kv_raw: Vec<u8> = Vec::new();
        File::open(path)?.read_to_end(&mut kv_raw)?;

        // deserialize with bincode and return
        let kv: Self = bincode::deserialize(&kv_raw).unwrap();
        Ok(kv)
    }

    /// Helper that retrieves the home directory by resolving $HOME
    #[inline]
    fn get_home_dir() -> PathBuf {
        PathBuf::from(env::var("HOME").unwrap())
    }

    /// Helper that forms an absolute path from a given database name and the default workspace path.
    #[inline]
    pub fn get_db_path(name: &str) -> PathBuf {
        let mut path = MicroKV::get_home_dir();
        path.push(DEFAULT_WORKSPACE_PATH);
        path.push(name);
        path.set_extension("kv");
        path
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
    pub fn with_pwd_clear(mut self, unsafe_pwd: String) -> Self {
        let pwd: SecStr = SecVec::new(sha256::hash(unsafe_pwd.as_bytes()).0.to_vec());
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

    ///////////////////////////////////////
    // Primitive key-value store operations
    ///////////////////////////////////////

    /// Decrypts and retrieves a value. Can return errors if lock is poisoned,
    /// ciphertext decryption doesn't work, and if parsing bytes fail.
    pub fn get<V>(&self, _key: &str) -> Result<V>
    where
        V: DeserializeOwned + 'static,
    {
        let key = String::from(_key);
        let lock = self.storage.read().map_err(|_| KVError {
            error: ErrorType::PoisonError,
            msg: None,
        })?;

        // initialize a copy of state
        let data = lock.clone();

        // retrieve value from IndexMap if stored, decrypt and return
        match data.get(&key) {
            Some(val) => {
                // get value to deserialize. If password is set, retrieve the value, and decrypt it
                // using AEAD. Otherwise just get the value and return
                let deser_val = match &self.pwd {
                    Some(pwd) => {
                        // initialize key from pwd slice
                        let key = match Key::from_slice(pwd.unsecure()) {
                            Some(k) => k,
                            None => {
                                return Err(KVError {
                                    error: ErrorType::CryptoError,
                                    msg: Some("cannot derive key from password hash".to_string()),
                                });
                            }
                        };

                        // borrow secured value by reference, and decrypt before deserializing
                        match secretbox::open(val.unsecure(), &self.nonce, &key) {
                            Ok(r) => r,
                            Err(_) => {
                                return Err(KVError {
                                    error: ErrorType::CryptoError,
                                    msg: Some("cannot validate value being decrypted".to_string()),
                                });
                            }
                        }
                    }

                    // if no password, return value as-is
                    None => val.unsecure().to_vec(),
                };

                // finally deserialize into deserializable object to return as
                let value: V = bincode::deserialize(&deser_val).map_err(|_| KVError {
                    error: ErrorType::KVError,
                    msg: Some("cannot deserialize into specified object type".to_string()),
                })?;
                Ok(value)
            }

            None => Err(KVError {
                error: ErrorType::KVError,
                msg: Some("key not found in storage".to_string()),
            }),
        }
    }

    /// Encrypts and adds a new key-value pair to storage.
    pub fn put<V>(&self, _key: &str, _value: &V) -> Result<()>
    where
        V: Serialize,
    {
        let key = String::from(_key);
        let mut data = self.storage.write().map_err(|_| KVError {
            error: ErrorType::PoisonError,
            msg: None,
        })?;

        // to retain best-case constant runtime, we remove the key-value if found
        if data.contains_key(&key) {
            let _ = data.remove(&key).unwrap();
        }

        // serialize the object for committing to db
        let ser_val: Vec<u8> = bincode::serialize(&_value).unwrap();

        // encrypt and secure value if password is available
        let value: SecVec<u8> = match &self.pwd {
            // encrypt using AEAD and secure memory
            Some(pwd) => {
                let key: Key = Key::from_slice(&pwd.unsecure()).unwrap();
                SecVec::new(secretbox::seal(&ser_val, &self.nonce, &key))
            }

            // otherwise initialize secure serialized object to insert to BTreeMap
            None => SecVec::new(ser_val),
        };
        data.insert(key, value);
        Ok(())
    }

    /// Delete removes an entry in the key value store.
    pub fn delete(&self, _key: &str) -> Result<()> {
        let key = String::from(_key);
        let mut data = self.storage.write().map_err(|_| KVError {
            error: ErrorType::PoisonError,
            msg: None,
        })?;

        // delete entry from BTreeMap by key
        let _ = data.remove(&key);
        Ok(())
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
    pub fn exists(&self, _key: &str) -> Result<bool> {
        let key = String::from(_key);
        let data = self.storage.read().map_err(|_| KVError {
            error: ErrorType::PoisonError,
            msg: None,
        })?;
        Ok(data.contains_key(&key))
    }

    /// Safely consumes an iterator over the keys in the `IndexMap` and returns a
    /// `Vec<String>` for further use.
    ///
    /// Note that key iteration, not value iteration, is only supported in order to preserve
    /// security guarentees.
    pub fn keys(&self) -> Result<Vec<String>> {
        let lock = self.storage.read().map_err(|_| KVError {
            error: ErrorType::PoisonError,
            msg: None,
        })?;

        // initialize a copy to data
        let data = lock.clone();
        let keys = data.keys().map(|x| x.to_string()).collect::<Vec<String>>();
        Ok(keys)
    }

    /// Safely consumes an iterator over a copy of in-place sorted keys in the
    /// `IndexMap` and returns a `Vec<String>` for further use.
    ///
    /// Note that key iteration, not value iteration, is only supported in order to preserve
    /// security guarentees.
    pub fn sorted_keys(&self) -> Result<Vec<String>> {
        let lock = self.storage.read().map_err(|_| KVError {
            error: ErrorType::PoisonError,
            msg: None,
        })?;

        // initialize a copy to data, and sort keys in-place
        let mut data = lock.clone();
        data.sort_keys();
        let keys = data.keys().map(|x| x.to_string()).collect::<Vec<String>>();
        Ok(keys)
    }

    /// Empties out the entire underlying `IndexMap` in O(n) time, but does
    /// not delete the persistent storage file from disk. The `IndexMap` remains,
    /// and its capacity is kept the same.
    pub fn clear(&self) -> Result<()> {
        let mut data = self.storage.write().map_err(|_| KVError {
            error: ErrorType::PoisonError,
            msg: None,
        })?;

        // first, iterate over the IndexMap and coerce drop on the secure value wrappers
        for (_, value) in data.iter_mut() {
            value.zero_out();
        }

        // next, clear all entries from the IndexMap
        data.clear();
        Ok(())
    }

    ///////////////////
    // I/O Operations
    ///////////////////

    /// Writes the IndexMap to persistent storage after encrypting with secure crypto construction.
    pub fn commit(&self) -> Result<()> {
        // initialize workspace directory if not exists
        let mut workspace_dir = MicroKV::get_home_dir();
        workspace_dir.push(DEFAULT_WORKSPACE_PATH);
        if !workspace_dir.is_dir() {
            fs::create_dir(workspace_dir)?;
        }

        // check if path to db exists, if not create it
        let path = Path::new(&self.path);
        let mut file: File = OpenOptions::new().write(true).create(true).open(path)?;

        // acquire a file lock that unlocks at the end of scope
        let _file_lock = Arc::new(Mutex::new(0));
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
