//! kv.rs
//!
//!     Defines the foundational structure and API that will enforce
//!     how the key-value store will be implemented.

use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};

use indexmap::IndexMap;
use secstr::{SecStr, SecVec};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use sodiumoxide::crypto::hash::sha256;
use sodiumoxide::crypto::secretbox::{self, Key, Nonce};

use crate::errors::{ErrorType, KVError, Result};
//use crate::ser::arclock;

/// Defines the directory path where a key-value store
/// (or multiple) can be interacted with.
const DEFAULT_WORKSPACE_PATH: &str = ".microkv/";

/// `KV` represents an alias to a base data structure that
/// supports storing associated types. An `IndexMap` is a strong
/// choice due to strong asymptotic performance with sorted key iteration.
type KV = IndexMap<String, SecVec<u8>>;

/// `MicroKV` defines the main interface structure
/// in order to represent the most recent state of the data
/// store.
#[derive(Serialize, Deserialize)]
pub struct MicroKV {
    path: PathBuf,

    // stores the actual key-value store encapsulated with a RwLock
    storage: Arc<RwLock<KV>>,

    // pseudorandom nonce that can be publicly known
    nonce: Nonce,

    // memory-guarded hashed password
    #[serde(skip_serializing, skip_deserializing)]
    pwd: Option<SecStr>,
}

impl MicroKV {
    /// `new()` initializes a new empty and unencrypted MicroKV store with
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

    /// `open()` opens a previously instantiated and encrypted MicroKV given a db name.
    /// The public nonce generated from a previous session is also retrieved in order to
    /// do authenticated encryption later on.
    pub fn open(dbname: &str) -> io::Result<Self> {
        // initialize abspath to persistent db
        let path = MicroKV::get_db_path(dbname);

        // read kv raw serialized structure to kv_raw
        let mut kv_raw: Vec<u8> = Vec::new();
        File::open(path)?.read_to_end(&mut kv_raw)?;

        // deserialize with bincode and return
        let kv: Self = bincode::deserialize(&kv_raw).unwrap();
        Ok(kv)
    }

    /// `get_home_dir()` is an inlined helper that retrieves the home directory by resolving
    /// $HOME, since `std::env::home_dir()` is depreciated.
    #[inline]
    fn get_home_dir() -> PathBuf {
        PathBuf::from(env::var("HOME").unwrap())
    }

    /// `get_db_path()` is an inlined helper that forms an absolute path from a given database
    /// name and the default workspace path.
    #[inline]
    fn get_db_path(name: &str) -> PathBuf {
        let mut path = PathBuf::from(MicroKV::get_home_dir());
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

    /// `with_pwd_clear()` builds up the MicroKV with a cleartext password, which is hashed using
    /// the defaultly supported SHA-256 by `sodiumoxide`, in order to instantiate a 32-byte hash.
    ///
    /// Ideally, this should be used if the password to encrypt is not naturally pseudorandom
    /// and secured in-memory, and is instead read elsewhere, like a file or stdin (developer
    /// should guarentee security when implementing such methods, as MicroKV only guarentees
    /// hashing and secure storage).
    pub fn with_pwd_clear(mut self, unsafe_pwd: String) -> Self {
        let pwd: SecStr = SecVec::new(sha256::hash(unsafe_pwd.as_bytes()).0.to_vec());
        self.pwd = Some(pwd);
        self
    }

    /// `with_pwd_hash()` builds up the MicroKV with a hashed buffer, which is then locked securely
    /// for later use.
    ///
    /// Ideally, this should be used if the password to encrypt is generated as a pseudorandom
    /// value, or previously hashed by another preferred one-way function within or outside the
    /// application.
    pub fn with_pwd_hash(mut self, _pwd: [u8; 32]) -> Self {
        let pwd: SecStr = SecVec::new(_pwd.to_vec());
        self.pwd = Some(pwd);
        self
    }

    ///////////////////////////////////////
    // Primitive key-value store operations
    ///////////////////////////////////////

    pub fn get<V>(&self, _key: &str) -> Result<V>
    where
        V: DeserializeOwned,
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
                                    msg: Some("cannot derive key from password hash"),
                                });
                            }
                        };

                        // borrow secured value by reference, and decrypt before deserializing
                        match secretbox::open(val.unsecure(), &self.nonce, &key) {
                            Ok(r) => r,
                            Err(_) => {
                                return Err(KVError {
                                    error: ErrorType::CryptoError,
                                    msg: Some("cannot validate value being decrypted"),
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
                    msg: Some("cannot deserialize into specified object type"),
                })?;
                Ok(value)
            }

            None => Err(KVError {
                error: ErrorType::KVError,
                msg: Some("key not found in storage"),
            }),
        }
    }

    /// `put()` adds a new key-value pair to storage. It consumes
    /// a string-type as a key, and any serializable value.
    pub fn put<V>(&self, _key: &str, _value: V) -> Result<()>
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

    /// `delete()` removes an entry in the key value store. Errors if the entry does
    /// not exist or if the database is poisoned.
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


    /// `lock_read()` is an arbitrary read-lock that encapsulates a read-only closure.
    /// This means that multiple concurrent readers can hold a lock and parse out data.
    pub fn lock_read<C, R>(&self, callback: C) -> Result<R>
    where
        C: Fn(&KV) -> R
    {
        let data = self.storage.read().map_err(|_| KVError {
            error: ErrorType::PoisonError,
            msg: None
        })?;
        Ok(callback(&data))
    }


    /// `lock_write()` is an arbitrary write-lock that encapsulates a write-only closure.
    /// This means that only one single writer can hold a lock and mutate data, blocking any
    /// other readers/writers before the lock is released.
    pub fn lock_write<C, R>(&self, mut callback: C) -> Result<R>
    where
        C: FnMut(&KV) -> R
    {
        let mut data = self.storage.write().map_err(|_| KVError {
            error: ErrorType::PoisonError,
            msg: None
        })?;
        Ok(callback(&mut data))
    }


    /// `exists()` is a helper routine that acquires a reader lock and checks if a key exists
    /// within the IndexMap structure.
    pub fn exists<K>(&self, _key: &str) -> Result<bool> {
        let key = String::from(_key);
        let data = self.storage.read().map_err(|_| KVError {
            error: ErrorType::PoisonError,
            msg: None,
        })?;
        Ok(data.contains_key(&key))
    }


    /// `keys()` safely consumes an iterator over the keys in
    /// the IndexMap and returns a Vec for further use.
    ///
    /// Note that key iteration, not value iteration, is only
    /// supported in order to preserve security guarentees.
    pub fn keys(&self) -> Result<Vec<&str>> {
        let lock = self.storage.read().map_err(|_| KVError {
            error: ErrorType::PoisonError,
            msg: None
        })?;
        let data = lock.clone();
        Ok(data.keys()
               .map(|x| x.as_str())
               .collect::<Vec<&str>>())
    }


    pub fn sorted_keys(&self) -> Result<Vec<&str>> {
        unimplemented!()
    }


    pub iter_keys(&self) -> Result<()> {
        unimplemented!()
    }


    pub iter_sorted_keys(&self) -> Result<()> {
        unimplemented!()
    }


    pub fn destroy(&self) -> Result<()> {
        unimplemented!()
    }

    ///////////////////
    // I/O Operations
    ///////////////////

    /// `commit()` writes the IndexMap to a deserializable bincode file for fast persistent storage.
    /// A secure crypto construction is used in order to encrypt information to the store, such
    /// that it can't be read out.
    pub fn commit(&self) -> io::Result<()> {
        // initialize workspace directory if not exists
        let workspace_dir: &Path = Path::new(DEFAULT_WORKSPACE_PATH);
        if !workspace_dir.is_dir() {
            fs::create_dir(DEFAULT_WORKSPACE_PATH)?;
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
}

// coerce a secure zero wipe
impl Drop for MicroKV {
    fn drop(&mut self) -> () {
        match self.pwd {
            Some(ref mut pwd) => pwd.zero_out(),
            None => {}
        }
    }
}
