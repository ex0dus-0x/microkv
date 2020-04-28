//! kv.rs
//!
//!     Defines the foundational structure and API that will enforce
//!     how the key-value store will be implemented.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::errors::{ErrorType, KVError, Result};

use serde::de::DeserializeOwned;
use serde::{Serialize, Deserialize};

use secstr::{SecStr, SecVec};

use sodiumoxide::crypto::hash::sha256;
use sodiumoxide::crypto::secretbox::{self, Key, Nonce};


/// Defines the directory path where a key-value store
/// (or multiple) can be interacted with.
const DEFAULT_WORKSPACE_PATH: &str = "$HOME/.microkv/";

/// `KV` represents an alias to a base data structure that
/// supports storing associated types. A B-tree is a strong
/// choice due to asymptotic performance during interaction.
type KV = BTreeMap<String, SecVec<u8>>;

/// `MicroKV` defines the main interface structure
/// in order to represent the most recent state of the data
/// store.
#[derive(Serialize, Deserialize)]
pub struct MicroKV {
    path: PathBuf,

    // stores the actual key-value store encapsulated with a Mutex
    storage: Mutex<KV>,

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
    pub fn new(dbname: String) -> Self {
        let storage = Mutex::new(KV::new());

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
            nonce
        }
    }

    /// `open()` opens a previously instantiated and encrypted MicroKV given a db name.
    /// The public nonce generated from a previous session is also retrieved in order to
    /// do authenticated encryption later on.
    pub fn open(dbname: String) -> io::Result<Self> {
        let path = MicroKV::get_db_path(dbname);
        unimplemented!();
    }


    /// `get_db_path()` is an inlined helper that forms an absolute path from a given database
    /// name and the default workspace path.
    #[inline]
    fn get_db_path(name: String) -> PathBuf {
        let mut path = PathBuf::from(DEFAULT_WORKSPACE_PATH);
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
    /// should guarentee security when implementing such methods, as MicroKV only guarentees secure
    /// storage).
    pub fn with_pwd_clear(mut self, unsafe_pwd: String) -> Self {
        let pwd: SecStr = SecVec::new(
            sha256::hash(unsafe_pwd.as_bytes()).0.to_vec()
        );
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
        let lock = self.storage.lock().map_err(|e| KVError {
            error: ErrorType::PoisonError,
            msg: None,
        })?;

        // check if key exists in store
        let data = lock.clone();

        // retrieve value from BTreeMap if stored, decrypt and return
        match data.get(&key) {
            Some(mut val) => {

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
                                    msg: Some("cannot derive key from password hash")
                                });
                            }
                        };

                        // borrow secured value by reference, and decrypt before deserializing
                        match secretbox::open(val.unsecure(), &self.nonce, &key) {
                            Ok(r) => r,
                            Err(_) => {
                                return Err(KVError {
                                    error: ErrorType::CryptoError,
                                    msg: Some("cannot validate value being decrypted")
                                });
                            }
                        }
                   },
                   None => val.unsecure().to_vec()
                };

                // finally deserialize into deserializable object to return as
                let value: V = bincode::deserialize(&deser_val).map_err(|e| {
                    KVError {
                        error: ErrorType::KVError,
                        msg: Some("cannot deserialize into specified object type")
                    }
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
    /// a string-type as a key, and any serializable
    pub fn put<K, V>(&self, _key: &str, _value: V) -> Result<()>
    where
        V: Serialize,
    {
        let key = String::from(_key);
        let mut data = self.storage.lock().map_err(|_| KVError {
            error: ErrorType::PoisonError,
            msg: None,
        })?;

        // check if key exists in store, and remove the entry
        if data.contains_key(&key) {
            let _ = data.remove(&key).unwrap();
        }

        // TODO: encrypt value if password if available

        // initialize secure serialized object and insert to BTreeMap
        let value: SecVec<u8> = SecVec::new(bincode::serialize(&_value).unwrap());
        data.insert(key, value);
        Ok(())
    }

    /// `delete()` removes an entry in the key value store. Errors if the entry does
    /// not exist or if the database is poisoned.
    pub fn delete(&self, _key: &str) -> Result<()> {
        let key = String::from(_key);
        let mut data = self.storage.lock().map_err(|_| KVError {
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

    pub fn exists<K>(&self, _key: &str) -> Result<bool> {
        let key = String::from(_key);
        let data = self.storage.lock().map_err(|_| KVError {
            error: ErrorType::PoisonError,
            msg: None,
        })?;
        Ok(data.contains_key(&key))
    }

    // TODO: get iterator of key, values, (keys + values),
    // TODO: clear all

    ///////////////////
    // I/O Operations
    ///////////////////

    /// `commit()` writes the BTreeMap to a deserializable bincode file for persistent storage.
    /// A secure crypto construction is used in order to encrypt information to the store, and
    pub fn commit(&self) -> io::Result<()> {

        // initialize workspace directory if not exists
        let workspace_dir: &Path = Path::new(DEFAULT_WORKSPACE_PATH);
        if !workspace_dir.is_dir() {
            fs::create_dir(DEFAULT_WORKSPACE_PATH)?;
        }
        Ok(())
    }
}

impl Drop for MicroKV {
    fn drop(&mut self) -> () {
        match self.pwd {
            Some(ref mut pwd) => {
                pwd.zero_out()
            }
            None => {}
        }
    }
}
