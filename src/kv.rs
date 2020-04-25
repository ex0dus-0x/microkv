//! kv.rs
//!
//!     Defines the foundational structure and API that will enforce
//!     how the key-value store will be implemented.

use std::io;
use std::path::PathBuf;
use std::sync::Mutex;
use std::collections::BTreeMap;

use crate::errors::{KVError, ErrorType, Result};

use serde::Serialize;


/// Defines the directory path where a key-value store
/// (or multiple) can be interacted with.
const DEFAULT_WORKSPACE_PATH: &str = "$HOME/.microkv/";


/// `KV` represents an alias to a base data structure that
/// supports storing associated types. A B-tree is a strong
/// choice due to asymptotic performance during interaction.
type KV = BTreeMap<String, Vec<u8>>;


/// `MicroKV` defines the main interface structure
/// in order to represent the most recent state of the data
/// store.
pub struct MicroKV {
    dbname: String,
    storage: Mutex<KV>,
    symmetric_key: Option<String>
}


impl MicroKV {


    /// `new()` initializes a new MicroKV store.
    pub fn new(dbname: String, safe_pwd: Option<String>) -> MicroKV {

        // initialize the BTreeMap
        let storage = KV::new();

        // assume pwd was previously securely constructed
        MicroKV { dbname, storage, symmetric_key }
    }


    /// `read_pwd()` securely reads in a cleartext password for use with the
    /// cryptographic construction. This uses `secretstr` in order to protect the
    /// in-memory page with `mlock`.
    pub fn read_pwd(self) -> Result<Self> {
        if let Some(_) = symmetric_key {
            return Err(KVError {
                e: ErrorType::DBError,
                msg: "symmetric key already exists"
            });
        }

        Ok(self)
    }


    ///////////////////////////////////////
    // Primitive key-value store operations
    ///////////////////////////////////////

    pub fn get<K, V>(&self, key: K) -> Result<V>
    where K: AsRef<str>, V: Serialize
    {
        let mut lock = self.storage.lock().map_err(|e| {
            KVError {
                error: ErrorType::PoisonError,
                msg: None
            }
        })?;

        let data = lock.clone();
        if !data.contains_key(&key) {
            return Err(KVError {
                error: ErrorType::KeyError,
                msg: Some("key not found in storage")
            });
        }
        self.storage.lock();
        unimplemented!();
    }

    /// `put` adds a new key-value pair to storage. It consumes
    /// a string-type as a key, and any serializable
    pub fn put<K, V>(&self, key: K, value: V) -> Result<()>
    where K: AsRef<str>, V: Serialize
    {
        unimplemented!();
    }

    pub fn delete(&self) -> Result<()> {
        unimplemented!();
    }


    //////////////////////////////////////////
    // Other key-value store helper operations
    //////////////////////////////////////////

    pub fn exists<K>(&self, key: K) -> bool
    where K: AsRef<str>
    {
        true
    }




    ///////////////////
    // I/O Operations
    ///////////////////

    pub fn init_from(path: PathBuf) -> MicroKV {
        unimplemented!();
    }


    /// `commit()` writes the BTreeMap to a deserializable bincode file for persistent storage.
    /// A secure crypto construction is used in order to encrypt information to the store, and
    pub fn commit(&self) -> io::Result<()> {

        // initialize workspace directory if not exists
        let workspace_dir: Path = Path::new(DEFAULT_WORKSPACE_PATH);
        if !workspace_dir.is_dir() {
            fs::create_dir(DEFAULT_WORKSPACE_PATH)?;
        }

        // get name if specified, otherwise
        let dbname: String = match self.dbname {
            Some(name) => name,
            None => {

            }
        };

    }
}
