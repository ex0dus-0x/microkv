//!
//! lib.rs
//!
//!     main library interface to TinyCollection
//!
extern crate base64;
extern crate crypto;
extern crate fs2;
extern crate serde;

#[macro_use]
extern crate serde_json;

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

use crypto::digest::Digest;
use crypto::sha2::Sha256;

use serde_json::{Map, Value};

use fs2::FileExt;

/// represents various errors encountered
/// during key-value DB interactions.
#[derive(Debug)]
pub enum TinyStoreError {
    KeyNotFound(String),
    SerializeError(String),
    CommitError(String),
    NoPathSupplied,
    IsEmpty,
    NotFound,
    TinyCollectionImbalance,
}

/// represents a key-value type based on serde's Map,
/// rather than the traditional HashMap<K,V>. This makes
/// de/serialization easier while maintaining the same
/// functionality.
type TinyCollection = Map<String, Value>;

/// main interaction object for in-memory key value store
pub struct TinyStore {
    path: Option<PathBuf>,
    hash: bool,
    storage: TinyCollection,
}

/// implement Default trait to automatically create TinyStore
impl Default for TinyStore {
    fn default() -> TinyStore {
        TinyStore {
            path: Some(PathBuf::from("database.json")),
            hash: false,
            storage: TinyCollection::new(),
        }
    }
}

impl TinyStore {
    /// helper that converts to JSON and then to string
    fn convert_to_string(&mut self) -> Result<String, serde_json::Error> {
        let storage = self.storage.clone();
        serde_json::to_string(&storage).map_err(|err| err)
    }

    /// `new` initializes a new TinyStore object with configuration
    /// supplied by various parameters
    pub fn new(path: Option<PathBuf>, hash_algo: bool) -> TinyStore {
        TinyStore {
            path: path,
            hash: hash_algo,
            storage: TinyCollection::new(),
        }
    }

    /// writes to key-value container, but does not commit to DB
    pub fn write(&mut self, key: String, value: Value) -> () {
        if self.hash {
            let mut hash = Sha256::new();
            hash.input(key.as_bytes());
            let _ = self.storage.insert(key, json!(hash.result_str()));
        } else {
            let _ = self.storage.insert(key, value);
        }
    }

    /// retrieves a value using a key `id`.
    pub fn get(&mut self, id: String) -> Result<Value, TinyStoreError> {
        if self.storage.contains_key(&id) == false {
            return Err(TinyStoreError::KeyNotFound(id));
        }

        // Retrieve mutable value from key
        let val = self.storage.get_mut(&id).unwrap();
        Ok(val.clone().take())
    }

    /// deletes an entry in key-value store by ID
    pub fn delete(&mut self, id: String) -> Result<(), TinyStoreError> {
        if self.storage.contains_key(&id) == false {
            return Err(TinyStoreError::KeyNotFound(id));
        }
        let _ = self.storage.remove(&id).unwrap();
        Ok(())
    }

    /// deletes the TinyCollection struct
    pub fn destruct(&mut self) -> () {
        self.storage.clear();
    }

    /// commit the storage structure, creating a JSON file
    pub fn commit(&mut self) -> Result<(), TinyStoreError> {
        if self.path == None {
            return Err(TinyStoreError::NoPathSupplied);
        }

        // create a string from TinyCollection container
        let json_data = match self.convert_to_string() {
            Err(e) => {
                let error = String::from(e.to_string());
                return Err(TinyStoreError::SerializeError(error));
            }
            Ok(data) => data,
        };

        // file creation
        let path = self.path.clone().unwrap();
        let mut target_file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .unwrap();

        // Ensure mutex lock for one thread write only
        let _ = target_file.lock_exclusive();

        match Write::write_all(&mut target_file, json_data.as_bytes()) {
            Err(e) => {
                let error = String::from(e.to_string());
                return Err(TinyStoreError::CommitError(error));
            }
            Ok(_) => {
                let _ = target_file.unlock();
            }
        }

        // Unlock file from mutex
        let _ = target_file.unlock();
        Ok(())
    }
}
