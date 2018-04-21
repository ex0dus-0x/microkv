extern crate crypto;
extern crate base64;
extern crate serde;

#[macro_use]
extern crate serde_json;
extern crate fs2;

use crypto::digest::Digest;

use serde_json::{Map, Value};

use fs2::FileExt;

use std::path::PathBuf;
use std::io::Write;
use std::fs::OpenOptions;
use std::error::Error;

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::sha2::Sha256;

    #[test]
    fn test_get() {
        let mut t = TinyStore::default();
        t.write(String::from("key1"), json!("a value"));

        match t.get(String::from("key1")){
            Ok(v) => println!("{:?}", v),
            Err(e) => panic!("{:?}", e),
        }
    }

    #[test]
    fn test_encrypted_get() {
        let hash = Sha256::new();
        let mut t = TinyStore::new(None, Some(hash));
        t.write(String::from("key1"), json!("a value"));

        match t.get(String::from("key1")){
            Ok(v) => println!("{:?}", v),
            Err(e) => panic!("{:?}", e),
        }
    }
}

// Rather than using a HashMap, a Map is much more optimized for JSON interactions
type KeyValue = Map<String, Value>;

#[derive(Debug)]
pub enum StoreError {
    KeyNotFound(String),
    SerializeError(String),
    CommitError(String),
    IsEmpty,
    NotFound,
    KeyValueImbalance,
}

pub struct TinyStore<T> {
    path: Option<PathBuf>,          // this is the path where the database file will be written to, if the user chooses to commit
    hash: Option<T>,                // implement a hash algorithm for values that store sensitive data, if the user chooses to
    storage: KeyValue,
}

impl<T: Digest> Default for TinyStore<T> {

    // Set default values for TinyStore struct, if user chooses not to specify custom parameters
    fn default() -> TinyStore<T> {

        TinyStore {
            path: Some(PathBuf::from("./tmp/database.json")),
            hash: None,
            storage: KeyValue::new(),
        }
    }
}


impl<T: Digest> TinyStore<T> {

    // Convert to JSON, then to String
    fn convert_to_string(&mut self) -> Result<String, serde_json::Error> {
        serde_json::to_string(&self.storage).map_err(|err| err)
    }

    // Creates a new TinyStore object without any configuration.
    // Assumes user is utilizing now hashing algorithm and wants to persist data in a file.
    pub fn quick_new() -> TinyStore<T> {
        // Creates a new database utilizing default struct values
        TinyStore::default()
    }

    // Creates a new TinyStore object with configuration supplied by parameters
    pub fn new(path: Option<String>, hash_algo: Option<T>) -> TinyStore<T> {

        // Check if path was supplied
        if let None = path {
            // Create new TinyStore with no path
            TinyStore {
                path: None,
                hash: hash_algo,
                storage: KeyValue::new(),
            }
        } else {
            // Create new TinyStore with path
            TinyStore {
                path: Some(PathBuf::from(path.unwrap())),
                hash: hash_algo,
                storage: KeyValue::new(),
            }
        }
    }

    // Writes to TinyStore key-value container, without commiting to file
    pub fn write(&mut self, key: String, value: Value) -> () {

        if let Some(ref mut hash_algo) = self.hash {
            hash_algo.input(key.as_bytes());
            let _ = self.storage.insert(key, json!(hash_algo.result_str()));
        } else {
            let _ = self.storage.insert(key, value);
        }
    }

    // Retrieves a value from TinyStore with key
    pub fn get(&mut self, id: String) -> Result<Value, StoreError> {

        // Check to see if container contains the key
        if self.storage.contains_key(&id) == false {
            return Err(StoreError::KeyNotFound(id));
        }

        // Retrieve mutable value from key
        let val = self.storage.get_mut(&id)
                        .unwrap();
        Ok(val.take())
    }

    /*
    pub fn get_all(&mut self) -> Result<(), StoreError> {

        // Check if container is empty
        if self.storage.is_empty() == true {
            return Err(StoreError::IsEmpty);
        }

        if self.storage.keys().len() != self.storage.len() && self.storage.values().len() != self.storage.len() {
            return Err(StoreError::KeyValueImbalance)
        }

    }
    */

    pub fn delete(&mut self, id: String) -> Result<(), StoreError> {
        // Check to see if container contains the key
        if self.storage.contains_key(&id) == false {
            return Err(StoreError::KeyNotFound(id));
        }

        // Delete entry
        let _ = self.storage.remove(&id).unwrap();
        Ok(())
    }

    pub fn commit(&mut self) -> Result<(), StoreError> {

        // Create a string from KeyValue container
        let json_data = match self.convert_to_string() {
            Err(e) => {
                let error = String::from(e.description());
                return Err(StoreError::SerializeError(error));
            }
            Ok(data) => data,
        };

        let path = self.path.clone().unwrap();

        // File creation
        let mut target_file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path).unwrap();

        // Ensure mutex lock for one thread write only
        let _ = target_file.lock_exclusive();

        match Write::write_all(&mut target_file, json_data.as_bytes()){
            Err(e) => {
                let error = String::from(e.description());
                return Err(StoreError::CommitError(error));
            },
            Ok(_) => { target_file.unlock(); },
        }

        Ok(())
    }

    /*
    pub fn destruct(self) -> Result<(), StoreError> {
        // Find file path
        // Delete file
    }
    */
}
