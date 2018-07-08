extern crate crypto;
extern crate base64;
extern crate serde;

#[macro_use]
extern crate serde_json;
extern crate fs2;

use crypto::digest::Digest;
use crypto::sha2::Sha256;

use serde_json::{Map, Value};

use fs2::FileExt;

use std::path::PathBuf;
use std::fs::OpenOptions;
use std::error::Error;
use std::io::Write;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get() {

        // Create a new TinyStore object, with default values
        let mut t = TinyStore::quick_new();

        // Add keys and values
        t.write(String::from("key1"), json!("a value"));
        t.write(String::from("key2"), json!("another value"));
        t.write(String::from("key3"), json!("a third value"));

        // Test retrieval of item
        match t.get(String::from("key1")){
            Ok(v) => println!("{:?}", v),
            Err(e) => panic!("{:?}", e),
        }

        // Write changes
        let _ = t.commit();
    }

    #[test]
    fn test_encrypted_get() {
        let mut t = TinyStore::new(None, true);
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
    NoPathSupplied,
    IsEmpty,
    NotFound,
    KeyValueImbalance,
}


pub struct TinyStore {
    path: Option<PathBuf>,          // this is the path where the database file will be written to, if the user chooses to commit
    hash: bool,                     // implement a hash algorithm for values that store sensitive data, if the user chooses to
    storage: KeyValue,              // represents where we will be
}


impl Default for TinyStore {

    // Set default values for TinyStore struct, if user chooses not to specify custom parameters
    fn default() -> TinyStore {

        TinyStore {
            path: Some(PathBuf::from("database.json")),
            hash: false,
            storage: KeyValue::new(),
        }
    }
}


impl TinyStore {

    // Convert to JSON, then to String
    fn convert_to_string(&mut self) -> Result<String, serde_json::Error> {
        let storage = self.storage.clone();
        serde_json::to_string(&storage).map_err(|err| err)
    }


    // Creates a new TinyStore object without any configuration.
    // This is optimal for the user that wishes to hash preemptively before interacting with container
    pub fn quick_new() -> TinyStore {

        // Creates a new database utilizing default struct values
        TinyStore::default()
    }


    // Creates a new TinyStore object with configuration supplied by parameters
    pub fn new(path: Option<String>, hash_algo: bool) -> TinyStore {

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

        if let true = self.hash {
            let mut hash = Sha256::new();
            hash.input(key.as_bytes());
            let _ = self.storage.insert(key, json!(hash.result_str()));
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

        // Return clone of value, to prevent moving
        Ok(val.clone().take())
    }


    pub fn get_all(&mut self) -> Result<KeyValue, StoreError> {

        // Check if container is empty
        if self.storage.is_empty() == true {
            return Err(StoreError::IsEmpty);
        }

        // Check if container has imbalance in keys and values
        if (self.storage.keys().len() != self.storage.len()) && (self.storage.values().len() != self.storage.len()) {
            return Err(StoreError::KeyValueImbalance)
        }

        Ok(self.storage.clone())
    }


    // Deletes an entry in key-value store by ID
    pub fn delete(&mut self, id: String) -> Result<(), StoreError> {

        // Check to see if container contains the key
        if self.storage.contains_key(&id) == false {
            return Err(StoreError::KeyNotFound(id));
        }

        // Delete entry in container by ID
        let _ = self.storage.remove(&id).unwrap();
        Ok(())
    }


    // Delete the storage structure
    pub fn destruct(&mut self) -> () {
        self.storage.clear();
    }


    // Commit the storage structure, creating a JSON file
    pub fn commit(&mut self) -> Result<(), StoreError> {

        // Check if container has path
        if self.path == None {
            return Err(StoreError::NoPathSupplied);
        }

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
            Ok(_) => { let _ = target_file.unlock(); },
        }

        // Unlock file from mutex
        let _ = target_file.unlock();

        Ok(())
    }
}
