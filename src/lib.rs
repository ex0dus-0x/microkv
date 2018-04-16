extern crate crypto;
extern crate base64;
extern crate serde;
extern crate serde_json;

use serde::{Serialize, Deserialize};
use serde_json::{Map, Value};

use std::fs;
use std::path::PathBuf;

// Rather than using a HashMap, a Map is much more optimized for JSON interactions
type KeyValue = Map<String, Value>;

pub enum StoreError {
    KeyNotFound(String),
}

pub struct TinyStore {
    path: Option<PathBuf>,          // this is the path where the database file will be written to, if the user chooses to commit
    hash: Option<String>,           // implement a hash algorithm for values that store sensitive data, if the user chooses to
    storage: KeyValue,
}

impl Default for TinyStore {

    // Set default values for TinyStore struct, if user chooses not to specify custom parameters
    fn default() -> TinyStore {

        TinyStore {
            path: Some(PathBuf::from("./tmp/database.json")),
            hash: None,
            storage: KeyValue::new(),
        }
    }
}

impl TinyStore {

    // Creates a new TinyStore object without any configuration.
    // Assumes user is utilizing now hashing algorithm and wants to persist data in a file.
    pub fn quick_new() -> TinyStore {
        // Creates a new database utilizing default struct values
        TinyStore::default()
    }

    // Creates a new TinyStore object with configuration supplied by parameters
    pub fn new(path: Option<String>, hash_algo: Option<String>) -> TinyStore {

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
    pub fn write(&mut self, key: String, value: Value){
        let _ = self.storage.insert(key, value);
        // TODO: implement hash algo
    }

    // Retrieves a value from TinyStore with key
    pub fn get(&mut self, id: String) -> Result<Value, StoreError> {

        // Check to see if container contains the key
        if self.storage.contains_key(&id) == false {
            return Err(StoreError::KeyNotFound(id));
        }

        let val = self.storage.get_mut(&id).unwrap();
        Ok(val.take())
    }

    pub fn get_all(&mut self) -> Result<Vec<KeyValue>, StoreError> {
        // TODO: iterator
    }

    /*
    pub fn delete(self, id: String) -> Result<(), StoreError> {

    }

    pub fn commit(self) -> Result<(), StoreError> {
        // check to see if PathBuf is path to a file, not directory

    }

    pub fn destruct(self) -> Result<(), StoreError> {

    }
    */
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
