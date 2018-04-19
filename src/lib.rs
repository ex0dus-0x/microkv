extern crate crypto;
extern crate base64;
extern crate serde;
extern crate serde_json;
extern crate fs2;

use crypto::digest::Digest;

use serde::{Serialize, Deserialize};
use serde_json::{Map, Value};

use fs2::FileExt;

use std::path::PathBuf;
use std::io::Write;
use std::fs::OpenOptions;

#[cfg(test)]
mod tests {
    use super::TinyStore;

    #[test]
    fn it_works() {
        let mut t = TinyStore::new(None, None);
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
    CommitError,
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
    fn convert_to_string(&mut self){
        
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

        // Retrieve mutable value from key
        let val = self.storage.get_mut(&id).unwrap();
        Ok(val.take())
    }

    pub fn get_all(&mut self) -> Result<Vec<KeyValue>, StoreError> {

    }

    pub fn delete(self, id: String) -> Result<(), StoreError> {

    }

    pub fn commit(&self) -> Result<(), StoreError> {

        // Create a string from KeyValue container
        let json_data = self.convert_to_string();

        // File creation
        let target_file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&self.path.unwrap()).unwrap();

        // Ensure mutex lock for one thread write only
        target_file.lock_exclusive();

        match Write::write_all(&mut target_file, json_data.as_bytes()){
            Err(e) => Err(StoreError::CommitError),
            Ok(_) => target_file.unlock(),
        }

        Ok(())
    }

    pub fn destruct(self) -> Result<(), StoreError> {
        // Find file path
        // Delete file
    }
}
