extern crate crypto;
extern crate base64;
extern crate serde;
extern crate serde_json;

use serde::{Serialize, Deserialize};
use serde_json::{Map, Value};

use std::fs;
use std::path::PathBuf;

enum StoreError {
    TinyStoreNew(String),
}

pub struct TinyStore {
    path: Option<PathBuf>,           // this is the path where the database file will be written to, if the user chooses to commit
    hash: Option<String>,           // implement a hash algorithm for values that store sensitive data
}

impl Default for TinyStore {

    // Set default values for TinyStore struct, if user chooses not to specify custom parameters
    fn default() -> TinyStore {        

        TinyStore {
            path: Some(PathBuf::from("./tmp/database.json")),
            hash: None,
        }
    }
}

impl TinyStore {

    pub fn quick_new() -> TinyStore {
        // Creates a new database utilizing default struct values
        TinyStore::default()
    }

    pub fn new(path: Option<String>, hash_algo: Option<String>) -> TinyStore {
        
        // Check if path was supplied 
        if let None = path {
            
            // Create new TinyStore with no path
            TinyStore {
                path: None,
                hash: hash_algo,
            }
        } else {

            // Create new TinyStore with path
            TinyStore {
                path: Some(PathBuf::from(path.unwrap())),
                hash: hash_algo,
            }
        }
    }
    
    /*
    pub fn write<T: Serialize>(self, id: &T) -> Result<(), StoreError> {

    }

    pub fn get(self, id: String) -> Result<(), StoreError> {

    }

    pub fn get_all(self) -> Result<String, StoreError> {

    }
    
    pub fn delete(self, id: String) -> Result<(), StoreError> {

    }
    
    pub fn commit(self) -> Result<(), StoreError> {


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
