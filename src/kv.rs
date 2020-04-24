//! kv.rs
//!
//!     Defines the foundational ADT that will enforce
//!     how the key-value store will be structured.

use std::io;
use std::path::PathBuf;
use std::sync::Mutex;
use std::collections::BTreeMap;

use crate::errors::Result;


/// Defines the directory path where a key-value store
/// (or multiple) can be interacted with.
const DEFAULT_WORKSPACE_PATH: &str = "$HOME/.microkv/";


/// TODO: define strong types for key and value
/// `KV` represents an alias to a base data structure that
/// supports storing associated types. A B-tree is a strong
/// choice due to asymptotic performance during interaction.
type KV = BTreeMap<String, String>;


/// `MicroKV` defines the main interface structure
/// in order to represent the most recent state of the data
/// store.
pub struct MicroKV {
    storage: KV,
    path: Option<PathBuf>,
    lock: Mutex<i32>,
}


impl MicroKV {

    pub fn new() -> MicroKV {
        unimplemented!();
    }


    ///////////////////////////////////////
    // Primitive key-value store operations
    ///////////////////////////////////////

    pub fn get<K, V>(&self, key: K) -> Result<V>
    where K: AsRef<str>, V: AsRef<str>
    {
        unimplemented!();
    }

    pub fn put<K, V>(&self, key: K, value: V) -> Result<()>
    where K: AsRef<str>, V: AsRef<str>
    {
        unimplemented!();
    }

    pub fn delete(&self) -> Result<()> {
        unimplemented!();
    }


    ///////////////////
    // I/O Operations
    ///////////////////

    pub fn init_from(path: PathBuf) -> MicroKV {
        unimplemented!();
    }

    pub fn commit(&self) -> io::Result<()> {
        unimplemented!();
    }
}
