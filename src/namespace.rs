use indexmap::IndexMap;
use secstr::SecVec;
use serde::de::DeserializeOwned;
use serde::Serialize;
use sodiumoxide::crypto::secretbox::{self, Key};
use std::borrow::Borrow;

use crate::errors::{ErrorType, KVError, Result};
use crate::MicroKV;

// Debug,
#[derive(Clone)]
pub struct NamespaceMicrokv<'a> {
    /// namespace
    namespace: String,
    /// stores the actual key-value store encapsulated with a RwLock
    microkv: &'a MicroKV,
}

pub fn format_key(namespace: &str, key: impl AsRef<str>) -> String {
    if namespace.is_empty() {
        key.as_ref().to_string()
    } else {
        format!("{}@{}", namespace, key.as_ref())
    }
}

impl<'a> NamespaceMicrokv<'a> {
    pub fn new(namespace: impl AsRef<str>, microkv: &'a MicroKV) -> Self {
        Self {
            namespace: namespace.as_ref().to_string(),
            microkv,
        }
    }
}

impl<'a> NamespaceMicrokv<'a> {
    /// unsafe get, may this api can change name to get_unwrap
    pub fn get_unwrap<V>(&self, key: impl AsRef<str>) -> Result<V>
    where
        V: DeserializeOwned + 'static,
    {
        if let Some(v) = self.get(key)? {
            return Ok(v);
        }
        Err(KVError {
            error: ErrorType::KVError,
            msg: Some("key not found in storage".to_string()),
        })
    }

    /// Decrypts and retrieves a value. Can return errors if lock is poisoned,
    /// ciphertext decryption doesn't work, and if parsing bytes fail.
    pub fn get<V>(&self, key: impl AsRef<str>) -> Result<Option<V>>
    where
        V: DeserializeOwned + 'static,
    {
        self.microkv
            .lock_read(|c| c.kv_get(self.microkv, &self.namespace, &key))?
    }

    /// Encrypts and adds a new key-value pair to storage.
    pub fn put<V>(&self, key: impl AsRef<str>, value: &V) -> Result<()>
    where
        V: Serialize,
    {
        self.microkv
            .lock_write(|c| c.kv_put(self.microkv, &self.namespace, &key, value))
    }

    /// Delete removes an entry in the key value store.
    pub fn delete(&self, key: impl AsRef<str>) -> Result<()> {
        self.microkv
            .lock_write(|c| c.kv_delete(&self.namespace, &key))
    }

    /// Helper routine that acquires a reader lock and checks if a key exists.
    pub fn exists(&self, key: impl AsRef<str>) -> Result<bool> {
        self.microkv
            .lock_read(|c| c.kv_exists(&self.namespace, &key))
    }

    /// Safely consumes an iterator over the keys in the `IndexMap` and returns a
    /// `Vec<String>` for further use.
    ///
    /// Note that key iteration, not value iteration, is only supported in order to preserve
    /// security guarantees.
    pub fn keys(&self) -> Result<Vec<String>> {
        self.microkv.lock_read(|c| {
            c.keys()
                .filter(|x| {
                    if self.namespace.is_empty() {
                        return true;
                    }
                    x.starts_with(&format_key(&self.namespace, ""))
                })
                .map(|x| x.to_string())
                .collect::<Vec<String>>()
        })
    }

    /// Safely consumes an iterator over a copy of in-place sorted keys in the
    /// `IndexMap` and returns a `Vec<String>` for further use.
    ///
    /// Note that key iteration, not value iteration, is only supported in order to preserve
    /// security guarantees.
    pub fn sorted_keys(&self) -> Result<Vec<String>> {
        self.microkv.lock_write(|c| {
            c.sort_keys();
            c.keys()
                .filter(|x| {
                    if self.namespace.is_empty() {
                        return true;
                    }
                    x.starts_with(&format_key(&self.namespace, ""))
                })
                .map(|x| x.to_string())
                .collect::<Vec<String>>()
        })
    }

    /// Empties out the entire underlying `IndexMap` in O(n) time, but does
    /// not delete the persistent storage file from disk. The `IndexMap` remains,
    /// and its capacity is kept the same.
    pub fn clear(&self) -> Result<()> {
        self.microkv.lock_write(|c| {
            // first, iterate over the IndexMap and coerce drop on the secure value wrappers
            c.iter_mut()
                .filter(|(key, _)| {
                    if self.namespace.is_empty() {
                        return true;
                    }
                    key.starts_with(&format_key(&self.namespace, ""))
                })
                .for_each(|(_, value)| value.zero_out());

            // next, clear all entries from the IndexMap
            if self.namespace.is_empty() {
                c.clear();
            } else {
                c.retain(|key, _| !key.starts_with(&format_key(&self.namespace, "")));
            }
        })
    }
}

pub trait ExtendedIndexMap {
    /// An extended version of delete that takes the key and the namespace
    fn kv_delete(&mut self, namespace: impl AsRef<str>, key: impl AsRef<str>);

    /// An extended version of exists that takes the key and the namespace
    fn kv_exists(&self, namespace: impl AsRef<str>, key: impl AsRef<str>) -> bool;

    /// An extended version of get that takes the key and the namespace and properly deserializes the value
    fn kv_get<V>(
        &self,
        microkv: &MicroKV,
        namespace: impl AsRef<str>,
        key: impl AsRef<str>,
    ) -> Result<Option<V>>
    where
        V: DeserializeOwned + 'static;

    /// An extended version of put that takes the key and the namespace and serializes it
    fn kv_put<V>(
        &mut self,
        microkv: &MicroKV,
        namespace: impl AsRef<str>,
        key: impl AsRef<str>,
        value: &V,
    ) where
        V: Serialize;
}

impl ExtendedIndexMap for IndexMap<String, SecVec<u8>> {
    fn kv_delete(&mut self, namespace: impl AsRef<str>, key: impl AsRef<str>) {
        let data_key = format_key(namespace.as_ref(), key);
        self.remove(&data_key);
    }

    fn kv_exists(&self, namespace: impl AsRef<str>, key: impl AsRef<str>) -> bool {
        let data_key = format_key(namespace.as_ref(), key);
        self.contains_key(&data_key)
    }

    fn kv_get<V>(
        &self,
        microkv: &MicroKV,
        namespace: impl AsRef<str>,
        key: impl AsRef<str>,
    ) -> Result<Option<V>>
    where
        V: DeserializeOwned + 'static,
    {
        let data_key = format_key(namespace.as_ref(), key);

        // retrieve value from IndexMap if stored, decrypt and return
        parse_value(microkv, self.get(&data_key))
    }

    fn kv_put<V>(
        &mut self,
        microkv: &MicroKV,
        namespace: impl AsRef<str>,
        key: impl AsRef<str>,
        value: &V,
    ) where
        V: Serialize,
    {
        let data_key = format_key(namespace.as_ref(), key);

        // to retain best-case constant runtime, we remove the key-value if found
        if self.contains_key(&data_key) {
            let _ = self.remove(&data_key).unwrap();
        }

        // serialize the object for committing to db
        let ser_val: Vec<u8> = bincode::serialize(&value).unwrap();

        // encrypt and secure value if password is available
        let value: SecVec<u8> = match microkv.pwd() {
            // encrypt using AEAD and secure memory
            Some(pwd) => {
                let key: Key = Key::from_slice(pwd.unsecure()).unwrap();
                SecVec::new(secretbox::seal(&ser_val, microkv.nonce(), &key))
            }

            // otherwise initialize secure serialized object to insert to BTreeMap
            None => SecVec::new(ser_val),
        };

        self.insert(data_key, value);
    }
}

/// This function takes an optional value of the kv_store and tries to deserialize it if present
fn parse_value<T, V>(microkv: &MicroKV, x: Option<T>) -> Result<Option<V>>
where
    T: Borrow<SecVec<u8>>,
    V: DeserializeOwned + 'static,
{
    match x {
        Some(val) => {
            // get value to deserialize. If password is set, retrieve the value, and decrypt it
            // using AEAD. Otherwise just get the value and return
            let deser_val = match &microkv.pwd() {
                Some(pwd) => {
                    // initialize key from pwd slice
                    let key = match Key::from_slice(pwd.unsecure()) {
                        Some(k) => k,
                        None => {
                            return Err(KVError {
                                error: ErrorType::CryptoError,
                                msg: Some("cannot derive key from password hash".to_string()),
                            });
                        }
                    };

                    // borrow secured value by reference, and decrypt before deserializing
                    match secretbox::open(val.borrow().unsecure(), microkv.nonce(), &key) {
                        Ok(r) => r,
                        Err(_) => {
                            return Err(KVError {
                                error: ErrorType::CryptoError,
                                msg: Some("cannot validate value being decrypted".to_string()),
                            });
                        }
                    }
                }

                // if no password, return value as-is
                None => val.borrow().unsecure().to_vec(),
            };

            // finally deserialize into deserializable object to return as
            let value: V = bincode::deserialize(&deser_val).map_err(|_| KVError {
                error: ErrorType::KVError,
                msg: Some("cannot deserialize into specified object type".to_string()),
            })?;
            Ok(Some(value))
        }

        None => Ok(None),
    }
}
