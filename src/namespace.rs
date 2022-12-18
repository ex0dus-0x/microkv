use indexmap::IndexMap;
use secstr::SecVec;
use serde::de::DeserializeOwned;
use serde::Serialize;
use sodiumoxide::crypto::secretbox::{self, Key};

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

fn format_key(namespace: &str, key: impl AsRef<str>) -> String {
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
        let lock = self.microkv.storage().read().map_err(|_| KVError {
            error: ErrorType::PoisonError,
            msg: None,
        })?;

        // initialize a copy of state
        let data = lock.clone();
        data.kv_get(self.microkv, &self.namespace, key)
    }

    /// Encrypts and adds a new key-value pair to storage.
    pub fn put<V>(&self, key: impl AsRef<str>, value: &V) -> Result<()>
    where
        V: Serialize,
    {
        let mut data = self.microkv.storage().write().map_err(|_| KVError {
            error: ErrorType::PoisonError,
            msg: None,
        })?;

        data.kv_put(self.microkv, &self.namespace, key, value);

        if !self.microkv.is_auto_commit() {
            return Ok(());
        }
        drop(data);
        self.microkv.commit()
    }

    /// Delete removes an entry in the key value store.
    pub fn delete(&self, key: impl AsRef<str>) -> Result<()> {
        let data_key = format_key(&self.namespace, key);
        let mut data = self.microkv.storage().write().map_err(|_| KVError {
            error: ErrorType::PoisonError,
            msg: None,
        })?;

        // delete entry from BTreeMap by key
        let _ = data.remove(&data_key);

        if !self.microkv.is_auto_commit() {
            return Ok(());
        }
        drop(data);
        self.microkv.commit()
    }

    /// Helper routine that acquires a reader lock and checks if a key exists.
    pub fn exists(&self, key: impl AsRef<str>) -> Result<bool> {
        let data_key = format_key(&self.namespace, key);
        let data = self.microkv.storage().read().map_err(|_| KVError {
            error: ErrorType::PoisonError,
            msg: None,
        })?;
        Ok(data.contains_key(&data_key))
    }

    /// Safely consumes an iterator over the keys in the `IndexMap` and returns a
    /// `Vec<String>` for further use.
    ///
    /// Note that key iteration, not value iteration, is only supported in order to preserve
    /// security guarentees.
    pub fn keys(&self) -> Result<Vec<String>> {
        let lock = self.microkv.storage().read().map_err(|_| KVError {
            error: ErrorType::PoisonError,
            msg: None,
        })?;

        // initialize a copy to data
        let data = lock.clone();
        let keys = data
            .keys()
            .filter(|x| {
                if self.namespace.is_empty() {
                    return true;
                }
                x.starts_with(&format_key(&self.namespace, ""))
            })
            .map(|x| x.to_string())
            .collect::<Vec<String>>();
        Ok(keys)
    }

    /// Safely consumes an iterator over a copy of in-place sorted keys in the
    /// `IndexMap` and returns a `Vec<String>` for further use.
    ///
    /// Note that key iteration, not value iteration, is only supported in order to preserve
    /// security guarentees.
    pub fn sorted_keys(&self) -> Result<Vec<String>> {
        let lock = self.microkv.storage().read().map_err(|_| KVError {
            error: ErrorType::PoisonError,
            msg: None,
        })?;

        // initialize a copy to data, and sort keys in-place
        let mut data = lock.clone();
        data.sort_keys();
        let keys = data
            .keys()
            .filter(|x| {
                if self.namespace.is_empty() {
                    return true;
                }
                x.starts_with(&format_key(&self.namespace, ""))
            })
            .map(|x| x.to_string())
            .collect::<Vec<String>>();
        Ok(keys)
    }

    /// Empties out the entire underlying `IndexMap` in O(n) time, but does
    /// not delete the persistent storage file from disk. The `IndexMap` remains,
    /// and its capacity is kept the same.
    pub fn clear(&self) -> Result<()> {
        let mut data = self.microkv.storage().write().map_err(|_| KVError {
            error: ErrorType::PoisonError,
            msg: None,
        })?;

        // first, iterate over the IndexMap and coerce drop on the secure value wrappers
        data.iter_mut()
            .filter(|(key, _)| {
                if self.namespace.is_empty() {
                    return true;
                }
                key.starts_with(&format_key(&self.namespace, ""))
            })
            .for_each(|(_, value)| value.zero_out());

        // next, clear all entries from the IndexMap
        if self.namespace.is_empty() {
            data.clear();
        } else {
            data.retain(|key, _| !key.starts_with(&format_key(&self.namespace, "")));
        }

        // auto commit
        if !self.microkv.is_auto_commit() {
            return Ok(());
        }
        self.microkv.commit()
    }
}

pub trait ExtendedIndexMap {
    /// An extended version of put that takes the key and the namespace and serializes it
    fn kv_put<V>(&mut self, microkv: &MicroKV, namespace: impl AsRef<str>, key: impl AsRef<str>, value: &V) where V: Serialize;

    /// An extended version of get that takes the key and the namespace and properly deserializes the value
    fn kv_get<V>(&self, microkv: &MicroKV, namespace: impl AsRef<str>, key: impl AsRef<str>) -> Result<Option<V>> where V: DeserializeOwned + 'static;
}

impl ExtendedIndexMap for IndexMap<String, SecVec<u8>> {
    fn kv_put<V>(&mut self, microkv: &MicroKV, namespace: impl AsRef<str>, key: impl AsRef<str>, value: &V) where V: Serialize {
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

    fn kv_get<V>(&self, microkv: &MicroKV, namespace: impl AsRef<str>, key: impl AsRef<str>) -> Result<Option<V>> where V: DeserializeOwned + 'static {
        let data_key = format_key(namespace.as_ref(), key);

        // retrieve value from IndexMap if stored, decrypt and return
        match self.get(&data_key) {
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
                        match secretbox::open(val.unsecure(), microkv.nonce(), &key) {
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
                    None => val.unsecure().to_vec(),
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
}