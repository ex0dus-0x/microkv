//! [`Txn`]: the context passed to [`MicroKV::transaction`](crate::MicroKV::transaction).
//!
//! Operations apply to a working copy of the store held under a single write lock;
//! namespaces are addressed explicitly (pass `""` for the default namespace).

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::error::{Error, Result};
use crate::format::Store;
use crate::store::{fetch, remove_from, seal_into, MicroKV};

/// A batch of operations applied atomically by `MicroKV::transaction`.
pub struct Txn<'a> {
    store: &'a mut Store,
    db: &'a MicroKV,
}

impl<'a> Txn<'a> {
    pub(crate) fn new(store: &'a mut Store, db: &'a MicroKV) -> Self {
        Self { store, db }
    }

    pub fn get<V: DeserializeOwned>(&self, ns: &str, key: &str) -> Result<Option<V>> {
        match fetch(self.store, ns, key) {
            Some(e) => self.db.inner.read_value(ns, key, &e),
            None => Ok(None),
        }
    }

    pub fn require<V: DeserializeOwned>(&self, ns: &str, key: &str) -> Result<V> {
        self.get(ns, key)?.ok_or(Error::NotFound)
    }

    pub fn put<V: Serialize>(&mut self, ns: &str, key: &str, value: &V) -> Result<()> {
        seal_into(&self.db.inner, self.store, ns, key, value, None)
    }

    pub fn remove(&mut self, ns: &str, key: &str) -> Result<bool> {
        Ok(remove_from(self.store, ns, key))
    }
}
