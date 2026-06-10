//! [`Tree`]: the per-namespace key-value API. Every read/write op lives here; the
//! `MicroKV` convenience methods just forward to the default namespace's tree.

use std::ops::ControlFlow;
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::codec::encode;
use crate::error::{Error, Result};
use crate::format::{Entry, Store};
use crate::secret::Secret;
use crate::store::{fetch, remove_from, seal_into, MicroKV};

/// A handle to a single namespace within a [`MicroKV`] store.
#[derive(Clone)]
pub struct Tree {
    db: MicroKV,
    name: String,
}

impl Tree {
    pub(crate) fn new(db: MicroKV, name: String) -> Self {
        Self { db, name }
    }

    /// The namespace name (`""` for the default namespace).
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn get<V: DeserializeOwned>(&self, key: &str) -> Result<Option<V>> {
        let entry = {
            let g = self.db.inner.read_store()?;
            fetch(&g, &self.name, key)
        };
        match entry {
            Some(e) => self.db.inner.read_value(&self.name, key, &e),
            None => Ok(None),
        }
    }

    pub fn require<V: DeserializeOwned>(&self, key: &str) -> Result<V> {
        self.get(key)?.ok_or(Error::NotFound)
    }

    /// Like [`Tree::get`] but wraps the result in a non-logging [`Secret`].
    pub fn get_secret<V: DeserializeOwned>(&self, key: &str) -> Result<Option<Secret<V>>> {
        Ok(self.get::<V>(key)?.map(Secret::new))
    }

    pub fn put<V: Serialize>(&self, key: &str, value: &V) -> Result<()> {
        self.put_inner(key, value, None)
    }

    pub fn put_with_ttl<V: Serialize>(&self, key: &str, value: &V, ttl: Duration) -> Result<()> {
        self.put_inner(key, value, Some(ttl))
    }

    fn put_inner<V: Serialize>(&self, key: &str, value: &V, ttl: Option<Duration>) -> Result<()> {
        self.db.ensure_writable()?;
        {
            let mut g = self.db.inner.write_store()?;
            seal_into(&self.db.inner, &mut g, &self.name, key, value, ttl)?;
        }
        self.db.after_write()
    }

    pub fn remove(&self, key: &str) -> Result<bool> {
        self.db.ensure_writable()?;
        let existed = {
            let mut g = self.db.inner.write_store()?;
            remove_from(&mut g, &self.name, key)
        };
        self.db.after_write()?;
        Ok(existed)
    }

    pub fn contains(&self, key: &str) -> Result<bool> {
        let entry = {
            let g = self.db.inner.read_store()?;
            fetch(&g, &self.name, key)
        };
        match entry {
            Some(e) => self.db.inner.is_live(&self.name, key, &e),
            None => Ok(false),
        }
    }

    pub fn len(&self) -> Result<usize> {
        let mut n = 0;
        for (k, e) in self.snapshot_entries(|_| true)? {
            if self.db.inner.is_live(&self.name, &k, &e)? {
                n += 1;
            }
        }
        Ok(n)
    }

    pub fn is_empty(&self) -> Result<bool> {
        Ok(self.len()? == 0)
    }

    /// Atomic read-modify-write under a single write lock. The closure receives the
    /// current value (if any) and returns the next value (`None` removes the key).
    pub fn update<V, F>(&self, key: &str, f: F) -> Result<()>
    where
        V: Serialize + DeserializeOwned,
        F: FnOnce(Option<V>) -> Option<V>,
    {
        self.db.ensure_writable()?;
        {
            let mut g = self.db.inner.write_store()?;
            let current = self.load::<V>(&g, key)?;
            match f(current) {
                Some(v) => seal_into(&self.db.inner, &mut g, &self.name, key, &v, None)?,
                None => {
                    remove_from(&mut g, &self.name, key);
                }
            }
        }
        self.db.after_write()
    }

    /// Return the value for `key`, inserting and returning `f()` if it is absent.
    pub fn get_or_insert_with<V, F>(&self, key: &str, f: F) -> Result<V>
    where
        V: Serialize + DeserializeOwned,
        F: FnOnce() -> V,
    {
        self.db.ensure_writable()?;
        let (value, wrote) = {
            let mut g = self.db.inner.write_store()?;
            match self.load::<V>(&g, key)? {
                Some(v) => (v, false),
                None => {
                    let v = f();
                    seal_into(&self.db.inner, &mut g, &self.name, key, &v, None)?;
                    (v, true)
                }
            }
        };
        if wrote {
            self.db.after_write()?;
        }
        Ok(value)
    }

    /// Set `key` to `new` only if its current value equals `expected` (compared by
    /// serialized form). Returns whether the swap happened.
    pub fn compare_and_swap<V: Serialize + DeserializeOwned>(
        &self,
        key: &str,
        expected: Option<&V>,
        new: Option<&V>,
    ) -> Result<bool> {
        self.db.ensure_writable()?;
        let swapped = {
            let mut g = self.db.inner.write_store()?;
            let current_bytes = match fetch(&g, &self.name, key) {
                Some(e) => self.db.inner.open_entry(&self.name, key, &e)?,
                None => None,
            };
            let expected_bytes = match expected {
                Some(v) => Some(encode(v)?),
                None => None,
            };

            if current_bytes == expected_bytes {
                match new {
                    Some(v) => seal_into(&self.db.inner, &mut g, &self.name, key, v, None)?,
                    None => {
                        remove_from(&mut g, &self.name, key);
                    }
                }
                true
            } else {
                false
            }
        };
        if swapped {
            self.db.after_write()?;
        }
        Ok(swapped)
    }

    /// Keys present in this namespace (expired entries excluded).
    pub fn keys(&self) -> Result<Vec<String>> {
        let mut out = Vec::new();
        for (k, e) in self.snapshot_entries(|_| true)? {
            if self.db.inner.is_live(&self.name, &k, &e)? {
                out.push(k);
            }
        }
        Ok(out)
    }

    /// Keys in sorted order.
    pub fn keys_sorted(&self) -> Result<Vec<String>> {
        let mut keys = self.keys()?;
        keys.sort();
        Ok(keys)
    }

    /// Decrypt and return all entries whose key starts with `prefix`.
    pub fn prefix<V: DeserializeOwned>(&self, prefix: &str) -> Result<Vec<(String, V)>> {
        let mut out = Vec::new();
        for (k, e) in self.snapshot_entries(|key| key.starts_with(prefix))? {
            if let Some(v) = self.db.inner.read_value::<V>(&self.name, &k, &e)? {
                out.push((k, v));
            }
        }
        Ok(out)
    }

    /// Visit every (non-expired) entry; return `ControlFlow::Break` to stop early.
    pub fn for_each<V, F>(&self, mut f: F) -> Result<()>
    where
        V: DeserializeOwned,
        F: FnMut(&str, V) -> ControlFlow<()>,
    {
        for (k, e) in self.snapshot_entries(|_| true)? {
            if let Some(v) = self.db.inner.read_value::<V>(&self.name, &k, &e)? {
                if let ControlFlow::Break(()) = f(&k, v) {
                    break;
                }
            }
        }
        Ok(())
    }

    /// Remove every entry in this namespace.
    pub fn clear(&self) -> Result<()> {
        self.db.ensure_writable()?;
        {
            let mut g = self.db.inner.write_store()?;
            if let Some(bucket) = g.get_mut(&self.name) {
                bucket.clear();
            }
        }
        self.db.after_write()
    }

    /// Load and decrypt the current value for `key` from an already-locked store.
    fn load<V: DeserializeOwned>(&self, store: &Store, key: &str) -> Result<Option<V>> {
        match fetch(store, &self.name, key) {
            Some(e) => self.db.inner.read_value(&self.name, key, &e),
            None => Ok(None),
        }
    }

    /// Clone out the entries matching `pred` so decryption can happen without holding the
    /// storage lock.
    fn snapshot_entries<P: Fn(&str) -> bool>(&self, pred: P) -> Result<Vec<(String, Entry)>> {
        let g = self.db.inner.read_store()?;
        Ok(g.get(&self.name)
            .map(|b| {
                b.iter()
                    .filter(|(k, _)| pred(k))
                    .map(|(k, e)| (k.clone(), e.clone()))
                    .collect()
            })
            .unwrap_or_default())
    }
}
