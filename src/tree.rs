//! [`Tree`]: the per-namespace key-value API. Every read/write op lives here; `MicroKV`
//! exposes the default namespace's tree directly via `Deref`.

use std::ops::ControlFlow;
use std::sync::Arc;
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::codec::encode;
use crate::error::{Error, Result};
use crate::format::{Entry, Store};
use crate::secret::Secret;
use crate::store::{fetch, remove_from, seal_into, Inner};

/// A handle to a single namespace within a [`MicroKV`](crate::MicroKV) store.
#[derive(Clone)]
pub struct Tree {
    inner: Arc<Inner>,
    name: String,
}

impl Tree {
    pub(crate) fn new(inner: Arc<Inner>, name: String) -> Self {
        Self { inner, name }
    }

    /// `""` for the default namespace.
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn get<V: DeserializeOwned>(&self, key: &str) -> Result<Option<V>> {
        let entry = {
            let g = self.inner.read_store()?;
            fetch(&g, &self.name, key)
        };
        match entry {
            Some(e) => self.inner.read_value(&self.name, key, &e),
            None => Ok(None),
        }
    }

    pub fn require<V: DeserializeOwned>(&self, key: &str) -> Result<V> {
        self.get(key)?.ok_or(Error::KeyNotFound)
    }

    /// [`Tree::get`], wrapped in a non-logging [`Secret`].
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
        self.inner.ensure_writable()?;
        {
            let mut g = self.inner.write_store()?;
            seal_into(&self.inner, &mut g, &self.name, key, value, ttl)?;
        }
        self.inner.after_write()
    }

    pub fn remove(&self, key: &str) -> Result<bool> {
        self.inner.ensure_writable()?;
        let existed = {
            let mut g = self.inner.write_store()?;
            remove_from(&mut g, &self.name, key)
        };
        self.inner.after_write()?;
        Ok(existed)
    }

    pub fn contains(&self, key: &str) -> Result<bool> {
        let entry = {
            let g = self.inner.read_store()?;
            fetch(&g, &self.name, key)
        };
        match entry {
            Some(e) => self.inner.is_live(&self.name, key, &e),
            None => Ok(false),
        }
    }

    pub fn len(&self) -> Result<usize> {
        let mut n = 0;
        for (k, e) in self.snapshot_entries(|_| true)? {
            if self.inner.is_live(&self.name, &k, &e)? {
                n += 1;
            }
        }
        Ok(n)
    }

    pub fn is_empty(&self) -> Result<bool> {
        Ok(self.len()? == 0)
    }

    /// Atomic read-modify-write under one lock. Returning `None` removes the key.
    pub fn update<V, F>(&self, key: &str, f: F) -> Result<()>
    where
        V: Serialize + DeserializeOwned,
        F: FnOnce(Option<V>) -> Option<V>,
    {
        self.inner.ensure_writable()?;
        {
            let mut g = self.inner.write_store()?;
            let current = self.load::<V>(&g, key)?;
            match f(current) {
                Some(v) => seal_into(&self.inner, &mut g, &self.name, key, &v, None)?,
                None => {
                    remove_from(&mut g, &self.name, key);
                }
            }
        }
        self.inner.after_write()
    }

    pub fn get_or_insert_with<V, F>(&self, key: &str, f: F) -> Result<V>
    where
        V: Serialize + DeserializeOwned,
        F: FnOnce() -> V,
    {
        self.inner.ensure_writable()?;
        let (value, wrote) = {
            let mut g = self.inner.write_store()?;
            match self.load::<V>(&g, key)? {
                Some(v) => (v, false),
                None => {
                    let v = f();
                    seal_into(&self.inner, &mut g, &self.name, key, &v, None)?;
                    (v, true)
                }
            }
        };
        if wrote {
            self.inner.after_write()?;
        }
        Ok(value)
    }

    /// Swap to `new` only if the current value equals `expected` (by serialized bytes).
    pub fn compare_and_swap<V: Serialize + DeserializeOwned>(
        &self,
        key: &str,
        expected: Option<&V>,
        new: Option<&V>,
    ) -> Result<bool> {
        self.inner.ensure_writable()?;
        let swapped = {
            let mut g = self.inner.write_store()?;
            let current_bytes = match fetch(&g, &self.name, key) {
                Some(e) => self.inner.open_entry(&self.name, key, &e)?,
                None => None,
            };
            let expected_bytes = match expected {
                Some(v) => Some(encode(v)?),
                None => None,
            };

            if current_bytes == expected_bytes {
                match new {
                    Some(v) => seal_into(&self.inner, &mut g, &self.name, key, v, None)?,
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
            self.inner.after_write()?;
        }
        Ok(swapped)
    }

    /// Live keys (expired entries excluded).
    pub fn keys(&self) -> Result<Vec<String>> {
        let mut out = Vec::new();
        for (k, e) in self.snapshot_entries(|_| true)? {
            if self.inner.is_live(&self.name, &k, &e)? {
                out.push(k);
            }
        }
        Ok(out)
    }

    pub fn keys_sorted(&self) -> Result<Vec<String>> {
        let mut keys = self.keys()?;
        keys.sort();
        Ok(keys)
    }

    /// Entries whose key starts with `prefix` (decrypts each match).
    pub fn prefix<V: DeserializeOwned>(&self, prefix: &str) -> Result<Vec<(String, V)>> {
        let mut out = Vec::new();
        for (k, e) in self.snapshot_entries(|key| key.starts_with(prefix))? {
            if let Some(v) = self.inner.read_value::<V>(&self.name, &k, &e)? {
                out.push((k, v));
            }
        }
        Ok(out)
    }

    /// Visit every live entry; return `Break` to stop early.
    pub fn for_each<V, F>(&self, mut f: F) -> Result<()>
    where
        V: DeserializeOwned,
        F: FnMut(&str, V) -> ControlFlow<()>,
    {
        for (k, e) in self.snapshot_entries(|_| true)? {
            if let Some(v) = self.inner.read_value::<V>(&self.name, &k, &e)? {
                if let ControlFlow::Break(()) = f(&k, v) {
                    break;
                }
            }
        }
        Ok(())
    }

    pub fn clear(&self) -> Result<()> {
        self.inner.ensure_writable()?;
        {
            let mut g = self.inner.write_store()?;
            if let Some(bucket) = g.get_mut(&self.name) {
                bucket.clear();
            }
        }
        self.inner.after_write()
    }

    /// Decrypt the current value, with the store already locked.
    fn load<V: DeserializeOwned>(&self, store: &Store, key: &str) -> Result<Option<V>> {
        match fetch(store, &self.name, key) {
            Some(e) => self.inner.read_value(&self.name, key, &e),
            None => Ok(None),
        }
    }

    /// Clone matching entries so we can decrypt without holding the lock.
    fn snapshot_entries<P: Fn(&str) -> bool>(&self, pred: P) -> Result<Vec<(String, Entry)>> {
        let g = self.inner.read_store()?;
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
