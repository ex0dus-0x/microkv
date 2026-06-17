//! Crypto primitives: the memory-locked key and the AEAD seal/open helpers.

use std::ptr::NonNull;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use zeroize::{Zeroize, Zeroizing};

use crate::config::KdfRepr;
use crate::error::{Error, Result};

pub(crate) const KEY_LEN: usize = 32;
pub(crate) const SALT_LEN: usize = 16;

enum KeyStore {
    /// `memsec`-guarded, `mlock`-ed, zeroed on free.
    Locked(NonNull<[u8; KEY_LEN]>),
    /// Fallback when secure allocation is unavailable and `strict-mlock` is off.
    #[cfg_attr(feature = "strict-mlock", allow(dead_code))]
    Heap(Zeroizing<[u8; KEY_LEN]>),
}

/// The 32-byte key. Prefers `mlock`-ed storage, degrades to a zeroizing heap allocation
/// if the OS denies it (e.g. low `RLIMIT_MEMLOCK`) — unless `strict-mlock` is set.
pub(crate) struct SecretKey {
    store: KeyStore,
}

// SAFETY: the key is only read after construction (never mutated/aliased), so sharing or
// moving the handle across threads is sound regardless of the storage variant.
unsafe impl Send for SecretKey {}
unsafe impl Sync for SecretKey {}

impl SecretKey {
    /// Move `key` into secure storage, wiping the caller's copy.
    pub(crate) fn new(mut key: [u8; KEY_LEN]) -> Result<Self> {
        // SAFETY: `malloc` returns a valid, uniquely-owned, aligned allocation or `None`.
        match unsafe { memsec::malloc::<[u8; KEY_LEN]>() } {
            Some(ptr) => {
                unsafe { ptr.as_ptr().write(key) };
                key.zeroize();
                Ok(Self {
                    store: KeyStore::Locked(ptr),
                })
            }
            None => {
                #[cfg(feature = "strict-mlock")]
                {
                    key.zeroize();
                    Err(Error::SecureAlloc)
                }
                #[cfg(not(feature = "strict-mlock"))]
                {
                    let sk = Self {
                        store: KeyStore::Heap(Zeroizing::new(key)),
                    };
                    key.zeroize();
                    Ok(sk)
                }
            }
        }
    }

    pub(crate) fn cipher(&self) -> ChaCha20Poly1305 {
        let key: &[u8] = match &self.store {
            // SAFETY: `ptr` is valid for `self`'s lifetime and never aliased mutably.
            KeyStore::Locked(ptr) => unsafe { ptr.as_ref() },
            KeyStore::Heap(z) => &z[..],
        };
        ChaCha20Poly1305::new_from_slice(key).expect("key length is KEY_LEN")
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        if let KeyStore::Locked(ptr) = self.store {
            // `free` zeroes the guarded region before releasing it.
            unsafe { memsec::free(ptr) };
        }
        // Heap variant zeroes itself via `Zeroizing`.
    }
}

/// Seal under a fresh random nonce; returns `(nonce, ciphertext+tag)`.
pub(crate) fn aead_encrypt(
    cipher: &ChaCha20Poly1305,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<([u8; 12], Vec<u8>)> {
    let mut nonce_bytes = [0u8; 12];
    getrandom::getrandom(&mut nonce_bytes).map_err(|_| Error::Random)?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Crypto)?;
    Ok((nonce_bytes, ciphertext))
}

pub(crate) fn aead_decrypt(
    cipher: &ChaCha20Poly1305,
    aad: &[u8],
    nonce: &[u8; 12],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::Crypto)
}

/// AAD binding a value to its `(namespace, key)`. Length-prefixed so `(a, bc)` and
/// `(ab, c)` can't collide.
pub(crate) fn value_aad(ns: &str, key: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(8 + ns.len() + key.len());
    aad.extend_from_slice(&(ns.len() as u32).to_le_bytes());
    aad.extend_from_slice(ns.as_bytes());
    aad.extend_from_slice(&(key.len() as u32).to_le_bytes());
    aad.extend_from_slice(key.as_bytes());
    aad
}

/// AAD binding the header (KDF params + salt) to the verifier, so tampering is caught.
pub(crate) fn header_aad(kdf: &KdfRepr, salt: &[u8; SALT_LEN]) -> Result<Vec<u8>> {
    rmp_serde::to_vec(&(kdf, salt)).map_err(|e| Error::Serialization(e.to_string()))
}

pub(crate) fn gen_salt() -> Result<[u8; SALT_LEN]> {
    let mut salt = [0u8; SALT_LEN];
    getrandom::getrandom(&mut salt).map_err(|_| Error::Random)?;
    Ok(salt)
}

pub(crate) fn rand_u64() -> Result<u64> {
    let mut buf = [0u8; 8];
    getrandom::getrandom(&mut buf).map_err(|_| Error::Random)?;
    Ok(u64::from_le_bytes(buf))
}
