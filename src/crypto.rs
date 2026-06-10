//! Low-level cryptographic primitives: the memory-locked symmetric key and the AEAD
//! seal/open helpers used to protect values and the store header.

use std::ptr::NonNull;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use zeroize::{Zeroize, Zeroizing};

use crate::config::KdfRepr;
use crate::error::{Error, Result};

/// Length of a ChaCha20-Poly1305 key.
pub(crate) const KEY_LEN: usize = 32;

/// Length of the per-store random salt.
pub(crate) const SALT_LEN: usize = 16;

/// Where the 32-byte key actually lives.
enum KeyStore {
    /// In a `memsec`-guarded, `mlock`-ed allocation, zeroed on free.
    Locked(NonNull<[u8; KEY_LEN]>),
    /// Fallback: a plain heap allocation that still zeroes on drop, used when secure
    /// allocation is unavailable (and the `strict-mlock` feature is off).
    #[cfg_attr(feature = "strict-mlock", allow(dead_code))]
    Heap(Zeroizing<[u8; KEY_LEN]>),
}

/// Owns the 32-byte symmetric key. Prefers `mlock`-ed storage but degrades gracefully to
/// a zeroizing heap allocation if the OS denies secure allocation (e.g. low
/// `RLIMIT_MEMLOCK` in a container) — unless the `strict-mlock` feature requires it.
pub(crate) struct SecretKey {
    store: KeyStore,
}

// SAFETY: the key is only read after construction (never mutated/aliased), so sharing or
// moving the handle across threads is sound regardless of the storage variant.
unsafe impl Send for SecretKey {}
unsafe impl Sync for SecretKey {}

impl SecretKey {
    /// Move `key` into secure storage, zeroizing the caller-provided copy. Returns
    /// [`Error::SecureAlloc`] only when secure allocation fails and `strict-mlock` is on.
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

    /// Build an AEAD cipher from the guarded key material.
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

/// Encrypt `plaintext` under `cipher` with a fresh random nonce and the given associated
/// data, returning the nonce and ciphertext (including authentication tag).
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

/// Authenticate and decrypt `ciphertext` under `cipher`, `nonce`, and associated data.
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

/// Associated data binding a value to its `(namespace, key)`. Length-prefixed so that
/// `(a, bc)` and `(ab, c)` can never collide.
pub(crate) fn value_aad(ns: &str, key: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(8 + ns.len() + key.len());
    aad.extend_from_slice(&(ns.len() as u32).to_le_bytes());
    aad.extend_from_slice(ns.as_bytes());
    aad.extend_from_slice(&(key.len() as u32).to_le_bytes());
    aad.extend_from_slice(key.as_bytes());
    aad
}

/// Deterministic associated data binding the file header (KDF params + salt) to the
/// verifier, so tampering with either is detected on open.
pub(crate) fn header_aad(kdf: &KdfRepr, salt: &[u8; SALT_LEN]) -> Result<Vec<u8>> {
    rmp_serde::to_vec(&(kdf, salt)).map_err(|e| Error::Serialization(e.to_string()))
}

/// A fresh random salt from the OS CSPRNG.
pub(crate) fn gen_salt() -> Result<[u8; SALT_LEN]> {
    let mut salt = [0u8; SALT_LEN];
    getrandom::getrandom(&mut salt).map_err(|_| Error::Random)?;
    Ok(salt)
}

/// 8 bytes of OS randomness as a `u64` (used for unique temp file names).
pub(crate) fn rand_u64() -> Result<u64> {
    let mut buf = [0u8; 8];
    getrandom::getrandom(&mut buf).map_err(|_| Error::Random)?;
    Ok(u64::from_le_bytes(buf))
}
