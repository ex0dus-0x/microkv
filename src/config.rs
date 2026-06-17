//! Public config types and key derivation.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::crypto::KEY_LEN;
use crate::error::{Error, Result};
use crate::secret::SecretString;

/// How to unlock a store. Encryption is mandatory — there is no plaintext option.
pub enum Credential {
    /// Derived from a password via the store's KDF + salt.
    Password(SecretString),
    /// A raw 32-byte key (e.g. from a KMS or keyring).
    Key([u8; KEY_LEN]),
}

impl Credential {
    /// Wrap a password in a zeroizing [`SecretString`].
    pub fn password(pwd: impl Into<String>) -> Self {
        Credential::Password(SecretString::new(pwd.into()))
    }

    pub fn key(key: [u8; KEY_LEN]) -> Self {
        Credential::Key(key)
    }
}

impl Drop for Credential {
    fn drop(&mut self) {
        // The password variant is zeroized by `SecretString`; wipe the raw key here.
        if let Credential::Key(key) = self {
            key.zeroize();
        }
    }
}

/// KDF algorithm + cost, persisted in the header so the work factor can change without
/// breaking existing stores.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) enum KdfRepr {
    Scrypt {
        log_n: u8,
        r: u32,
        p: u32,
    },
    Argon2id {
        m_cost: u32,
        t_cost: u32,
        p_cost: u32,
    },
}

/// Opaque KDF parameters.
#[derive(Clone)]
pub struct KdfParams(pub(crate) KdfRepr);

impl KdfParams {
    pub fn scrypt(log_n: u8, r: u32, p: u32) -> Self {
        KdfParams(KdfRepr::Scrypt { log_n, r, p })
    }

    /// ~32 MiB; fast enough per-open (default).
    pub fn interactive() -> Self {
        KdfParams::scrypt(15, 8, 1)
    }

    /// ~128 MiB; for secrets at rest.
    pub fn sensitive() -> Self {
        KdfParams::scrypt(17, 8, 1)
    }

    /// Requires the `argon2` feature.
    #[cfg(feature = "argon2")]
    pub fn argon2id(m_cost: u32, t_cost: u32, p_cost: u32) -> Self {
        KdfParams(KdfRepr::Argon2id {
            m_cost,
            t_cost,
            p_cost,
        })
    }
}

impl Default for KdfParams {
    fn default() -> Self {
        KdfParams::interactive()
    }
}

/// When to flush to disk.
#[derive(Clone, Copy, Default)]
pub enum AutoSave {
    /// Only on an explicit `MicroKV::save`.
    #[default]
    Manual,
    OnEveryWrite,
    /// Save on a write if this much time has passed since the last save.
    Periodic(Duration),
    /// Save when the last handle drops.
    OnDrop,
}

/// Cross-process locking, via a sidecar `.lock` file.
#[derive(Clone, Copy, Default)]
pub enum LockMode {
    #[default]
    None,
    Shared,
    Exclusive,
}

/// Open-time knobs. Everything defaults: `Config { read_only: true, ..Default::default() }`.
#[derive(Clone, Default)]
pub struct Config {
    /// Stamped into *new* stores only; ignored when opening an existing one.
    pub kdf: KdfParams,
    pub autosave: AutoSave,
    pub lock_mode: LockMode,
    pub read_only: bool,
}

/// The 32-byte key for a credential: raw keys as-is, passwords run through the KDF.
pub(crate) fn credential_key(
    cred: &Credential,
    kdf: &KdfRepr,
    salt: &[u8],
) -> Result<[u8; KEY_LEN]> {
    match cred {
        Credential::Password(pwd) => derive_pwd(pwd.as_bytes(), kdf, salt),
        Credential::Key(key) => Ok(*key),
    }
}

pub(crate) fn derive_pwd(pwd: &[u8], kdf: &KdfRepr, salt: &[u8]) -> Result<[u8; KEY_LEN]> {
    let mut key = [0u8; KEY_LEN];
    match kdf {
        KdfRepr::Scrypt { log_n, r, p } => {
            let params = scrypt::Params::new(*log_n, *r, *p, KEY_LEN)
                .map_err(|_| Error::CorruptStore("invalid scrypt parameters".to_string()))?;
            scrypt::scrypt(pwd, salt, &params, &mut key).map_err(|_| Error::Crypto)?;
        }
        KdfRepr::Argon2id {
            m_cost,
            t_cost,
            p_cost,
        } => {
            #[cfg(feature = "argon2")]
            {
                use argon2::{Algorithm, Argon2, Params as AParams, Version};
                let params = AParams::new(*m_cost, *t_cost, *p_cost, Some(KEY_LEN))
                    .map_err(|_| Error::CorruptStore("invalid argon2 parameters".to_string()))?;
                let a = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
                a.hash_password_into(pwd, salt, &mut key)
                    .map_err(|_| Error::Crypto)?;
            }
            #[cfg(not(feature = "argon2"))]
            {
                let _ = (m_cost, t_cost, p_cost);
                return Err(Error::CorruptStore(
                    "store uses argon2 but the 'argon2' feature is disabled".to_string(),
                ));
            }
        }
    }
    Ok(key)
}
