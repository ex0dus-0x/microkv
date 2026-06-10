//! Public configuration: how to unlock a store, how keys are derived, and store
//! persistence/locking policies.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::crypto::KEY_LEN;
use crate::error::{Error, Result};
use crate::secret::SecretString;

/// How to unlock a store. There is no plaintext option — encryption is mandatory.
pub enum Credential {
    /// Derive the key from a password using the store's KDF and salt.
    Password(SecretString),
    /// Use a caller-supplied 32-byte key directly (e.g. from a KMS or keyring).
    Key([u8; KEY_LEN]),
}

impl Credential {
    /// Build a password credential from anything convertible into a [`SecretString`].
    pub fn password(pwd: impl Into<SecretString>) -> Self {
        Credential::Password(pwd.into())
    }

    /// Build a credential from a raw 32-byte key.
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

/// Key-derivation algorithm + cost parameters, persisted in the store header so the work
/// factor can evolve without invalidating existing databases.
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

/// Public, opaque handle to a set of KDF parameters.
#[derive(Clone)]
pub struct KdfParams(pub(crate) KdfRepr);

impl KdfParams {
    /// scrypt with explicit parameters (`log_n`, `r`, `p`).
    pub fn scrypt(log_n: u8, r: u32, p: u32) -> Self {
        KdfParams(KdfRepr::Scrypt { log_n, r, p })
    }

    /// Interactive cost: ~32 MiB, fast enough for per-open use (default).
    pub fn interactive() -> Self {
        KdfParams::scrypt(15, 8, 1)
    }

    /// Sensitive cost: ~128 MiB, for secrets that sit at rest.
    pub fn sensitive() -> Self {
        KdfParams::scrypt(17, 8, 1)
    }

    /// Argon2id with explicit parameters. Requires the `argon2` feature.
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

/// When the store flushes to disk automatically.
#[derive(Clone, Copy)]
pub enum AutoSave {
    /// Never auto-save; the caller must invoke `MicroKV::save`.
    Manual,
    /// Persist after every successful write.
    OnEveryWrite,
    /// Persist on a write only if at least this much time has elapsed since the last save.
    Periodic(Duration),
    /// Persist once, when the last handle is dropped.
    OnDrop,
}

/// Cross-process file locking applied on open (via a sidecar `.lock` file).
#[derive(Clone, Copy)]
pub enum LockMode {
    /// No file locking.
    None,
    /// Shared (multiple-reader) lock.
    Shared,
    /// Exclusive (single-writer) lock.
    Exclusive,
}

/// Derive the 32-byte symmetric key for a credential. Raw keys are used as-is;
/// passwords are stretched with the store's KDF over its salt.
pub(crate) fn credential_key(
    cred: &Credential,
    kdf: &KdfRepr,
    salt: &[u8],
) -> Result<[u8; KEY_LEN]> {
    match cred {
        Credential::Password(pwd) => derive_pwd(pwd.expose().as_bytes(), kdf, salt),
        Credential::Key(key) => Ok(*key),
    }
}

/// Stretch a password into a 32-byte key with the configured KDF.
pub(crate) fn derive_pwd(pwd: &[u8], kdf: &KdfRepr, salt: &[u8]) -> Result<[u8; KEY_LEN]> {
    let mut key = [0u8; KEY_LEN];
    match kdf {
        KdfRepr::Scrypt { log_n, r, p } => {
            let params = scrypt::Params::new(*log_n, *r, *p, KEY_LEN)
                .map_err(|_| Error::Corrupt("invalid scrypt parameters".to_string()))?;
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
                    .map_err(|_| Error::Corrupt("invalid argon2 parameters".to_string()))?;
                let a = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
                a.hash_password_into(pwd, salt, &mut key)
                    .map_err(|_| Error::Crypto)?;
            }
            #[cfg(not(feature = "argon2"))]
            {
                let _ = (m_cost, t_cost, p_cost);
                return Err(Error::Corrupt(
                    "store uses argon2 but the 'argon2' feature is disabled".to_string(),
                ));
            }
        }
    }
    Ok(key)
}
