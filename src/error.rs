use thiserror::Error;

/// Result with the crate's [`enum@Error`].
pub type Result<T> = std::result::Result<T, Error>;

/// Anything that can go wrong. Non-exhaustive; match with a wildcard arm.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[error("key not found")]
    KeyNotFound,

    #[error("incorrect password or key")]
    WrongPassword,

    #[error("corrupt store: {0}")]
    CorruptStore(String),

    #[error("unsupported store version {found} (expected {expected})")]
    UnsupportedStoreVersion { found: u8, expected: u8 },

    #[error("cryptographic operation failed")]
    Crypto,

    #[error("could not read OS randomness")]
    Random,

    /// `mlock`-ed allocation failed and the `strict-mlock` feature is on.
    #[error("secure memory allocation failed")]
    SecureAlloc,

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// Poisoned in-process lock or a contended cross-process file lock.
    #[error("lock unavailable or poisoned")]
    Locked,

    #[error("store already exists")]
    AlreadyExists,

    #[error("store is read-only")]
    ReadOnly,

    #[error("entry expired")]
    Expired,

    /// Persistence attempted on an in-memory store.
    #[error("no path associated with store")]
    NoPath,
}
