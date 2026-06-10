use thiserror::Error;

/// Convenience alias for results returned throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// All failures the store can surface. Exhaustive matching is discouraged
/// (`#[non_exhaustive]`) so new variants can be added without a breaking change.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// A required key was absent.
    #[error("key not found")]
    NotFound,

    /// The supplied password or key failed verification against the store.
    #[error("incorrect password or key")]
    WrongPassword,

    /// The store file is malformed, foreign, or otherwise unreadable.
    #[error("corrupt store: {0}")]
    Corrupt(String),

    /// The store was written by an incompatible format version.
    #[error("unsupported store version {found} (expected {expected})")]
    UnsupportedVersion { found: u8, expected: u8 },

    /// An encryption/decryption/authentication operation failed.
    #[error("cryptographic operation failed")]
    Crypto,

    /// The OS random number generator was unavailable.
    #[error("could not read OS randomness")]
    Random,

    /// Secure (memory-locked) allocation for the key failed while strict mode is enabled.
    #[error("secure memory allocation failed")]
    SecureAlloc,

    /// Serialization or deserialization of a value failed.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// An underlying I/O operation failed.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// A lock could not be acquired (poisoned in-process lock, or contended file lock).
    #[error("lock unavailable or poisoned")]
    Locked,

    /// `create_new` was asked to create a store that already exists.
    #[error("store already exists")]
    AlreadyExists,

    /// A write was attempted on a read-only store.
    #[error("store is read-only")]
    ReadOnly,

    /// An entry was present but past its time-to-live.
    #[error("entry expired")]
    Expired,

    /// A persistence operation was attempted on an in-memory store.
    #[error("no path associated with store")]
    NoPath,
}
