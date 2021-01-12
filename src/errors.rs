//! Defines a portable error-handling module for use when encountering runtime exceptions.

use std::error::Error;
use std::fmt;

/// Aliases a custom `Result` type to return our specific error type.
pub type Result<T> = std::result::Result<T, KVError>;

/// Defines the general implementation-level errors that
/// may be reached during runtime.
#[derive(Debug)]
pub enum ErrorType {
    KVError,     // issues involving database interactions
    CryptoError, // problems arisen from performing authentication encryption
    FileError,   // unified type for io::Error
    PoisonError, // locking error, indicating poisoned mutex
}

/// Encapsulates an ErrorType, and is what ultimately gets returned to
/// any user-facing code when and exception is handled.
pub struct KVError {
    pub error: ErrorType,
    pub msg: Option<String>,
}

impl fmt::Debug for KVError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(msg) = &self.msg {
            write!(f, "KVError::{:?}: {}", self.error, msg)
        } else {
            write!(f, "KVError::{:?}", self.error)
        }
    }
}

impl fmt::Display for KVError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(msg) = &self.msg {
            write!(
                f,
                "{:?} received from microkv with message: {}",
                self.error, msg
            )
        } else {
            write!(f, "{:?} received from microkv", self.error)
        }
    }
}

// Enables us to unify any I/O errors with our error type.
impl From<std::io::Error> for KVError {
    fn from(error: std::io::Error) -> Self {
        KVError {
            error: ErrorType::FileError,
            msg: Some(error.to_string()),
        }
    }
}

impl Error for KVError {}
