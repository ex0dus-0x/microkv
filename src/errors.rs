//! errors.rs
//!
//!     Defines a portable error-handling  module for
//!     use when encountering runtime exceptions.

use std::error::Error;
use std::fmt;

/// Aliases a custom `Result` type to return our specific error type.
pub type Result<'a, T> = std::result::Result<T, KVError<'a>>;

/// `ErrorType` defines the general implementation-level errors that
/// may be reached during runtime execution.
#[derive(Debug)]
pub enum ErrorType {
    KVError,     // issues involving database interactions
    CryptoError, // problems arisen from performing authentication encryption
    FileError,   // unified type for io::Error
    PoisonError, // locking error, indicating poisoned mutex
}

/// `KVError<'a>` encapsulates an ErrorType, and is what ultimately
/// gets returned to any user-facing code when and exception is handled.
pub struct KVError<'a> {
    pub error: ErrorType,
    pub msg: Option<&'a str>,
}

impl<'a> fmt::Debug for KVError<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(msg) = &self.msg {
            write!(f, "KVError::{:?}: {}", self.error, msg)
        } else {
            write!(f, "KVError::{:?}", self.error)
        }
    }
}

impl<'a> fmt::Display for KVError<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} received from microKV: {}", "test", "test")
    }
}

/*
// Enables us to unify any I/O errors with our error type.
impl<'a> From<std::io::Error> for KVError<'a> {
    fn from(error: std::io::Error) -> Self {
        let err = error.to_string().clone();
        KVError {
            error: ErrorType::FileError,
            msg: Some(&err.as_str()),
        }
    }
}
*/

impl<'a> Error for KVError<'a> {}
