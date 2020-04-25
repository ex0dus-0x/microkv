//! errors.rs
//!
//!     Defines a portable error-handling  module for
//!     use when encountering runtime exceptions.

use std::io;
use std::fmt;
use std::error::Error;


// aliases a custom Result type to return our specific error type.
pub type Result<'a, T> = std::result::Result<T, KVError<'a>>;


/// `ErrorType` defines the general impl<'a>ementation-level errors that
/// may be reached during runtime execution.
#[derive(Debug)]
pub enum ErrorType {
    KeyError,       // issues involving specified key
    FileError,      // unified type for io::Error
    PoisonError     // locking error, indicating poisoned mutex
}


/// `KVError<'a>` encapsulates an ErrorType, and is what ultimately
/// gets returned to any user-facing code when and exception is handled.
pub struct KVError<'a> {
    error: ErrorType,
    msg: Option<&'a str>
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


// Enables us to unify any I/O errors with our error type.
impl<'a> From<io::Error> for KVError<'a> {
    fn from(error: io::Error) -> Self {
        KVError {
            error: ErrorType::FileError,
            msg: Some(&error.to_string()),
        }
    }
}


// TODO: impl<'a>ement source()
impl<'a> Error for KVError<'a> {}
