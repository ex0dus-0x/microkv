//! errors.rs
//!
//!     Defines a portable error-handling  module for
//!     use when encountering runtime exceptions.

use std::io;
use std::fmt;
use std::error::Error;


// aliases a custom Result type to return our specific error type.
pub type Result<T> = std::result::Result<T, ErrorType>;


/// `ErrorType` defines the implementation-level errors that
/// may be reached during runtime execution.
#[derive(Debug)]
pub enum ErrorType {
    KeyNotFound,
    SerializeError,
    DeserializeError,
    FileError,
    CommitError,
    NoPathSupplied,
    IsEmpty,
    NotFound,
    TinyCollectionImbalance,
}


/// `KVError` encapsulates an ErrorType, and is what ultimately
/// gets returned to any user-facing code when and exception is handled.
pub struct KVError {
    error: ErrorType,
    message: Option<String>
}


impl fmt::Debug for KVError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(msg) = &self.message {
            write!(f, "KVError::{:?}: {}", self.error, msg)
        } else {
            write!(f, "KVError::{:?}", self.error)
        }
    }
}


impl fmt::Display for KVError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} received from microKV: {}", "test", "test")
    }
}


// Enables us to unify any I/O errors with our error type.
impl From<io::Error> for KVError {
    fn from(error: io::Error) -> Self {
        KVError {
            error: ErrorType::FileError,
            message: Some(error.to_string()),
        }
    }
}


// TODO: implement source()
impl Error for KVError {}
