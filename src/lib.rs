//! lib.rs
//!
//!     Defines modules within library crates
//!     that can be exported for interfacing.

pub mod errors;
pub mod kv;
mod ser;

// re-import for accessible namespace
pub use self::kv::MicroKV;
