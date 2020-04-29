//! lib.rs
//!
//!     Defines modules within library crates
//!     that can be exported for interfacing.

extern crate bincode;
extern crate indexmap;
extern crate secstr;
extern crate serde;
extern crate sodiumoxide;

mod ser;
pub mod errors;
pub mod kv;

// re-import for accessible namespace
pub use self::kv::MicroKV;
