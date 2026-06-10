//! __microkv__ is a minimal, security-focused key-value store for sensitive data, with
//! encrypted persistence to disk.
//!
//! Every store is encrypted (there is no plaintext mode): values are sealed with
//! ChaCha20-Poly1305 under a key derived from a password (scrypt, or argon2 behind a
//! feature flag) or supplied directly. Data is organized into isolated namespaces
//! ("trees"), persisted atomically, and key material is held in memory-locked,
//! auto-zeroed storage.
//!
//! ```rust
//! use microkv::{MicroKV, Credential};
//!
//! let db = MicroKV::in_memory(Credential::password("p@ssw0rd")).unwrap();
//! db.put("answer", &42u32).unwrap();
//! let answer: u32 = db.require("answer").unwrap();
//! assert_eq!(answer, 42);
//! ```

mod codec;
mod config;
mod crypto;
mod error;
mod format;
mod secret;
mod store;
mod tree;
mod txn;

pub use crate::config::{AutoSave, Credential, KdfParams, LockMode};
pub use crate::error::{Error, Result};
pub use crate::secret::{Secret, SecretString};
pub use crate::store::{Builder, MicroKV};
pub use crate::tree::Tree;
pub use crate::txn::Txn;
