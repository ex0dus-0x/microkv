//! __microkv__ is a persistent key-value store implemented in Rust, aiming to maintain a balance
//! between security and performance. It is built out of a yearning to learn more about the
//! intricacies of distributed systems, databases, and secure persistent storage.
//!
//! While __microkv__ shouldn't be used in large-scale environments that facilitate an insane
//! volume of transactional interactions,
//! it is still optimal for use in a production-grade system/application that may not require the
//! complex luxuries of a full-blown database or even industry-standard KV-store like Redis or LevelDB.
//!
//! ## Use cases
//!
//! Here are some specific use-cases that you may want to use __microkv__ for:
//!
//! * Local persistent serialization for sensitive configurations
//! * Secrets management for a single-process application
//! * License key management

pub mod errors;
pub mod kv;

// re-import for accessible namespace
pub use self::kv::MicroKV;
