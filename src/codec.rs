//! Value (de)serialization to and from msgpack.
//!
//! Decoding zeroizes the transient plaintext buffer once the value has been parsed out
//! of it, so decrypted bytes don't linger on the heap.

use serde::de::DeserializeOwned;
use serde::Serialize;
use zeroize::Zeroize;

use crate::error::{Error, Result};

/// Serialize a value to msgpack bytes.
pub(crate) fn encode<V: Serialize>(value: &V) -> Result<Vec<u8>> {
    rmp_serde::to_vec(value).map_err(|e| Error::Serialization(e.to_string()))
}

/// Deserialize a value from a plaintext buffer, then wipe the buffer.
pub(crate) fn decode<V: DeserializeOwned>(mut bytes: Vec<u8>) -> Result<V> {
    let out = rmp_serde::from_slice(&bytes).map_err(|e| Error::Serialization(e.to_string()));
    bytes.zeroize();
    out
}
