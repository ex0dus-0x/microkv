//! Value <-> msgpack conversion.

use serde::de::DeserializeOwned;
use serde::Serialize;
use zeroize::Zeroize;

use crate::error::{Error, Result};

pub(crate) fn encode<V: Serialize>(value: &V) -> Result<Vec<u8>> {
    rmp_serde::to_vec(value).map_err(|e| Error::Serialization(e.to_string()))
}

/// Decode, then wipe the plaintext buffer so decrypted bytes don't linger.
pub(crate) fn decode<V: DeserializeOwned>(mut bytes: Vec<u8>) -> Result<V> {
    let out = rmp_serde::from_slice(&bytes).map_err(|e| Error::Serialization(e.to_string()));
    bytes.zeroize();
    out
}
