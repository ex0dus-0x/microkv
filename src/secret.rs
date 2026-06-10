//! Lightweight wrappers that keep secret material out of logs and zero it on drop.
//!
//! These intentionally do not implement `Debug`/`Display`, so a secret can't be
//! accidentally formatted into a log line or error message.

use zeroize::Zeroize;

/// A password held in memory that is zeroized when dropped.
///
/// Construct from a `String` or `&str` via `into()`, and read it back only through
/// [`SecretString::expose`] at the point of use.
pub struct SecretString(String);

impl SecretString {
    /// Borrow the underlying password. Keep the borrow as short-lived as possible.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl From<String> for SecretString {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for SecretString {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// A wrapper marking a decrypted value as sensitive.
///
/// It does not implement `Debug`, so it won't leak into logs, and the transient
/// plaintext buffer used to decode it is always zeroized regardless. Access the inner
/// value via [`Secret::expose`] or consume it with [`Secret::into_inner`].
pub struct Secret<V>(V);

impl<V> Secret<V> {
    pub(crate) fn new(value: V) -> Self {
        Self(value)
    }

    /// Borrow the protected value.
    pub fn expose(&self) -> &V {
        &self.0
    }

    /// Consume the wrapper and take ownership of the value.
    pub fn into_inner(self) -> V {
        self.0
    }
}
