//! Wrappers that keep secret material out of logs and zero it on drop.

use zeroize::Zeroizing;

/// A password held in memory that is zeroized when dropped.
///
/// This is just [`zeroize::Zeroizing<String>`], so it derefs to `str` for reading.
///
/// [`Credential::password`]: crate::Credential::password
pub type SecretString = Zeroizing<String>;

/// A wrapper marking a decrypted value as sensitive.
///
/// It does not implement `Debug`, so it won't leak into logs. The plaintext
/// buffer is always zeroized regardless.
pub struct Secret<V>(V);

impl<V> Secret<V> {
    pub(crate) fn new(value: V) -> Self {
        Self(value)
    }

    pub fn expose(&self) -> &V {
        &self.0
    }

    pub fn into_inner(self) -> V {
        self.0
    }
}
