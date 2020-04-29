//! ser.rs
//!
//!     Helper module that defines de/serialization routines
//!     for `Arc<RwLock<T>>`s.
//!
//!     Inspired by:
//!     https://users.rust-lang.org/t/how-to-serialize-deserialize-an-async-std-rwlock-t-where-t-serialize-deserialize/37407/2


// WIP!!
#[allow(dead_code)]
pub mod arclock {

    use std::sync::{Arc, RwLock};

    use serde::{Serialize, Deserialize};
    use serde::de::Deserializer;
    use serde::ser::Serializer;


    pub fn serialize<S, T>(val: &Arc<RwLock<T>>, s: S) -> Result<S::Ok, S::Error>
        where S: Serializer,
              T: Serialize,
    {
        T::serialize(&*val.read().unwrap(), s)
    }


    pub fn deserialize<'de, D, T>(d: D) -> Result<Arc<RwLock<T>>, D::Error>
        where D: Deserializer<'de>,
              T: Deserialize<'de>,
    {
        Ok(Arc::new(RwLock::new(T::deserialize(d)?)))
    }
}
