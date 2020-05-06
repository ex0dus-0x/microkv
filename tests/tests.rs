//! tests.rs
//!
//!     MicroKV module unit testing suite.
//!
//!     Defines unit tests for:
//!         - simple database interactions
//!         - concurrent database interactions

extern crate microkv;
extern crate serde;

use microkv::MicroKV;
use serde::{Deserialize, Serialize};

static TEST_PASSWORD: &str = "TEST_PASSWORD";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TestStruct {
    pub id: u64,
    pub name: String,
}

#[test]
fn test_simple() {
    let kv: MicroKV = MicroKV::new("test_simple").with_pwd_clear(TEST_PASSWORD.to_string());

    let key: &str = "some_key";
    let value: u64 = 12345;
    kv.put(key, value);

    let res: u64 = kv.get::<u64>(key).unwrap();
    assert_eq!(value, res);
}

#[test]
fn test_complex() {
    let kv: MicroKV = MicroKV::new("test_complex").with_pwd_clear(TEST_PASSWORD.to_string());

    let key: &str = "some_key";
    let value = TestStruct {
        id: 13,
        name: String::from("Bob"),
    };
    kv.put(key, value);

    let res: TestStruct = kv.get::<TestStruct>(key).unwrap();
    assert_eq!(value.id, res.id);
    assert_eq!(value.name, res.name);
}
