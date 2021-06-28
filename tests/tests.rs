//! MicroKV module unit testing suite.
//!
//! Defines unit tests for:
//! - simple database interactions
//! - concurrent database interactions

use std::env;

use serde::{Deserialize, Serialize};

use microkv::MicroKV;

// constants used throughout each test case
static KEY_NAME: &str = "some_key";
static TEST_PASSWORD: &str = "TEST_PASSWORD";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TestStruct {
    pub id: u64,
    pub name: String,
}

#[test]
fn test_simple_integral() {
    let kv: MicroKV =
        MicroKV::new("test_simple_integral").with_pwd_clear(TEST_PASSWORD.to_string());

    // insert uint value
    let value: u64 = 12345;
    kv.put(KEY_NAME, &value).expect("cannot insert value");

    // get key and validate
    let res: u64 = kv.get_unwrap(KEY_NAME).expect("cannot retrieve value");
    assert_eq!(value, res);

    // delete value
    kv.delete(KEY_NAME).expect("cannot remove value");

    // insert int value
    let value: i32 = -12345;
    kv.put(KEY_NAME, &value).expect("cannot insert value");

    // get key and validate
    let res: i32 = kv.get_unwrap(KEY_NAME).expect("cannot retrieve value");
    assert_eq!(value, res);
}

#[test]
fn test_simple_string() {
    let kv: MicroKV = MicroKV::new("test_simple_string").with_pwd_clear(TEST_PASSWORD.to_string());

    // insert String value
    let value: String = String::from("my value");
    kv.put(KEY_NAME, &value).expect("cannot insert value");

    // get key and validate
    let res: String = kv.get_unwrap(KEY_NAME).expect("cannot retrieve value");
    assert_eq!(value, res);
}

#[test]
fn test_complex_struct() {
    let kv: MicroKV = MicroKV::new("test_complex_struct").with_pwd_clear(TEST_PASSWORD.to_string());

    let value = TestStruct {
        id: 13,
        name: String::from("Bob"),
    };
    kv.put(KEY_NAME, &value).expect("cannot insert value");

    let res: TestStruct = kv.get_unwrap(KEY_NAME).expect("cannot retrieve value");
    assert_eq!(value.id, res.id);
    assert_eq!(value.name, res.name);
}

#[test]
fn test_base_path_with_auto_commit() {
    let mut dir = env::temp_dir();
    dir.push("microkv");

    let kv: MicroKV = MicroKV::open_with_base_path("test_base_path_with_auto_commit", dir)
        .expect("Failed to create MicroKV from a stored file or create MicroKV for this file")
        .set_auto_commit(true)
        .with_pwd_clear(TEST_PASSWORD.to_string());

    // insert String value
    let value: String = String::from("my value");
    kv.put(KEY_NAME, &value).expect("cannot insert value");

    // get key and validate
    let res: Option<String> = kv.get(KEY_NAME).expect("cannot retrieve value");
    println!("{:?}", res);
    assert_eq!(Some(value), res);
}
