//! MicroKV module unit testing suite.
//!
//! Defines unit tests for:
//! - simple database interactions
//! - concurrent database interactions

use std::{env, thread};

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

#[test]
fn test_multiple_thread() {
    let mut dir = env::temp_dir();
    dir.push("microkv");

    let kv: MicroKV = MicroKV::open_with_base_path("test_multiple_thread", dir)
        .expect("Failed to create MicroKV from a stored file or create MicroKV for this file")
        .set_auto_commit(true)
        .with_pwd_clear(TEST_PASSWORD.to_string());

    let mut threads = Vec::new();
    for ix in 0..1000 {
        let microkv = kv.clone();
        let key = format!("key-thread-{}", ix);
        let value = format!("value-thread-{}", ix);

        let thread = thread::spawn(move || {
            microkv
                .put(key, &value)
                .expect("failed to put data to MicroKV");
        });
        threads.push(thread);
    }

    for thread in threads {
        thread.join().unwrap();
    }
    for ix in 0..1000 {
        let except_key = format!("key-thread-{}", ix);
        let except_value = format!("value-thread-{}", ix);
        let real_value: String = kv
            .get_unwrap(except_key)
            .expect("failed to get value from MicroKV");
        assert_eq!(real_value, except_value);
    }
}

#[test]
fn test_namespace_with_base_path_and_store() {
    let mut dir = env::temp_dir();
    dir.push("microkv");

    let kv = MicroKV::open_with_base_path("test_namespace_with_base_path_and_store", dir)
        .expect("Failed to create MicroKV from a stored file or create MicroKV for this file")
        .set_auto_commit(true)
        .with_pwd_clear(TEST_PASSWORD.to_string());
    let namespace_default = kv.namespace_default();
    let namespace_one = kv.namespace("one");

    kv.put("foo", &"bar".to_string()).unwrap();
    namespace_default.put("egg", &"gge".to_string()).unwrap();

    namespace_one.put("zoo", &"big".to_string()).unwrap();

    assert_eq!(
        Some("bar".to_string()),
        namespace_default.get("foo").unwrap(),
    );
    assert_eq!(Some("gge".to_string()), kv.get("egg").unwrap());
    let zoo_nsg_def: Option<String> = namespace_default.get("zoo").unwrap();
    assert_eq!(None, zoo_nsg_def);

    let foo_ns_one: Option<String> = namespace_one.get("foo").unwrap();
    let egg_ns_one: Option<String> = namespace_one.get("egg").unwrap();
    assert_eq!(None, foo_ns_one);
    assert_eq!(None, egg_ns_one);
    assert_eq!(Some("big".to_string()), namespace_one.get("zoo").unwrap());

    let keys_df0 = kv.keys().unwrap();
    let keys_df1 = namespace_default.keys().unwrap();
    assert_eq!(keys_df0, keys_df1);
    let keys_ns_one = namespace_one.keys().unwrap();
    assert_ne!(keys_df0, keys_ns_one);

    assert!(keys_df0.contains(&"foo".to_string()));
    assert!(keys_df0.contains(&"egg".to_string()));
    assert!(keys_df1.contains(&"foo".to_string()));
    assert!(keys_df1.contains(&"egg".to_string()));
    assert_eq!(keys_ns_one, vec!["one@zoo"]);
}
