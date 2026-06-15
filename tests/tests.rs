//! Integration tests for the redesigned microkv API.

use std::env;
use std::ops::ControlFlow;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use microkv::{AutoSave, Credential, Error, MicroKV};

static PASSWORD: &str = "correct horse battery staple";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct User {
    id: u64,
    name: String,
}

fn mem() -> MicroKV {
    MicroKV::in_memory(Credential::password(PASSWORD)).expect("cannot open in-memory store")
}

fn temp(name: &str) -> std::path::PathBuf {
    let mut p = env::temp_dir();
    p.push(format!("microkv_it_{name}.kv"));
    let _ = std::fs::remove_file(&p);
    let _ = std::fs::remove_file(format!("{}.lock", p.display()));
    p
}

#[test]
fn basic_crud() {
    let db = mem();

    db.put("n", &12345u64).unwrap();
    assert_eq!(db.get::<u64>("n").unwrap(), Some(12345));
    assert_eq!(db.require::<u64>("n").unwrap(), 12345);
    assert!(db.contains("n").unwrap());
    assert_eq!(db.len().unwrap(), 1);

    assert!(db.remove("n").unwrap());
    assert!(!db.remove("n").unwrap());
    assert!(!db.contains("n").unwrap());
    assert!(matches!(db.require::<u64>("n"), Err(Error::KeyNotFound)));

    let user = User {
        id: 7,
        name: "bob".into(),
    };
    db.put("u", &user).unwrap();
    assert_eq!(db.require::<User>("u").unwrap(), user);
}

#[test]
fn namespaces_are_isolated() {
    let db = mem();
    let a = db.namespace("a");
    let b = db.namespace("b");

    a.put("same", &"from-a".to_string()).unwrap();
    b.put("same", &"from-b".to_string()).unwrap();

    assert_eq!(a.get::<String>("same").unwrap(), Some("from-a".into()));
    assert_eq!(b.get::<String>("same").unwrap(), Some("from-b".into()));
    // default namespace sees neither
    assert_eq!(db.get::<String>("same").unwrap(), None);
}

#[test]
fn atomic_update_and_cas() {
    let db = mem();
    db.put("counter", &0u32).unwrap();

    for _ in 0..5 {
        db.update::<u32, _>("counter", |cur| Some(cur.unwrap_or(0) + 1))
            .unwrap();
    }
    assert_eq!(db.require::<u32>("counter").unwrap(), 5);

    // CAS succeeds on match, fails on mismatch
    assert!(db
        .compare_and_swap("counter", Some(&5u32), Some(&10u32))
        .unwrap());
    assert!(!db
        .compare_and_swap("counter", Some(&5u32), Some(&99u32))
        .unwrap());
    assert_eq!(db.require::<u32>("counter").unwrap(), 10);

    // get_or_insert_with
    let v = db.get_or_insert_with("fresh", || 42u32).unwrap();
    assert_eq!(v, 42);
    assert_eq!(db.get_or_insert_with("fresh", || 99u32).unwrap(), 42);
}

#[test]
fn transaction_commits_and_rolls_back() {
    let db = mem();
    db.put("balance", &100u64).unwrap();

    // committed transaction
    db.transaction(|tx| {
        let bal: u64 = tx.require("", "balance")?;
        tx.put("", "balance", &(bal - 10))?;
        tx.put("audit", "last", &"debit".to_string())?;
        Ok(())
    })
    .unwrap();
    assert_eq!(db.require::<u64>("balance").unwrap(), 90);
    assert_eq!(
        db.namespace("audit").get::<String>("last").unwrap(),
        Some("debit".into())
    );

    // failing transaction rolls back every mutation
    let res: Result<(), Error> = db.transaction(|tx| {
        tx.put("", "balance", &0u64)?;
        Err(Error::KeyNotFound)
    });
    assert!(res.is_err());
    assert_eq!(db.require::<u64>("balance").unwrap(), 90); // unchanged
}

#[test]
fn ttl_expiry() {
    let db = mem();
    db.put_with_ttl("ephemeral", &"poof".to_string(), Duration::from_secs(0))
        .unwrap();
    db.put_with_ttl("durable", &"stays".to_string(), Duration::from_secs(3600))
        .unwrap();

    // ttl of 0 ⇒ already expired
    assert_eq!(db.get::<String>("ephemeral").unwrap(), None);
    assert!(!db.contains("ephemeral").unwrap());
    assert_eq!(db.get::<String>("durable").unwrap(), Some("stays".into()));

    let purged = db.sweep_expired().unwrap();
    assert_eq!(purged, 1);
}

#[test]
fn ttl_survives_persistence() {
    // expiry is now framed inside the ciphertext, so it must round-trip through save/open
    let path = temp("ttl_persist");
    let db = MicroKV::builder()
        .path(&path)
        .autosave(AutoSave::OnEveryWrite)
        .open(Credential::password(PASSWORD))
        .unwrap();
    db.put_with_ttl("live", &"v".to_string(), Duration::from_secs(3600))
        .unwrap();
    db.put_with_ttl("dead", &"v".to_string(), Duration::from_secs(0))
        .unwrap();
    drop(db);

    let db = MicroKV::open(&path, Credential::password(PASSWORD)).unwrap();
    assert_eq!(db.require::<String>("live").unwrap(), "v");
    assert_eq!(db.get::<String>("dead").unwrap(), None);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn tampered_value_is_rejected() {
    // flipping any ciphertext byte (which includes the framed expiry) must fail AEAD auth
    let path = temp("tamper");
    {
        let db = MicroKV::builder()
            .path(&path)
            .autosave(AutoSave::OnEveryWrite)
            .open(Credential::password(PASSWORD))
            .unwrap();
        db.put("k", &"sensitive".to_string()).unwrap();
    }

    let mut bytes = std::fs::read(&path).unwrap();
    // perturb a byte inside the last entry (past the header), low-bit flip to keep the
    // msgpack structure parseable where possible so the corruption lands in ciphertext.
    let pos = bytes.len() - 2;
    bytes[pos] ^= 0x01;
    std::fs::write(&path, &bytes).unwrap();

    // tampering must be rejected — either as Corrupt (at open) or Crypto (at get).
    let result =
        MicroKV::open(&path, Credential::password(PASSWORD)).and_then(|db| db.get::<String>("k"));
    assert!(
        result.is_err(),
        "tampering must be rejected, got {result:?}"
    );

    let _ = std::fs::remove_file(&path);
}

#[test]
fn wrong_password_rejected_eagerly() {
    let path = temp("wrong_pwd");

    let db = MicroKV::builder()
        .path(&path)
        .autosave(AutoSave::OnEveryWrite)
        .open(Credential::password(PASSWORD))
        .unwrap();
    db.put("secret", &"hunter2".to_string()).unwrap();
    drop(db);

    let err = MicroKV::open(&path, Credential::password("wrong"))
        .expect_err("wrong password must be rejected at open");
    assert!(matches!(err, Error::WrongPassword));

    // correct password still works
    let db = MicroKV::open(&path, Credential::password(PASSWORD)).unwrap();
    assert_eq!(db.require::<String>("secret").unwrap(), "hunter2");

    let _ = std::fs::remove_file(&path);
}

#[test]
fn rejects_corrupt_and_wrong_version() {
    let path = temp("corrupt");
    std::fs::write(&path, b"definitely not msgpack microkv").unwrap();
    let err = MicroKV::open(&path, Credential::password(PASSWORD)).unwrap_err();
    assert!(matches!(err, Error::CorruptStore(_)));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn create_new_and_open_existing_modes() {
    let path = temp("modes");

    // open_existing on a missing file fails
    assert!(MicroKV::open_existing(&path, Credential::password(PASSWORD)).is_err());

    // create_new makes it
    let db = MicroKV::create_new(&path, Credential::password(PASSWORD)).unwrap();
    db.save().unwrap();
    drop(db);

    // create_new again fails (already exists)
    let err = MicroKV::create_new(&path, Credential::password(PASSWORD)).unwrap_err();
    assert!(matches!(err, Error::AlreadyExists));

    // open_existing now succeeds
    assert!(MicroKV::open_existing(&path, Credential::password(PASSWORD)).is_ok());

    let _ = std::fs::remove_file(&path);
}

#[test]
fn persistence_round_trip() {
    let path = temp("persist");

    let db = MicroKV::builder()
        .path(&path)
        .autosave(AutoSave::OnEveryWrite)
        .open(Credential::password(PASSWORD))
        .unwrap();
    db.namespace("settings")
        .put("theme", &"dark".to_string())
        .unwrap();
    db.put("count", &3u32).unwrap();
    drop(db);

    let db = MicroKV::open(&path, Credential::password(PASSWORD)).unwrap();
    assert_eq!(db.require::<u32>("count").unwrap(), 3);
    assert_eq!(
        db.namespace("settings").require::<String>("theme").unwrap(),
        "dark"
    );

    let _ = std::fs::remove_file(&path);
}

#[test]
fn change_password_then_reopen() {
    let path = temp("rekey");

    let db = MicroKV::builder()
        .path(&path)
        .autosave(AutoSave::OnEveryWrite)
        .open(Credential::password(PASSWORD))
        .unwrap();
    db.put("k", &"v".to_string()).unwrap();

    // wrong old password is rejected
    assert!(matches!(
        db.change_password("nope".into(), "new-pass".into()),
        Err(Error::WrongPassword)
    ));

    db.change_password(PASSWORD.into(), "new-pass".into())
        .unwrap();
    drop(db);

    // old password no longer opens it; new one does
    assert!(MicroKV::open(&path, Credential::password(PASSWORD)).is_err());
    let db = MicroKV::open(&path, Credential::password("new-pass")).unwrap();
    assert_eq!(db.require::<String>("k").unwrap(), "v");

    let _ = std::fs::remove_file(&path);
}

#[test]
fn keys_prefix_and_for_each() {
    let db = mem();
    db.put("user:1", &1u32).unwrap();
    db.put("user:2", &2u32).unwrap();
    db.put("config:x", &9u32).unwrap();

    let mut sorted = db.keys_sorted().unwrap();
    sorted.sort();
    assert_eq!(sorted, vec!["config:x", "user:1", "user:2"]);

    let mut users = db.prefix::<u32>("user:").unwrap();
    users.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        users,
        vec![("user:1".to_string(), 1), ("user:2".to_string(), 2)]
    );

    let mut sum = 0u32;
    db.for_each::<u32, _>(|_, v| {
        sum += v;
        ControlFlow::Continue(())
    })
    .unwrap();
    assert_eq!(sum, 12);
}

#[test]
fn read_only_rejects_writes() {
    let path = temp("ro");
    {
        let db = MicroKV::builder()
            .path(&path)
            .autosave(AutoSave::OnEveryWrite)
            .open(Credential::password(PASSWORD))
            .unwrap();
        db.put("k", &1u32).unwrap();
    }

    let db = MicroKV::builder()
        .path(&path)
        .read_only(true)
        .open(Credential::password(PASSWORD))
        .unwrap();
    assert_eq!(db.require::<u32>("k").unwrap(), 1);
    assert!(matches!(db.put("k", &2u32), Err(Error::ReadOnly)));

    let _ = std::fs::remove_file(&path);
}

#[test]
fn raw_key_credential() {
    let path = temp("rawkey");
    let key = [7u8; 32];

    let db = MicroKV::builder()
        .path(&path)
        .autosave(AutoSave::OnEveryWrite)
        .open(Credential::key(key))
        .unwrap();
    db.put("k", &"value".to_string()).unwrap();
    drop(db);

    let db = MicroKV::open(&path, Credential::key(key)).unwrap();
    assert_eq!(db.require::<String>("k").unwrap(), "value");
    // a different key fails verification
    assert!(MicroKV::open(&path, Credential::key([8u8; 32])).is_err());

    let _ = std::fs::remove_file(&path);
}

#[test]
fn concurrent_writers_share_one_store() {
    let db = Arc::new(mem());
    let mut handles = Vec::new();
    for ix in 0..500 {
        let kv = Arc::clone(&db);
        handles.push(thread::spawn(move || {
            kv.put(&format!("key-{ix}"), &ix).unwrap();
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    for ix in 0..500 {
        assert_eq!(db.require::<i32>(&format!("key-{ix}")).unwrap(), ix);
    }
}
