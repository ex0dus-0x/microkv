# microkv

[![Actions][actions-badge]][actions-url]
[![crates.io version][crates-microkv-badge]][crates-microkv]
[![Docs][docs-badge]][docs.rs]

[actions-badge]: https://github.com/ex0dus-0x/microkv/workflows/CI/badge.svg?branch=master
[actions-url]: https://github.com/ex0dus-0x/microkv/actions

[crates-microkv-badge]: https://img.shields.io/crates/v/microkv.svg
[crates-microkv]: https://crates.io/crates/microkv

[docs-badge]: https://docs.rs/microkv/badge.svg
[docs.rs]: https://docs.rs/microkv

__microkv__ is a small key-value store for sensitive in-memory data, aiming to miminize its exposure to local attackers who can snoop on your application's virtual memory.

## Features

* Key material held in memory-locked, auto-zeroed storage (`memsec`).
* Entries are encrypted with ChaCha20-Poly1305 under a key derived via `scrypt` / `argon2` / raw keys.
* Anti-tampering through authenticated file header when persisted to disk.
* Other database features: isolated namespaces ("trees"), atomic operations, rollback-on-error transactions, password rotation, and TTl/expiry.

## Anti-features

* No plaintext mode — a credential is mandatory.
* No command line interface, server, or networking.
* Does not defend against an attacker with full kernel page-table read/write.

## Usage

In your `Cargo.toml`:

```toml
[dependencies]
microkv = "0.3.0"
```

### Basic usage

```rust
use microkv::{MicroKV, Credential};

// open (or create) an encrypted store on disk
let db = MicroKV::open("store.kv", Credential::password("p@ssw0rd"))?;

db.put("name", &"test".to_string())?;          // any Serialize value
let name: String = db.require("name")?;         // errors if absent
let maybe: Option<u32> = db.get("count")?;      // None if absent
db.remove("name")?;

db.save()?;                                     // flush to disk
```

`MicroKV` derefs to its default namespace, so `db.put(..)` and `db.namespace("").put(..)` are the same thing.

### In-memory store

```rust
use microkv::{MicroKV, Credential};

// ephemeral store, never touches disk
let cache = MicroKV::in_memory(Credential::password("p@ssw0rd"))?;
```

Using `*_with` methods, we can also pass a `Config` for customizations:

```rust
use microkv::{MicroKV, Credential, Config, AutoSave, LockMode, KdfParams};

let db = MicroKV::open_with(
    "store.kv",
    Credential::password("p@ssw0rd"),
    Config {
        autosave: AutoSave::OnEveryWrite,   // persist after each write
        lock_mode: LockMode::Exclusive,     // cross-process file lock
        kdf: KdfParams::sensitive(),        // stronger KDF for new stores
        ..Default::default()
    },
)?;

// open read-only: writes return Error::ReadOnly
let ro = MicroKV::open_with(
    "store.kv",
    Credential::password("p@ssw0rd"),
    Config { read_only: true, ..Default::default() },
)?;
```

There are also `create_new` / `open_existing` (and their `*_with` variants) when you want to fail instead of silently creating or opening.

### Namespacing

```rust
let users = db.namespace("users");
let sessions = db.namespace("sessions");

users.put("alice", &42u32)?;
sessions.put("alice", &"token-xyz".to_string())?;   // same key, no collision

let id: Option<u32> = users.get("alice")?;
```

### Atomic updates

```rust
// read-modify-write under one lock (no get/put race)
db.update::<u32, _>("counter", |cur| Some(cur.unwrap_or(0) + 1))?;

// insert only if missing
let v: u32 = db.get_or_insert_with("seed", || 7)?;

// compare-and-swap
let swapped = db.compare_and_swap("counter", Some(&1u32), Some(&2u32))?;
```

### Transactions

All operations apply together; returning `Err` rolls everything back. Namespaces are
addressed explicitly (`""` is the default).

```rust
db.transaction(|tx| {
    let balance: u64 = tx.require("", "balance")?;
    tx.put("", "balance", &(balance - 10))?;
    tx.put("audit", "last", &"debit".to_string())?;
    Ok(())
})?;
```

### Expiring entries (TTL)

```rust
use std::time::Duration;

db.put_with_ttl("otp", &"123456".to_string(), Duration::from_secs(60))?;
let purged = db.sweep_expired()?;   // drop expired entries
```

### Iteration

```rust
let all_keys: Vec<String> = db.keys()?;
let sorted: Vec<String> = db.keys_sorted()?;

// decrypt every entry matching a prefix
let active: Vec<(String, u32)> = db.namespace("users").prefix("admin:")?;
```

### Password rotation

```rust
// verify the old password, then re-encrypt everything under the new one
db.change_password("p@ssw0rd", "even-better-passphrase")?;
```

## License

[MIT license](https://codemuch.tech/docs/license.txt)
