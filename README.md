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

secure minimal key-value store

## intro

__microkv__ is a small key-value store for sensitive in-memory data, aiming to miminize its exposure to local attackers who can sniff on your application's virtual memory.

## features

* Always encrypted: values are sealed with ChaCha20-Poly1305 under a key derived via `scrypt` (or `argon2` behind a feature flag), or supplied directly.
* Ciphertext is bound to its `(namespace, key)` and the file header is authenticated, so tampering and blob-swapping are detected.
* Isolated namespaces ("trees"), atomic operations (`update`, `compare_and_swap`), and rollback-on-error transactions.
* Atomic, crash-safe persistence with optional cross-process file locking; password rotation and TTL/expiry.
* Key material held in memory-locked, auto-zeroed storage (`memsec`).

## anti-features

* No plaintext mode — a credential is mandatory.
* No command line interface, server, or networking.
* Does not defend against an attacker with full page-table read/write.

## usage

In your `Cargo.toml`:

```toml
[dependencies]
microkv = "0.3.0"
```

```rust
use microkv::{MicroKV, Credential};

// open (or create) an encrypted store on disk
let db = MicroKV::open("store.kv", Credential::password("p@ssw0rd"))?;

db.put("name", &"test".to_string())?;
let name: String = db.require("name")?;

// isolated namespace
let users = db.namespace("users");
users.put("id-1", &42u32)?;

db.save()?;
```

## License

[MIT license](https://codemuch.tech/docs/license.txt)
