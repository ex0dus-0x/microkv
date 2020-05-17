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

> NOTE: Functionally complete, but still WIP!

a minimal and persistent key-value store designed with security in mind.

## intro

__microkv__ is a persistent key-value store implemented in Rust, aiming to maintain a balance between security and performance. It is built out of a yearning to learn more about the intricacies of distributed systems, databases, and secure persistent storage.

While __microkv__ shouldn't be used in large-scale environments that facilitate an insane volume of transactional interactions,
it is still optimal for use in a production-grade system/application that may not require the complex luxuries of a
full-blown database or even industry-standard KV-store like Redis or LevelDB.

## use cases

Here are some specific use-cases that you may want to use __microkv__ for:

* Local persistent serialization for sensitive configurations
* Secrets management for a single-process application
* License key management

## features

* __Performant__

__microkv__'s underlying map structure is based off of @bluss's [indexmap](https://github.com/bluss/indexmap) implementation, which offers performance on par with built-in `HashMap`'s amortized constant runtime, but can also provided sorted key iteration, similar to the less-performant `BTreeMap`. This provides a strong balance between performance and functionality.

When reading and persisting to disk, the key-value store Uses `bincode` for fast de/serialization of the underlying structures, allowing users to insert any serializable structure without worrying about incurred overhead for storing complex data structures.

* __Secure__

__microkv__ acts almost in the sense of a secure enclave with any stored information. First, inserted values are immediately encryped using authenticated encryption with XSalsa20 (stream cipher) and Poly1305 (HMAC) from `sodiumoxide`, guarenteeing security and integrity. Encryped values in-memory are also memory-locked with `mlock`, and securely zeroed when destroyed to avoid persistence in memory pages.

__microkv__ also provides locking support with `RwLock`s, which utilize mutual exclusion like mutexes, but robust in the sense that concurrent read locks can be held, but only one writer lock can be held at a time. This helps remove thread-safey and data race concerns, but also enables multiple read accesses safely.

* __Small__

At its core, __microkv__ is implemented in ~500 LOCs, making the implementation portable and auditable. It does not offer extensions to other serializable formats, or any other user-involved configurability, meaning it will work right out of the box.

## design

(Still WIP)

To see details about how microkv is internally implemented check out the `docs/` folder for the following documentation:

* [Threat Model](https://github.com/ex0dus-0x/microkv/blob/master/docs/threat_model.md)
* [Internal Design](https://github.com/ex0dus-0x/microkv/blob/master/docs/internal_design.md)


## usage

You can use microkv as both a library crate for your implementation, or a standalone CLI.

To install locally, simply clone the repository and install with `cargo`:

```
# .. from crates.io
$ cargo install microkv

# .. or locally
$ git clone https://github.com/ex0dus-0x/microkv
$ cargo install --path .
```

Run `cargo test` to validate that the test suite works:

```
$ cargo test
```

### library

Here's example usage of the `microkv` library crate:

```rust
extern crate microkv;

use microkv::MicroKV;

#[derive(Serialize, Deserialize, Debug)]
struct Identity {
    uuid: u32,
    name: String,
    sensitive_data: String,
}


fn main() -> {
    let unsafe_pwd: String = "my_password_123";

    // initialize database with (unsafe) cleartext password
    let db: MicroKV = MicroKV::new("my_db")
        .with_password_clear(unsafe_pwd);

    // simple interaction
    db.put("simple", 1);
    print("{}", db.get::<i32>("simple").unwrap());
    db.delete("simple");

    // more complex interaction
    let identity = Identity {
        uuid: 123,
        name: String::from("Alice"),
        sensitive_data: String::from("something_important_here")
    };
    db.put("complex", identity);
    print("{:?}", db.get::<Identity>("complex").unwrap());
    db.delete("complex");
}
```

### cli

(TODO)

## inspirations

* [rustbreak](https://github.com/TheNeikos/rustbreak)
* [Writing a simple database in Rust](https://nikhilism.com/post/2016/writing-simple-database-in-rust-part-1/)

## TODO

* [ ] Unit tests
* [ ] Client CLI
* [ ] Performance Benchmarks against other ADTs
* [x] Other helper DB operations
* [ ] Incorporate write-append logging/snapshotting
* [ ] Threat model and design docs

## license

[mit license](https://codemuch.tech/license.txt)
