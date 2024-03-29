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

Minimal and persistent key-value store designed with security in mind.

## Introduction

__microkv__ is a minimal and persistent key-value store designed with security in mind, built to prioritize secure storage for client-side application. I created this project out of a yearning to learn more about the intricacies of distributed systems, databases, and secure persistent storage.

While __microkv__ shouldn't be used in large-scale environments that facilitate an insane volume of transactional interactions,
it is still optimal for use in a production-grade system/application that may not require the complex luxuries of a
full-blown database or even industry-standard KV-store like Redis or LevelDB.

## Features

* __Performant__

__microkv__'s underlying map structure is based off of @bluss's [indexmap](https://github.com/bluss/indexmap) implementation, which offers performance on par with built-in `HashMap`'s amortized constant runtime, but can also provided sorted key iteration, similar to the less-performant `BTreeMap`. This provides a strong balance between performance and functionality.

When reading and persisting to disk, the key-value store uses `bincode` for fast de/serialization of the underlying structures, allowing users to insert any serializable structure without worrying about incurred overhead for storing complex data structures.

* __Secure__

__microkv__ acts almost in the sense of a secure enclave with any stored information. First, inserted values are immediately encryped using authenticated encryption with XSalsa20 (stream cipher) and Poly1305 (HMAC) from `sodiumoxide`, guarenteeing security and integrity. Encryped values in-memory are also memory-locked with `mlock`, and securely zeroed when destroyed to avoid persistence in memory pages.

__microkv__ also provides locking support with `RwLock`s, which utilize mutual exclusion like mutexes, but robust in the sense that concurrent read locks can be held, but only one writer lock can be held at a time. This helps remove thread-safety and data race concerns, but also enables multiple read accesses safely.

* __Small__

At its core, __microkv__ is implemented in ~500 LOCs, making the implementation portable and auditable. It remains faithfully opinionated, meaning it will not offer extensions to other serializable formats, or any other user-involved configurability, allowing it to work right out of the box.

## Usage

To install locally, simply clone the repository and install with `cargo`:

```
# .. from crates.io
$ cargo install microkv

# .. or locally
$ git clone https://github.com/ex0dus-0x/microkv
$ cargo install --path .
```

Here's example usage of the `microkv` library crate:

```rust
use microkv::MicroKV;

#[derive(Serialize, Deserialize, Debug)]
struct Identity {
    uuid: u32,
    name: String,
    sensitive_data: String,
}


fn main() {
    let unsafe_pwd: String = "my_password_123";

    // initialize in-memory database with (unsafe) cleartext password
    let db: MicroKV = MicroKV::new("my_db")
        .with_pwd_clear(unsafe_pwd);

    // ... or backed by disk, with auto-commit per transaction
    let db: MicroKV = MicroKV::open_with_base_path("my_db_on_disk", SOME_PATH)
        .expect("Failed to create MicroKV from a stored file or create MicroKV for this file")
        .set_auto_commit(true)
        .with_pwd_clear(unsafe_pwd);

    // simple interaction to default namespace
    db.put("simple", 1);
    print("{}", db.get_unwrap("simple").unwrap());
    db.delete("simple");

    // more complex interaction to default namespace
    let identity = Identity {
        uuid: 123,
        name: String::from("Alice"),
        sensitive_data: String::from("something_important_here")
    };
    db.put("complex", identity);
    let stored_identity: Identity = db.get_unwrap("complex").unwrap();
    println!("{:?}", stored_identity);
    db.delete("complex");
}
```

__microkv__ also supports transactions on other namespaces to support grouping and
organizing keys (thanks @fewensa!):

```rust
    let namespace_one = db.namespace("one");
    namespace_one.put("zoo", &"big".to_string()).unwrap();
```

__microkv__ also includes a [simple command line application](https://github.com/ex0dus-0x/microkv/tree/master/cli)
that is installed alongside the package. While not entirely useful at the moment, future plans are to be able 
to integrate it such that it can be exposed through a Docker container.

## Contributions

Interested on improving the state of this project? Check out the [issue tracker](https://github.com/ex0dus-0x/microkv/issues) for what we need help on!

## License

[MIT license](https://codemuch.tech/docs/license.txt)
