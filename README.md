# micro-kv

> NOTE: Functionally complete, but still WIP!

a minimal and persistent key-value store designed with security in mind.

## intro

__micro-kv__ is a persistent key-value store implemented in Rust, aiming to maintain a balance between security and performance. It is built out of a yearning to learn more about the intricacies of distributed systems, databases, and secure persistent storage.

While __micro-kv__ shouldn't be used in large-scale environments that facilitate an insane volume of transactional interactions,
it is still optimal for use in a production-grade system/application that may not require the complex luxuries of a
full-blown database or even industry-standard KV-store like Redis or LevelDB.

## use cases

Here are some use-cases that you may want to use __micro-kv__ for:

* Local persistent serialization for configurations
* Secrets management for a single-process application
* In-transit encrypted storage for multi-peer communication

## features

* __Performant__

__micro-kv__'s underlying map structure is based off of @bluss's [indexmap](https://github.com/bluss/indexmap) implementation, which offers performance on par with built-in `HashMap`'s amortized constant runtime, but can also provided sorted key iteration, similar to the less-performant `BTreeMap`. This provides a strong balance between performance and functionality.

When reading and persisting to disk, the key-value store Uses `bincode` for fast de/serialization of the underlying structures, allowing users to insert any serializable structure without worring about incured overhead for persisting.

* __Secure__

`microkv` acts almost in the sense of a secure enclave with any stored information. First, inserted values are immediately encryped using authenticated encryption with XSalsa20 (stream cipher) and Poly1305 (HMAC) from `sodiumoxide`, guarenteeing security and integrity. Encryped values in-memory are also memory-locked with `mlock`, and securely zeroed when destroyed to avoid persistence in memory pages.

* __Small__

`microkv` is


## design

To see details about how micro-kv is internally implemented check out the `docs/` folder for the following documentation:

* Threat Model
* Internal Design

(TODO)

## usage

You can use micro-kv as both a library crate or an executable that serves a local server instance.

To install locally, simply clone the repository and install with `cargo`:

```
$ cargo install --path .
```

Run `cargo test` to validate that the test suite works (TODO):

```
$ cargo test
```

## TODO

* tests!
* use a `Rwlock` instead of `Mutex` for robust read-write locking routines (ie. `kv.lock_read(callback: Fn())`)
* build client and server cli
* other helper database operations (iterators, cleanup)
* finalize unified error handling types and routines
* threat model and design docs

## license

[mit license](https://codemuch.tech/license.txt)
