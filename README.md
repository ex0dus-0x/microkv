# micro-kv

a minimal and persistent key-value store designed with security and performance in mind

## intro

__micro-kv__ is a persistent key-value store implemented in Rust, aiming to maintain a balance between security and performance. It is built out of a yearning to learn more about the intricacies of distributed systems and databases, and how security plays a role into the overall picture.

While __micro-kv__ shouldn't be used in large-scale environments that facilitate an insane volume of transactional interactions, it is still optimal for use in a production-grade system/application that may not require the complex luxuries of a full-blown database or even industry-standard KV-store like Redis or LevelDB.

## use cases

Here are some use-cases that you may want to use __micro-kv__ for:

* Local persistent serialization for configurations
* Secrets management for a single-process application
* In-transit encrypted storage for multi-node communications

## features

* __Fast__ - uses a

* __Secure__ - TODO

* __Small__ - a small and auditable codebase means a faster runtime with a reduced atteck surface


## design

To see details about how micro-kv is internally implemented check out the `docs/` folder for the following documentation:

* Threat Model
* Internal Design

## usage

You can use micro-kv as both a library crate or an executable that serves a local server instance.

To install, simply clone the repository and install with `cargo`:

```
$ cargo install --path .
```

Run `cargo test` to validate that the test suite works:

```
$ cargo test
```

## license

[mit license](https://codemuch.tech/license.txt)
