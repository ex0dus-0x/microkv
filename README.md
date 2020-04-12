# tinystore

key-value store in Rust designed with security in mind

## intro

__tinystore__ is an experimental key-value store implementation in Rust that harnesses native capabilities like locking and hashing while relying on the JSON serialization format for persistence.

## features

* easy to use and interface
* mutex locking during DB interactions
* SHA-256 hashing
* (TODO) re-do log
* (TODO) serialize ADSs

## design

## use cases

## usage

To install, simply clone the repository and install with `cargo`:

```
$ cargo install --path .
```

Run `cargo test` to validate that the test suite works:

```
$ cargo test
```

TODO: fuzzing

## license

[mit](https://codemuch.tech/license.txt)
