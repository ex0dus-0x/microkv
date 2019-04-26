# tinystore

experimental key-value store in Rust

## intro

__tinystore__ is an experimental key-value store implementation in Rust that harnesses native capabilities like locking and hashing while relying on the JSON serialization format for persistence.

## features

* easy to use and interface
* mutex locking during DB interactions
* SHA-256 hashing
* (TODO) re-do log
* (TODO) serialize ADSs

## build

TODO: re-implement tests, improve docs, and add `examples/`

```
$ cargo test
```

## license

[mit](https://codemuch.tech/license.txt)
