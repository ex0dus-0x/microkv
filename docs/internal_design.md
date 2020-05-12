# Internal Design

This document provides an in-depth technical specification about how
microkv is designed and implemented. We split this document into several parts:

## Technical Description

### What microkv Is

microkv is a minimally-built _key-value store_, which enables users and developers to store key-value pairs in a persistent state. microkv is defined such that key-value pairs can index not only serializable primitive types, but also well-formed, structured types, making them an appealing alternative for a full-blown database, which ma

microkv is comprised of a base library, which enables developers to implement alongside their application. This can include...

that also backs the command-line application.

#### Use Cases

(TODO)

### What microkv Isn't

microkv is _not_ a replacement for relational databases, or even many of the industry-grade key-value store implementations out there. Relational / SQL-based database implementations often are much more feature-ful, and rely on an [ACID](https://en.wikipedia.org/wiki/ACID)-based transactional model that a key-value store may not adhere to.

## Implementation

### Security

> Before reading, consider a look at the [Threat Model](threat_model.md) document to understand the types of attacks that microkv aim to mitigate against, and the security invariants that are upheld.

micro

### Performance

(TODO: IOPS performance test for ADTs)

