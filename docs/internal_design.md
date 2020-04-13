# Internal Design

This document provides an in-depth technical specification about how
micro-kv is designed and implemented. We split this document into several parts:

```
```

## Technical Description

### What micro-kv Is

### What micro-kv Isn't

micro-kv is _not_ a replacement for relational databases, or even many of the industry-grade key-value store implementations out there. Relational / SQL-based database implementations often are much more feature-ful, and rely on an [ACID](https://en.wikipedia.org/wiki/ACID)-based transactional model that a key-value store may not adhere to.

## Implementation

### Security

> Before reading, consider a look at the [Threat Model]()

### Performance
