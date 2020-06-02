# Threat Model

> Last Revision: June 1st, 2020

## Introduction

This is an (informal) specification covering the threat model that __microkv__ aims to mitigate against. While still current a prototype-level implementation, I hope this documentation can help both the reader and I remain cognizant of the security goals and guarentees that is attempting to be achieved, and that future iterations uphold the core principles established.

## Implementation Overview

> For an in-depth look at the implementation, see __Internal Design__.

__microkv__ is developed into two components: a Rust library crate and a command-line application. The library crate serves as the main API for any external developers that choose to implement key-value storage functionality into their implementations. The command-line application harnesses the API in order to provide a client, which can then be deployed as its own microservice (pun), or used locally.

The ideal implementation that __microkv__ should be used for primarily is a secrets manager, like HashiCorp's [Vault](https://www.vaultproject.io/).

## Security Assumptions

* The user of the CLI and/or API is actually using a password when mutating state on the database
* An application is properly securing password inputs from STDIN.

## Threat Model

The threat model is that of an attacker that has gained priviledged access to a machine, and has the capabilities to access the database disk file, and can also trace the process memory mappings for the CLI, or an application utilizing __microkv__. The key-value instance aims to mitigate these attackers by ensuring that whenever interactions are made with the underlying storage structure, values are immediately encrypted and authenticated with [XSalsa20-Poly1305](https://crypto.stackexchange.com/questions/33013/is-xsalsa20-poly1305-siv-a-reasonable-choice-for-nonce-misuse-resistant-authenti), which is a strong and modern authenticated encryption scheme.

## Questions or Concerns?

Reach out to me!
