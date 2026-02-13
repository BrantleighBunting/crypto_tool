# AGENTS.md

Guidelines for AI agents working on this codebase.

## Project Overview

This is a Rust workspace with two crates:

- **`crypto`** -- a `no_std` library crate containing cipher implementations (RC4 from scratch, ChaCha20-Poly1305 via `ring`).
- **`rcli`** -- a binary crate providing a CLI for file encryption/decryption using the `crypto` library.

## Architecture

### `crypto` crate

- Must remain `#![no_std]` compatible (use `alloc`, not `std`). The `#![cfg_attr(not(test), no_std)]` attribute allows `std` only in test builds.
- Must maintain `#![forbid(unsafe_code)]` -- no unsafe blocks anywhere.
- RC4 is implemented from scratch in `rc4.rs` with both stateful (`apply_keystream`) and stateless (`apply_keystream_static`) APIs.
- ChaCha20-Poly1305 wraps the `ring` crate's AEAD implementation. Key and nonce generation helpers are provided but callers control when they're used.
- Public API is re-exported from `lib.rs` via `pub use crate::rc4::*`.

### `rcli` crate

- Uses `clap` with derive macros and subcommands (`rc4`, `chacha`, `keygen`).
- Keys are passed as space-separated hex bytes on the command line (with optional `0x` prefix).
- ChaCha20-Poly1305 encrypted files use the format: `nonce (12 bytes) || ciphertext + auth tag`. The nonce is prepended on encrypt and stripped on decrypt.
- File operations are done in-place (read, rewind, truncate, write).

## Conventions

- Keep the `crypto` crate independent of `std` -- anything needing `std` belongs in `rcli` or behind `#[cfg(test)]`.
- Tests for `crypto` live in `rc4.rs` under `#[cfg(test)]` and validate against IETF test vectors (RFC 6229).
- Hex byte CLI args use `num_args` ranges in clap: 5..=256 for RC4, exactly 32 for ChaCha20-Poly1305.

## Build and Test

```sh
cargo build              # Build everything
cargo test -p crypto     # Run crypto library tests
```
