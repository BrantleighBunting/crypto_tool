# crypto_tool

A Rust workspace implementing stream ciphers and authenticated encryption, built as part of [High Assurance Rust](https://highassurance.rs/). The project goes beyond the book's RC4 coverage by adding ChaCha20-Poly1305 authenticated encryption (per [RFC 8439](https://tools.ietf.org/html/rfc8439)).

## Safety Properties

- `#![forbid(unsafe_code)]` -- no unsafe blocks permitted in any crate
- `#![no_std]` compatible -- the `crypto` library builds without the standard library (uses `alloc` only)

## Workspace Structure

```
crypto_tool/
  crypto/     # Library crate: cipher implementations
    src/
      lib.rs  # ChaCha20-Poly1305 (via ring), key/nonce generation
      rc4.rs  # RC4 stream cipher (from-scratch implementation)
  rcli/       # Binary crate: CLI for file encryption/decryption
    src/
      main.rs
```

## Supported Ciphers

| Cipher | Type | Key Size | Notes |
|---|---|---|---|
| RC4 | Stream cipher | 40--2048 bit (5--256 bytes) | Symmetric XOR -- same operation encrypts and decrypts |
| ChaCha20-Poly1305 | AEAD | 256 bit (32 bytes) | Authenticated encryption with 96-bit nonce; uses `ring` |

## CLI Usage

### Generate a ChaCha20-Poly1305 key

```sh
rcli keygen
# Output: 32 space-separated hex bytes
```

### Encrypt / decrypt with ChaCha20-Poly1305

```sh
# Encrypt (nonce is generated and prepended to the file automatically)
rcli chacha --file secret.txt --key $(rcli keygen) --encrypt

# Decrypt (reads the 12-byte nonce prefix, then decrypts the remainder)
rcli chacha --file secret.txt --key <same 32 hex bytes> --decrypt
```

### Encrypt / decrypt with RC4

```sh
# RC4 is symmetric -- run the same command to encrypt or decrypt
rcli rc4 --file secret.txt --key 0x4b 0x8e 0x29 0x87 0x80
```

### Install

```sh
cargo install --path rcli
```

## Build and Test

```sh
# Build the entire workspace
cargo build

# Run crypto library tests (includes IETF RC4 test vectors from RFC 6229)
cargo test -p crypto
```

## Dependencies

- [ring](https://crates.io/crates/ring) -- ChaCha20-Poly1305 AEAD and secure random number generation
- [clap](https://crates.io/crates/clap) -- CLI argument parsing with derive macros
- [entropy](https://crates.io/crates/entropy) -- additional entropy utilities
