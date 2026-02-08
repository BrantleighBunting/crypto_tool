/* Unless doing a test build, make no assumptions about platform */
#![cfg_attr(not(test), no_std)]
/* Ensure no unsafe code block in entire crate */
#![forbid(unsafe_code)]

/* This allows us to use vec! in nostd environments */
extern crate alloc;
use alloc::vec::Vec;

/* re-export the rc4 impl */
mod rc4;
pub use crate::rc4::*;

/* The RFC for CHACHA20_POLY1305
 * [RFC 8439]: https://tools.ietf.org/html/rfc8439 */
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use ring::rand::{SecureRandom, SystemRandom};

pub fn generate_key(key_bytes: &mut [u8]) {
    let rng = SystemRandom::new();

    rng.fill(key_bytes).unwrap();
}

pub fn generate_nonce(nonce_bytes: &mut [u8]) {
    let rng = SystemRandom::new();
    rng.fill(nonce_bytes).unwrap();
}

pub enum ErrorStates {
    KeyInitializationFailed,
    EncryptionFailed,
    DecryptionFailed,
}

pub fn chacha20_poly1305_cipher(
    key_bytes: &[u8],
    nonce_bytes: &[u8; 12],
    data: Vec<u8>,
    encrypt: bool,
) -> Result<Vec<u8>, ErrorStates> {
    let algorithm = &CHACHA20_POLY1305;

    let unbound_key = UnboundKey::new(algorithm, key_bytes)
        .map_err(|_| ErrorStates::KeyInitializationFailed)?;

    let key = LessSafeKey::new(unbound_key);

    let nonce = Nonce::assume_unique_for_key(*nonce_bytes);
    let aad = Aad::empty();

    let mut in_out = data;

    if encrypt {
        key.seal_in_place_append_tag(nonce, aad, &mut in_out)
            .map_err(|_| ErrorStates::EncryptionFailed)?;
        Ok(in_out)
    } else {
        match key.open_in_place(nonce, aad, &mut in_out) {
            Ok(plaintext) => {
                let len = plaintext.len();
                in_out.truncate(len);
                Ok(in_out)
            }
            Err(_) => {
                in_out.clear();
                Err(ErrorStates::DecryptionFailed)
            }
        }
    }
}
