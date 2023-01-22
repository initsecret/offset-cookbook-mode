//! An implementation of `CTX<AES128-OCB3>`, where `CTX` is specified in [Chan
//! and Rogaway (2022)][0] and instantiated using `Blake2s256`.
//!
//! [0]: https://eprint.iacr.org/2022/1260

pub use aead::{
    self, generic_array::GenericArray, AeadCore, AeadInPlace, Error, KeyInit, KeySizeUser,
};
use aes::{self, Aes128};
use blake2;

use blake2::Blake2s256;
use blake2::Digest;
use cipher::consts::{U0, U12, U16, U32};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::ocb3::Aes128Ocb3;

pub type Key = GenericArray<u8, U16>;
pub type Tag = GenericArray<u8, U32>;
pub type Nonce = GenericArray<u8, U12>;

#[derive(Clone)]
pub struct Aes128Ocb3Ctx {
    aead: Aes128Ocb3,
    key: Key,
}
impl Drop for Aes128Ocb3Ctx {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl KeySizeUser for Aes128Ocb3Ctx {
    type KeySize = <Aes128 as KeySizeUser>::KeySize;
}
impl AeadCore for Aes128Ocb3Ctx {
    type NonceSize = U12;
    type TagSize = U32;
    type CiphertextOverhead = U0;
}

impl KeyInit for Aes128Ocb3Ctx {
    fn new(key: &Key) -> Aes128Ocb3Ctx {
        let aead = Aes128Ocb3::new(key);
        Self { aead, key: *key }
    }
}

impl AeadInPlace for Aes128Ocb3Ctx {
    fn encrypt_in_place_detached(
        &self,
        nonce: &aead::Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> aead::Result<aead::Tag<Self>> {
        // Adapted from Figure 2 of https://eprint.iacr.org/2022/1260.pdf
        let tag = self
            .aead
            .encrypt_in_place_detached(nonce, associated_data, buffer)?;

        let mut hasher = Blake2s256::new();
        hasher.update(self.key);
        hasher.update(nonce);
        hasher.update(associated_data);
        hasher.update(tag);
        let tag_star = hasher.finalize();

        Ok(tag_star)
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &aead::Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &aead::Tag<Self>,
    ) -> aead::Result<()> {
        // Adapted from Figure 2 of https://eprint.iacr.org/2022/1260.pdf
        let tag_prime = self
            .aead
            .decrypt_in_place_return_tag(nonce, associated_data, buffer);

        let mut hasher = Blake2s256::new();
        hasher.update(self.key);
        hasher.update(nonce);
        hasher.update(associated_data);
        hasher.update(tag_prime);
        let expected_tag = hasher.finalize();

        if expected_tag.ct_eq(tag).into() {
            Ok(())
        } else {
            Err(Error)
        }
    }
}
