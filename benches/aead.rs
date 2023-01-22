//! Benchmarks a selection of AEAD schemes.

#![allow(dead_code)]

use ::aead::{AeadInPlace, KeyInit};
use aes_gcm::Aes128Gcm;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use offset_cookbook_mode::ocb3::{Aes128Ocb3, Key, Nonce};
use offset_cookbook_mode::ocb3_ctx::Aes128Ocb3Ctx;
use ring::aead::{self, BoundKey};

const MESSAGES_SIZES_TO_MEASURE: [usize; 1] = [4096];

/// Simple nonce sequence implementation for use when benchmarking Ring AEAD.
struct NonceSequence(pub u64);
impl aead::NonceSequence for NonceSequence {
    fn advance(&mut self) -> Result<aead::Nonce, ring::error::Unspecified> {
        let mut result = [0u8; aead::NONCE_LEN];
        result[4..].copy_from_slice(&(self.0 + 1).to_be_bytes());
        Ok(aead::Nonce::assume_unique_for_key(result))
    }
}
macro_rules! benchmark_ring_aead {
    ($group_name:expr, $algorithm:expr, $c:expr) => {
        let mut group = $c.benchmark_group($group_name);
        // pick key
        let mut key_bytes = vec![0u8; $algorithm.key_len()];
        getrandom::getrandom(&mut key_bytes).unwrap();
        // pick ad
        let ad = [0u8; 16];

        for size in MESSAGES_SIZES_TO_MEASURE {
            // initialize a new cipher
            let key = aead::UnboundKey::new($algorithm, &key_bytes).unwrap();
            let mut sealing_key = aead::SealingKey::new(key, NonceSequence(0));
            let key = aead::UnboundKey::new($algorithm, &key_bytes).unwrap();
            let mut opening_key = aead::OpeningKey::new(key, NonceSequence(0));
            // pick a random plaintext of specified size
            let mut plaintext = vec![0u8; size];
            getrandom::getrandom(&mut plaintext).unwrap();
            let mut plaintext = black_box(plaintext);

            group.throughput(Throughput::Bytes(size as u64));
            group.bench_function(BenchmarkId::new(size.to_string(), "encrypt"), |b| {
                b.iter(|| {
                    let aad = aead::Aad::from(ad);
                    let _tag = sealing_key.seal_in_place_separate_tag(aad, &mut plaintext);
                })
            });
            group.bench_function(BenchmarkId::new(size.to_string(), "decrypt"), |b| {
                b.iter(|| {
                    let aad = aead::Aad::from(ad);
                    let _ = opening_key.open_in_place(aad, &mut plaintext);
                })
            });
        }
        group.finish();
    };
}

macro_rules! benchmark_rust_aead {
    ($group_name:expr, $algorithm:tt, $c:expr) => {
        let mut group = $c.benchmark_group($group_name);
        // pick key
        let mut key_bytes = [0u8; 16];
        getrandom::getrandom(&mut key_bytes).unwrap();
        let key = Key::from(key_bytes);
        // pick ad and nonce
        let ad = [0u8; 16];
        let nonce = Nonce::from([0u8; 12]);

        for size in MESSAGES_SIZES_TO_MEASURE {
            // initialize a new cipher
            let state = $algorithm::new(&key);
            // pick a random plaintext of specified size
            let mut plaintext = vec![0u8; size];
            getrandom::getrandom(&mut plaintext).unwrap();
            let mut plaintext = black_box(plaintext);

            group.throughput(Throughput::Bytes(size as u64));
            group.bench_function(BenchmarkId::new(size.to_string(), "encrypt"), |b| {
                b.iter(|| {
                    let _tag = state.encrypt_in_place_detached(&nonce, &ad, &mut plaintext);
                })
            });
            group.bench_function(BenchmarkId::new(size.to_string(), "decrypt"), |b| {
                b.iter(|| {
                    let _ = state.decrypt_in_place_detached(
                        &nonce,
                        &ad,
                        &mut plaintext,
                        &Default::default(),
                    );
                })
            });
        }
        group.finish();
    };
}

fn benchmark_aead(c: &mut Criterion) {
    benchmark_rust_aead!("ocb3", Aes128Ocb3, c);
    benchmark_rust_aead!("ocb3-ctx", Aes128Ocb3Ctx, c);
    benchmark_rust_aead!("rustcrypto-gcm", Aes128Gcm, c);
    benchmark_ring_aead!("ring-gcm", &aead::AES_128_GCM, c);
    benchmark_ring_aead!("ring-chacha20-poly1305", &aead::CHACHA20_POLY1305, c);
}

criterion_group!(
    name = aead_perf;
    config = Criterion::default();
    targets = benchmark_aead
);

criterion_main!(aead_perf);
