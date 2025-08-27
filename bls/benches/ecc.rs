// This source code can be freely used for research purposes.
// For any other purpose, please contact the authors.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

fn bench_single(c: &mut Criterion) {
    let mut group = c.benchmark_group("single");

    let seed = [0u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);

    let sizes = vec![8, 16, 32, 64, 128, 256, 512];

    for size in sizes {
        let mut msg = vec![0u8; size as usize];
        rng.fill_bytes(&mut msg);

        // ECDSA using secp256k1 curve
        {
            use k256::{
                ecdsa::{signature::Signer, Signature, SigningKey},
                ecdsa::{signature::Verifier, VerifyingKey},
            };

            // Signing
            let signing_key = SigningKey::random(&mut rng); // Serialize with `::to_bytes()`

            let ecdsa_sign = (&signing_key, &msg);
            group.bench_with_input(
                BenchmarkId::new("ECDSA sign", size),
                &ecdsa_sign,
                |b, (sk, msg)| {
                    b.iter(|| {
                        let _: Signature = sk.sign(msg);
                    })
                },
            );

            let signature: Signature = signing_key.sign(&msg);
            let verifying_key = VerifyingKey::from(&signing_key);

            let ecdsa_verify = (&verifying_key, &msg, signature);

            group.bench_with_input(
                BenchmarkId::new("ECDSA verify", size),
                &ecdsa_verify,
                |b, (verifying_key, msg, signature)| {
                    b.iter(|| {
                        verifying_key.verify(msg, signature).unwrap();
                    })
                },
            );
        }

        // Bounce BLS
        {
            use bls::min_pk::proof_of_possession::*;

            let sk = SecretKey::generate();
            let bls_sign = (&sk, &msg);

            group.bench_with_input(
                BenchmarkId::new("BLS sign", size),
                &bls_sign,
                |b, (sk, msg)| b.iter(|| sk.sign(msg)),
            );

            let signature = sk.sign(&msg);
            let pk = sk.sk_to_pk();
            let bls_verify = (&pk, &msg, &signature);

            group.bench_with_input(
                BenchmarkId::new("BLS verify", size),
                &bls_verify,
                |b, (pk, msg, signature)| b.iter(|| assert!(signature.verify(pk, msg))),
            );
        }

        // EdDSA using Curve 25519
        {
            use ed25519_dalek::Signer;
            use ed25519_dalek::SigningKey;

            let keypair = SigningKey::generate(&mut rng);

            let eddsa_sign = (&keypair, &msg);

            group.bench_with_input(
                BenchmarkId::new("EdDSA sign", size),
                &eddsa_sign,
                |b, (keypair, msg)| b.iter(|| keypair.sign(msg)),
            );

            let signature = keypair.sign(&msg);
            let eddsa_verify = (&keypair, &msg, &signature);

            group.bench_with_input(
                BenchmarkId::new("EdDSA verify", size),
                &eddsa_verify,
                |b, (keypair, msg, signature)| b.iter(|| keypair.verify(msg, signature).unwrap()),
            );
        }
    }

    group.finish();
}

criterion_group!(benches, bench_single);
criterion_main!(benches);
