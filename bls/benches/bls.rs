// This source code can be freely used for research purposes.
// For any other purpose, please contact the authors.

use bls::min_pk::proof_of_possession::*;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

struct BenchData {
    _sk: SecretKey,
    pk: PublicKey,
    msg: Vec<u8>,
    sig: Signature,
}

fn gen_bench_data_for_msg(seed: [u8; 32], msg: &[u8]) -> BenchData {
    let sk = SecretKey::generate_with_seed(seed);
    let pk = sk.sk_to_pk();

    let sig = sk.sign(msg);

    BenchData {
        _sk: sk,
        pk,
        msg: msg.to_vec(),
        sig,
    }
}

fn bench_sign_verify(c: &mut Criterion) {
    let seed = [0u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);

    // num bytes
    let sizes = vec![1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024];
    let mut group = c.benchmark_group("bls_sign_verify");

    for size in sizes {
        let mut msg = vec![0u8; size as usize];
        rng.fill_bytes(&mut msg);

        let sk = SecretKey::generate();
        let bls_sign = (&sk, &msg);

        group.bench_with_input(BenchmarkId::new("sign", size), &bls_sign, |b, (sk, msg)| {
            b.iter(|| sk.sign(black_box(msg)))
        });

        let signature = sk.sign(&msg);
        let pk = sk.sk_to_pk();
        let bls_verify = (&pk, &msg, &signature);

        group.bench_with_input(
            BenchmarkId::new("verify", size),
            &bls_verify,
            |b, (pk, msg, signature)| {
                b.iter(|| assert!(signature.verify(black_box(pk), black_box(msg))))
            },
        );
    }
}

fn bench_fast_aggregate_verify(c: &mut Criterion) {
    let seed = [0u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);

    let msg_len = (rng.next_u64() & 0x3F) + 1;
    let mut msg = vec![0u8; msg_len as usize];
    rng.fill_bytes(&mut msg);

    let num_signatures = [8, 16, 32, 64, 128];
    // [10, 50, 100, 300, 1000, 4000];

    let bench_data: Vec<_> = (0..num_signatures[num_signatures.len() - 1])
        .map(|_| gen_bench_data_for_msg(seed, &msg))
        .collect();

    let mut group = c.benchmark_group("bls_fast_aggregate_verify");

    for size in num_signatures.iter() {
        let pks_refs = bench_data
            .iter()
            .take(*size)
            .map(|s| &s.pk)
            .collect::<Vec<&PublicKey>>();

        let sig_refs = bench_data
            .iter()
            .take(*size)
            .map(|s| &s.sig)
            .collect::<Vec<&Signature>>();

        let agg = match Signature::aggregate(&sig_refs) {
            Ok(agg) => agg,
            Err(err) => panic!("aggregate failure: {:?}", err),
        };

        group.bench_with_input(
            BenchmarkId::new("BLS aggregate signatures", size),
            &sig_refs,
            |b, sig_refs| {
                b.iter(|| {
                    let agg = Signature::aggregate(black_box(sig_refs));
                    assert!(agg.is_ok());
                });
            },
        );

        let agg_ver = (agg, pks_refs, &bench_data[0].msg);

        group.bench_with_input(
            BenchmarkId::new("fast_aggregate_verify", size),
            &agg_ver,
            |b, (a, pks, m)| {
                b.iter(|| {
                    let result = a.fast_aggregate_verify(black_box(pks), black_box(m));
                    assert!(result);
                });
            },
        );
    }
}

criterion_group!(benches, bench_sign_verify, bench_fast_aggregate_verify);
criterion_main!(benches);
