use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

// What's the cost of extra Proof of Possession prove/verify
// prove = serialize pk to bytes + sign
// verify = serialize pk to bytes + verify
fn bench_min_sig_pop(c: &mut Criterion) {
    use bls::min_sig::proof_of_possession::*;

    let seed = [0u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);
    let mut group = c.benchmark_group("min_sig_pop");

    let ikm = rng.gen::<[u8; 32]>();
    let sk = SecretKey::key_gen(&ikm).unwrap();

    group.bench_function("pop provve", |b| {
        b.iter(|| {
            let _ = sk.pop_prove();
        })
    });

    let pk_with_proof = (sk.sk_to_pk(), sk.pop_prove());

    group.bench_with_input("pop verify", &pk_with_proof, |b, (pk, proof)| {
        b.iter(|| {
            let _ = proof.pop_verify(black_box(pk));
        })
    });
}

fn bench_min_pk_pop(c: &mut Criterion) {
    use bls::min_pk::proof_of_possession::*;

    let seed = [0u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);
    let mut group = c.benchmark_group("min_pk_pop");

    let ikm = rng.gen::<[u8; 32]>();
    let sk = SecretKey::key_gen(&ikm).unwrap();

    group.bench_function("pop provve", |b| {
        b.iter(|| {
            let _ = sk.pop_prove();
        })
    });

    let pk_with_proof = (sk.sk_to_pk(), sk.pop_prove());

    group.bench_with_input("pop verify", &pk_with_proof, |b, (pk, proof)| {
        b.iter(|| {
            let _ = proof.pop_verify(black_box(pk));
        })
    });
}

criterion_group!(benches, bench_min_sig_pop, bench_min_pk_pop);
criterion_main!(benches);
