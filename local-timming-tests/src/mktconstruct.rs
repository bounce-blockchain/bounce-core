use std::time::Instant;
use keccak_hash::keccak;
use rand::Rng;
use rayon::prelude::*;
use rs_merkle::MerkleTree;
use bls::min_pk::PublicKey;
use bounce_core::types::{Keccak256, Transaction};

fn main() {
    let total_txs = 10_000_000;
    let pk = PublicKey::default();
    let start = Instant::now();
    let txs:Vec<Transaction> = (0..total_txs).into_par_iter().map(|i|{
        let mut rng = rand::thread_rng();
        let mut data = [0u8; 256];
        rng.fill(&mut data);
        Transaction::new(
            pk,
            pk,
            i,
            data.to_vec(),
        )
    }).collect();
    let duration = start.elapsed();
    println!("Generate {} of txs: {:?}", total_txs, duration);

    let start = Instant::now();
    let hashes = txs
        .par_iter()
        .map(|tx| keccak(tx.as_ref()).into())
        .collect::<Vec<[u8; 32]>>();
    let duration = start.elapsed();
    println!("Hashing {} of txs: {:?}", total_txs, duration);

    for i in 3..total_txs.ilog10() {
        let start = Instant::now();
        MerkleTree::<Keccak256>::from_leaves(&hashes[..10_usize.pow(i)]);
        let duration = start.elapsed();
        println!("Build MerkleTree with {} of hashes: {:?}", 10_usize.pow(i), duration);
    }
    let start = Instant::now();
    let mt = MerkleTree::<Keccak256>::from_leaves(&hashes);
    let duration = start.elapsed();
    println!("Build MerkleTree with {} of hashes: {:?}", total_txs, duration);
}