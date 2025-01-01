use eth_trie::{EthTrie, MemoryDB, Trie, DB};
use rand::{Rng, SeedableRng};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::Duration;
use keccak_hash::keccak;
use rayon::prelude::*;
use rkyv::rancor;
use rs_merkle::MerkleTree;
use bounce_core::types::{Keccak256, Transaction, TxInner};
use bls::min_pk::{PublicKey, SecretKey, Signature};
use serde::{Deserialize, Serialize};

const TRANSACTIONS_PER_TREE: usize = 100_000;
const ROOTS_PER_SLOT: usize = 10;
const NUM_WALLETS: usize = 1_000_000;
const NUM_SLOT: usize = 2;
const SLOT_DURATION: u64 = 2; // seconds
#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, PartialEq, Eq, Clone)]
#[rkyv(
    // This will generate a PartialEq impl between our unarchived
    // and archived types
    compare(PartialEq),
    // Derives can be passed through to the generated type:
    derive(Debug),
)]
struct Wallet {
    id: u64,
    balance: u64,
    seqnum: u64,
}

struct TxCounter{
    tx_overdraft: u64,
    tx_bad_seqnum: u64,
    tx_success: u64,
}

fn generate_transactions(num: usize, wallet_id_seqnum_pair:&[(u64,u64)]) -> Vec<Transaction> {
    let mut txs = Vec::new();
    for i in 0..num {
        let mut rng = rand::rng();
        let mut data = [0u8; 256];
        rng.fill(&mut data);
        let data = data.to_vec();
        let tx = Transaction::new(
            PublicKey::default(),
            PublicKey::default(),
            rand::random_range(0..500),
            data,
            (wallet_id_seqnum_pair[i].0, wallet_id_seqnum_pair[i].1),
        );
        txs.push(tx);
    }
    txs
}

fn hash_transactions(transactions: &[Transaction]) -> Vec<[u8; 32]> {
    transactions.par_iter()
        .map(|tx| keccak(&tx.0).into())
        .collect::<Vec<[u8; 32]>>()
}

fn build_merkle_tree(transactions: &[Transaction]) -> Vec<u8> {
    let hashes = hash_transactions(transactions);
    let mt = MerkleTree::<Keccak256>::from_leaves(&hashes);
    mt.root().unwrap_or_default().to_vec()
}

fn process_transaction(
    transaction: &Transaction,
    seen_txs: &Arc<RwLock<HashSet<(u64,u64)>>>,
    trie: &Arc<RwLock<EthTrie<MemoryDB>>>,
    updates_producer: &crossbeam_channel::Sender<(Vec<u8>,Vec<u8>)>,
    tx_counter: &Arc<Mutex<TxCounter>>,
) {
    let initial_start = std::time::Instant::now();
    let start = std::time::Instant::now();
    // Deserialize the transaction and extract wallet_id and seqnum efficiently
    let tx_inner: TxInner = bincode::deserialize(&transaction.0).unwrap();
    let (wallet_id, seqnum) = tx_inner.id;
    let elapsed = start.elapsed();
    //println!("Deserialized transaction in {:.4?}", elapsed);

    // Check if transaction is already processed
    // let start = std::time::Instant::now();
    // {
    //     let mut seen_txs_guard = seen_txs.read().unwrap();
    //     if seen_txs_guard.contains(&tx_inner.id) {
    //         let mut tx_counter = tx_counter.lock().unwrap();
    //         tx_counter.tx_bad_seqnum += 1;
    //         return;
    //     }
    // }
    // let elapsed = start.elapsed();
    //println!("Checked seen_txs in {:.4?}", elapsed);

    let start = std::time::Instant::now();
    let key = wallet_id.to_be_bytes();
    let read_trie = trie.read().unwrap();
    let wallet_encoded = read_trie.get(&key).unwrap().unwrap();
    drop(read_trie); // Release the lock early for parallel processing
    let wallet = unsafe { rkyv::access_unchecked::<ArchivedWallet>(&wallet_encoded) };
    let elapsed = start.elapsed();
    //println!("Read wallet in {:.4?}", elapsed);

    if wallet.seqnum > seqnum {
        let mut tx_counter = tx_counter.lock().unwrap();
        tx_counter.tx_bad_seqnum += 1;
        return;
    }

    if wallet.balance < tx_inner.value {
        let mut tx_counter = tx_counter.lock().unwrap();
        tx_counter.tx_overdraft += 1;
        return;
    }

    let mut success = false;
    {
        let start = std::time::Instant::now();
        let updated_wallet = Wallet {
            id: u64::from(wallet.id),
            balance: wallet.balance - tx_inner.value,
            seqnum: seqnum + 1,
        };
        let encoded = rkyv::to_bytes::<rancor::Error>(&updated_wallet).unwrap();
        let mut seen_txs = seen_txs.write().unwrap();
        if seen_txs.insert(tx_inner.id) {
            updates_producer.send((key.to_vec(),encoded.to_vec())).unwrap();
            success = true;
        }
        let elapsed = start.elapsed();
        //println!("Create the updates in {:.4?}", elapsed);
    }

    // Increment success counter
    {
        let mut tx_counter = tx_counter.lock().unwrap();
        if success {
            tx_counter.tx_success += 1;
        } else {
            tx_counter.tx_bad_seqnum += 1;
        }
    }

    let elapsed = initial_start.elapsed();
    //println!("Processed transaction in {:.4?}", elapsed);
}

fn process_roots(
    committed: &(Vec<u8>, Vec<Transaction>),
    seen_roots: Arc<Mutex<HashSet<Vec<u8>>>>,
    trie: Arc<RwLock<EthTrie<MemoryDB>>>,
    tx_counter: Arc<Mutex<TxCounter>>,
) {
    let (root, transactions) = committed;
    let start = std::time::Instant::now();

    let seen_txs:HashSet<(u64,u64)> = HashSet::new();
    let shared_seen_txs = Arc::new(RwLock::new(seen_txs));
    // Check if root is already processed
    let mut seen_roots_guard = seen_roots.lock().unwrap();
    if !seen_roots_guard.contains(root) {
        seen_roots_guard.insert(root.clone());
        drop(seen_roots_guard); // Release the lock early for parallel processing

        //use mpsc to send the wallet updates and process them at once.
        let (updates_producer,updates_consumer) = crossbeam_channel::unbounded();
        // Parallelize transaction processing
        let updates_producer = Arc::new(updates_producer);
        transactions.par_iter().for_each(|transaction| {
            process_transaction(transaction, &shared_seen_txs, &trie, &updates_producer, &tx_counter);
        });

        let start = std::time::Instant::now();
        let mut keys = Vec::new();
        let mut values = Vec::new();
        while let Ok((key,encoded)) = updates_consumer.recv_timeout(Duration::from_millis(1)) {
            keys.push(key);
            values.push(encoded);
        }
        let elapsed = start.elapsed();
        println!("Received updates in {:.4?}", elapsed);
        let start = std::time::Instant::now();
        {
            let mut write_trie = trie.write().unwrap();
            write_trie.db.insert_batch(keys, values).unwrap();
        }
        let elapsed = start.elapsed();
        println!("Updated trie in {:.2?}", elapsed);
    } else {
        println!("Root already processed");
    }

    let elapsed = start.elapsed();
    println!("Processed root in {:.2?}", elapsed);
}

fn main() {
    println!("Generating {NUM_WALLETS} Wallets stored in the trie...");

    let db = Arc::new(MemoryDB::new(false));
    let mut trie = EthTrie::new(db.clone());
    for i in 0..NUM_WALLETS {
        let wallet = Wallet {
            id: i as u64,
            balance: 1000,
            seqnum: 0,
        };
        let encoded = rkyv::to_bytes::<rancor::Error>(&wallet).unwrap();
        trie.insert(&wallet.id.to_be_bytes(), &encoded).unwrap();
    }

    let mut wallet_id_seqnum_pairs_total = Vec::new();

    for i in 1..=NUM_SLOT {
        let mut wallet_id_seqnum_pairs : Vec<Vec<(u64,u64)>> = Vec::new();
        for _ in 0..ROOTS_PER_SLOT {
            let mut wallet_id_seqnum_pair = Vec::new();
            for _ in 0..TRANSACTIONS_PER_TREE {
                let wallet_id = rand::random_range(0..NUM_WALLETS) as u64;
                let seqnum = i as u64;
                wallet_id_seqnum_pair.push((wallet_id, seqnum));
            }
            wallet_id_seqnum_pairs.push(wallet_id_seqnum_pair);
        }
        wallet_id_seqnum_pairs_total.push(wallet_id_seqnum_pairs);
    }

    println!("Generating transactions and Merkle trees...");
    let mut merkle_trees_total : Vec<Vec<(Vec<u8>,Vec<Transaction>)>> = Vec::new();

    let results: Vec<Vec<(Vec<u8>, Vec<Transaction>)>> = (1..=NUM_SLOT)
        .into_par_iter()
        .map(|i| {
            let mut merkle_trees: Vec<(Vec<u8>, Vec<Transaction>)> = Vec::new();

            let mut inner_results: Vec<(Vec<u8>, Vec<Transaction>)> = (0..ROOTS_PER_SLOT-1)
                .into_par_iter()
                .map(|j| {
                        let transactions = generate_transactions(
                            TRANSACTIONS_PER_TREE,
                            &wallet_id_seqnum_pairs_total[i - 1][j],
                        );
                        let root = build_merkle_tree(&transactions);
                        (root, transactions)
                })
                .collect();
            inner_results.push(inner_results[0].clone());

            merkle_trees.extend(inner_results);
            merkle_trees
        })
        .collect();

    merkle_trees_total.extend(results);

    println!("Processing roots...");
    let mut seen_roots = HashSet::new();
    let mut tx_counter = TxCounter {
        tx_overdraft: 0,
        tx_bad_seqnum: 0,
        tx_success: 0,
    };

    let shared_seen_roots = Arc::new(Mutex::new(seen_roots));
    let shared_trie = Arc::new(RwLock::new(trie));
    let shared_tx_counter = Arc::new(Mutex::new(tx_counter));
    for i in 1..=NUM_SLOT {
        let start = std::time::Instant::now();
        for j in 0..ROOTS_PER_SLOT {
            let shared_seen_roots = shared_seen_roots.clone();
            let shared_trie = shared_trie.clone();
            let shared_tx_counter = shared_tx_counter.clone();
            process_roots(&merkle_trees_total[i-1][j], shared_seen_roots, shared_trie, shared_tx_counter);
        }
        let elapsed = start.elapsed();
        println!("Processed roots for slot {} in {:.2?}", i, elapsed);
    }

    let tx_counter = shared_tx_counter.lock().unwrap();
    let total_txs = tx_counter.tx_success + tx_counter.tx_overdraft + tx_counter.tx_bad_seqnum;
    println!("Total transactions processed: {}", total_txs);
    println!("Processed {} transactions successfully({}%) with {} overdrafts({}%) and {} bad seqnums({}%).", tx_counter.tx_success, tx_counter.tx_success * 100 / total_txs, tx_counter.tx_overdraft, tx_counter.tx_overdraft * 100 / total_txs, tx_counter.tx_bad_seqnum, tx_counter.tx_bad_seqnum * 100 / total_txs);


    // Allow time for processing (example: 20 seconds).
    thread::sleep(Duration::from_secs(10));
    println!("Finished processing roots.");
}
