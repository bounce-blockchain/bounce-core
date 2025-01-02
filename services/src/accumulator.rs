mod db;

use eth_trie::{EthTrie, Trie, DB};
use rand::{Rng};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use dashmap::DashSet;
use keccak_hash::keccak;
use rayon::prelude::*;
use rkyv::rancor;
use rs_merkle::MerkleTree;
use bounce_core::types::{ArchivedTxInner, Keccak256, Transaction, TxInner};
use bls::min_pk::{PublicKey};
use serde::{Deserialize};
use services::db::MemoryDB;

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
            wallet_id_seqnum_pair[i].0,
            (wallet_id_seqnum_pair[i].0 + 1) % NUM_WALLETS as u64,
            rand::random_range(0..500),
            data,
            wallet_id_seqnum_pair[i].1,
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
    seen_txs: &DashSet<(u64, u64)>,
    //trie: &Arc<RwLock<EthTrie<MemoryDB>>>,
    db: &Arc<MemoryDB>,
    updates_producer: &crossbeam_channel::Sender<(Vec<u8>, Vec<u8>)>,
    tx_counter: &Arc<Mutex<TxCounter>>,
) {
    let tx_inner = unsafe { rkyv::access_unchecked::<ArchivedTxInner>(&transaction.0) };

    // Read wallet from trie
    let wallet_id:u64 = tx_inner.from.into();
    let seqnum:u64 = tx_inner.seqnum.into();
    // let wallet_encoded = {
    //     let read_trie = trie.read().unwrap();
    //     match read_trie.get(&key) {
    //         Ok(Some(wallet)) => wallet.clone(),
    //         _ => return,
    //     }
    // };
    let wallet_encoded = db.get(&wallet_id.to_be_bytes()).unwrap().unwrap();

    let wallet = unsafe { rkyv::access_unchecked::<ArchivedWallet>(&wallet_encoded) };

    if wallet.seqnum >= seqnum {
        tx_counter.lock().unwrap().tx_bad_seqnum += 1;
        return;
    }

    if wallet.balance < tx_inner.value {
        tx_counter.lock().unwrap().tx_overdraft += 1;
        return;
    }

    let updated_wallet = Wallet {
        id: u64::from(wallet.id),
        balance: wallet.balance - tx_inner.value,
        seqnum,
    };

    let encoded = rkyv::to_bytes::<rancor::Error>(&updated_wallet).unwrap();

    let target_wallet_id:u64 = tx_inner.to.into();
    let target_wallet_encoded = db.get(&target_wallet_id.to_be_bytes()).unwrap().unwrap();
    let target_wallet = unsafe { rkyv::access_unchecked::<ArchivedWallet>(&target_wallet_encoded) };

    let updated_target_wallet = Wallet {
        id: u64::from(target_wallet.id),
        balance: target_wallet.balance + tx_inner.value,
        seqnum: target_wallet.seqnum.into(),
    };

    let encoded_target = rkyv::to_bytes::<rancor::Error>(&updated_target_wallet).unwrap();

    if seen_txs.insert((wallet_id, seqnum)) {
        updates_producer.send((wallet_id.to_be_bytes().to_vec(), encoded.to_vec())).unwrap();
        updates_producer.send((target_wallet_id.to_be_bytes().to_vec(), encoded_target.to_vec())).unwrap();

        tx_counter.lock().unwrap().tx_success += 1;
    } else {
        tx_counter.lock().unwrap().tx_bad_seqnum += 1;
    }
}

fn process_roots(
    committed: &(Vec<u8>, Vec<Transaction>),
    seen_roots: Arc<DashSet<Vec<u8>>>,
    //trie: Arc<RwLock<EthTrie<MemoryDB>>>,
    db: Arc<MemoryDB>,
    tx_counter: Arc<Mutex<TxCounter>>,
) {
    let (root, transactions) = committed;

    if seen_roots.insert(root.clone()) {
        let (updates_producer, updates_consumer) = crossbeam_channel::unbounded();
        let shared_seen_txs = DashSet::new();
        let updates_producer = Arc::new(updates_producer);

        let start = std::time::Instant::now();
        transactions.par_iter().for_each(|transaction| {
            process_transaction(
                transaction,
                &shared_seen_txs,
                &db,
                &updates_producer,
                &tx_counter,
            );
        });
        let elapsed = start.elapsed();
        println!("Processed transactions in {:.2?}", elapsed);

        // Batch updates to the trie in parallel
        let shared_db = db.clone();
        std::thread::spawn(move || {
            let start = std::time::Instant::now();
            let mut keys = Vec::new();
            let mut values = Vec::new();
            while let Ok((key, encoded)) = updates_consumer.recv_timeout(Duration::from_millis(1)) {
                keys.push(key);
                values.push(encoded);
            }
            shared_db.insert_batch(keys, values).unwrap();
            let elapsed = start.elapsed();
            println!("Updated trie in {:.2?} (concurrently)", elapsed);
        });
    } else {
        println!("Root already processed");
    }
}

fn main() {
    println!("Generating {NUM_WALLETS} Wallets stored in the trie...");

    let db = Arc::new(MemoryDB::new(false));
    //let mut trie = EthTrie::new(db.clone());
    for i in 0..NUM_WALLETS {
        let wallet = Wallet {
            id: i as u64,
            balance: 1000,
            seqnum: 0,
        };
        let encoded = rkyv::to_bytes::<rancor::Error>(&wallet).unwrap();
       // trie.insert(&wallet.id.to_be_bytes(), &encoded).unwrap();
        db.insert(&wallet.id.to_be_bytes(), encoded.to_vec()).unwrap();
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
    let mut tx_counter = TxCounter {
        tx_overdraft: 0,
        tx_bad_seqnum: 0,
        tx_success: 0,
    };

    let shared_seen_roots = Arc::new(DashSet::new());
    //let shared_trie = Arc::new(RwLock::new(trie));
    let shared_tx_counter = Arc::new(Mutex::new(tx_counter));
    for i in 1..=NUM_SLOT {
        let start = std::time::Instant::now();
        for j in 0..ROOTS_PER_SLOT {
            let shared_seen_roots = shared_seen_roots.clone();
            //let shared_trie = shared_trie.clone();
            let shared_db = db.clone();
            let shared_tx_counter = shared_tx_counter.clone();
            process_roots(&merkle_trees_total[i-1][j], shared_seen_roots, shared_db, shared_tx_counter);
        }
        let elapsed = start.elapsed();
        println!("Processed roots for slot {} in {:.2?}", i, elapsed);
    }

    let tx_counter = shared_tx_counter.lock().unwrap();
    let total_txs = tx_counter.tx_success + tx_counter.tx_overdraft + tx_counter.tx_bad_seqnum;
    println!("Total transactions processed: {}", total_txs);
    println!("Processed {} transactions successfully({}%) with {} overdrafts({}%) and {} bad seqnums({}%).", tx_counter.tx_success, tx_counter.tx_success * 100 / total_txs, tx_counter.tx_overdraft, tx_counter.tx_overdraft * 100 / total_txs, tx_counter.tx_bad_seqnum, tx_counter.tx_bad_seqnum * 100 / total_txs);


    std::thread::sleep(Duration::from_secs(3));
    println!("Finished processing roots.");
}
