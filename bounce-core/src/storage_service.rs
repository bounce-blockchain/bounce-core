// This source code can be freely used for research purposes.
// For any other purpose, please contact the authors.

use std::error::Error;
use std::sync::{Arc};
use rocksdb::{DB};
use keccak_hash::keccak;
use crate::{ResetId, SlotId};
use crate::types::{CommitRecord, SignedCommitRecord};


const CR_CHAIN_PATH: &str = "store/cr_chain";
const NEGATIVE_CR_PATH: &str = "store/negative_cr";
const TX_DATA_PATH: &str = "store/tx_data";

pub struct CrChainStore {
    db: DB,
}

pub struct NegativeCrStore {
    db: DB,
}

pub struct TxDataStore {
    db: DB,
}

impl CrChainStore {
    /**
    key is the hash of the commit record, and value is the commit record and the signature
    */
    pub fn new() -> Self {
        let db = DB::open_default(CR_CHAIN_PATH).unwrap();
        CrChainStore { db }
    }

    pub fn get(&self, cr_hash:&[u8]) -> Option<SignedCommitRecord> {
        let signed_commit_record = self.db.get(cr_hash).unwrap();
        if let Some(signed_commit_record) = signed_commit_record {
            return Some(bincode::deserialize(&signed_commit_record).unwrap());
        }
        None
    }

    pub fn get_head(&self) -> Option<SignedCommitRecord> {
        let head = self.db.get(b"HEAD").unwrap();
        if let Some(head) = head {
            return Some(bincode::deserialize(&head).unwrap());
        }
        None
    }

    pub fn put(&self, signed_commit_record: SignedCommitRecord) {
        let serialized_signed_commit_record = bincode::serialize(&signed_commit_record).unwrap();
        self.db.put(keccak(bincode::serialize(&signed_commit_record.commit_record).unwrap()), serialized_signed_commit_record.clone()).expect("failed to store positive commit record");
        self.update_cr_chain_head(&serialized_signed_commit_record, signed_commit_record.commit_record.slot_id, signed_commit_record.commit_record.reset_id);
    }

    fn update_cr_chain_head(&self, signed_commit_record: &[u8], slot_id: SlotId, reset_id: ResetId) {
        let prev_head = self.db.get(b"HEAD").expect("failed to retrieve HEAD");
        if let Some(prev_head) = prev_head {
            let prev_head:SignedCommitRecord = bincode::deserialize(&prev_head).expect("failed to deserialize previous HEAD");
                if slot_id > prev_head.commit_record.slot_id && reset_id >= prev_head.commit_record.reset_id {
                    self.db.put(b"HEAD", signed_commit_record).expect("failed to update HEAD");
                }
                return;
        }
        self.db.put(b"HEAD", signed_commit_record).expect("failed to update HEAD");
    }
}

impl NegativeCrStore {
    pub fn new() -> Self {
        let db = DB::open_default(NEGATIVE_CR_PATH).unwrap();
        NegativeCrStore { db }
    }

    pub fn retrieve_negative_commit_record(&self, reset_id: ResetId) -> Result<Option<Vec<SignedCommitRecord>>, Box<dyn Error>> {
        match self.db.get(reset_id.to_be_bytes())? {
            Some(value) => {
                let negative_crs = bincode::deserialize::<Vec<SignedCommitRecord>>(&value)?;
                Ok(Some(negative_crs))
            }
            None => Ok(None),
        }
    }

    pub fn put(&self, reset_id: ResetId, signed_commit_record: SignedCommitRecord) {
        let mut negative_crs = match self.db.get(reset_id.to_be_bytes()).expect("failed to retrieve negative commit record") {
            Some(value) => {
                bincode::deserialize::<Vec<SignedCommitRecord>>(&value).expect("failed to deserialize negative commit record")
            }
            None => Vec::new(),
        };
        negative_crs.push(signed_commit_record);
        self.db.put(reset_id.to_be_bytes(), bincode::serialize(&negative_crs).expect("failed to serialize negative commit record")).expect("failed to store negative commit record");
    }
}

impl TxDataStore {
    pub fn new() -> Self {
        let db = DB::open_default(TX_DATA_PATH).unwrap();
        TxDataStore { db }
    }

    pub fn put(&self, txroot: &[u8], txdata: &[u8]) {
        self.db.put(txroot, txdata).expect("failed to store tx data");
    }

    pub fn get(&self, txroot: &[u8]) -> Option<Vec<u8>> {
        self.db.get(txroot).expect("failed to retrieve tx data")
    }
}

#[derive(Clone)]
pub struct StorageService {
    pub cr_chain_store: Arc<CrChainStore>,
    pub negative_cr_store: Arc<NegativeCrStore>,
    pub tx_data_store: Arc<TxDataStore>,
}

impl StorageService {
    pub fn new() -> Self {
        let cr_chain_store = Arc::new(CrChainStore::new());
        let negative_cr_store = Arc::new(NegativeCrStore::new());
        let tx_data_store = Arc::new(TxDataStore::new());
        StorageService {
            cr_chain_store,
            negative_cr_store,
            tx_data_store,
        }
    }
}

#[cfg(test)]
//you should REMOVE the store/ directory before and after running the tests
mod tests{
    use rkyv::rancor;
    use bls::min_pk::{PublicKey, SecretKey};
    use bls::min_pk::proof_of_possession::SecretKeyPop;
    use crate::types::{Transaction};
    use super::*;

    #[test]
    fn test_cr_chain() {
        let cr_chain = CrChainStore::new();
        let cr = CommitRecord {
            reset_id: 0,
            slot_id: 0,
            txroots: vec![],
            prev: [0u8; 32],
            commit_flag: true,
            used_as_reset: false,
        };
        let sk = SecretKey::generate();
        let signed_cr = SignedCommitRecord {
            signature: sk.sign(&bincode::serialize(&cr).unwrap()),
            commit_record: cr.clone(),
        };
        let head = cr_chain.get_head();
        assert_eq!(head, None);
        cr_chain.put(signed_cr.clone());
        let retrieved = cr_chain.get((&keccak(&bincode::serialize(&cr).unwrap())).as_ref()).unwrap();
        assert_eq!(retrieved, signed_cr);
        let head = cr_chain.get_head().unwrap();
        assert_eq!(head, signed_cr);

        let cr2 = CommitRecord {
            reset_id: 0,
            slot_id: 1,
            txroots: vec![],
            prev: <[u8; 32]>::from(keccak(&bincode::serialize(&cr).unwrap())),
            commit_flag: true,
            used_as_reset: false,
        };

        let signed_cr2 = SignedCommitRecord {
            signature: sk.sign(&bincode::serialize(&cr2).unwrap()),
            commit_record: cr2,
        };

        cr_chain.put(signed_cr2.clone());
        let head = cr_chain.get_head().unwrap();
        assert_eq!(head, signed_cr2);

        let signed_cr1 = cr_chain.get(&head.commit_record.prev).unwrap();
        assert_eq!(signed_cr1, signed_cr);
    }

    #[test]
    fn test_negative_cr() {
        let negative_cr = NegativeCrStore::new();
        let cr = CommitRecord {
            reset_id: 0,
            slot_id: 0,
            txroots: vec![],
            prev: [0u8; 32],
            commit_flag: true,
            used_as_reset: false,
        };
        let sk = SecretKey::generate();
        let signed_cr = SignedCommitRecord {
            signature: sk.sign(&bincode::serialize(&cr).unwrap()),
            commit_record: cr.clone(),
        };
        let reset_id = 0;
        let negative_crs = negative_cr.retrieve_negative_commit_record(reset_id).unwrap();
        assert_eq!(negative_crs, None);
        negative_cr.put(reset_id, signed_cr.clone());
        let negative_crs = negative_cr.retrieve_negative_commit_record(reset_id).unwrap().unwrap();
        assert_eq!(negative_crs, vec![signed_cr.clone()]);
        let negative_crs = negative_cr.retrieve_negative_commit_record(reset_id+1).unwrap();
        assert_eq!(negative_crs, None);
        let cr2 = CommitRecord {
            reset_id: 0,
            slot_id: 1,
            txroots: vec![],
            prev: <[u8; 32]>::from(keccak(&bincode::serialize(&cr).unwrap())),
            commit_flag: true,
            used_as_reset: false,
        };

        let signed_cr2 = SignedCommitRecord {
            signature: sk.sign(&bincode::serialize(&cr2).unwrap()),
            commit_record: cr2,
        };

        negative_cr.put(reset_id, signed_cr2.clone());
        let negative_crs = negative_cr.retrieve_negative_commit_record(reset_id).unwrap().unwrap();
        assert_eq!(negative_crs, vec![signed_cr, signed_cr2]);
    }

    #[test]
    fn test_tx_data() {
        let tx_data_store = TxDataStore::new();
        let tx1 = Transaction::new(
            PublicKey::default(),
            PublicKey::default(),
            0,
            vec![0u8],
        );
        let mut txs = vec![tx1.clone()];
        let tx2 = Transaction::new(
            PublicKey::default(),
            PublicKey::default(),
            1,
            vec![2u8],
        );
        txs.push(tx2);

        let serialized_data = rkyv::to_bytes::<rkyv::rancor::Error>(&txs).unwrap();

        let txroot = keccak(&serialized_data);

        tx_data_store.put(&txroot.0, &serialized_data);

        let retrieved = tx_data_store.get(&txroot.0).unwrap();
        let deserialized = rkyv::from_bytes::<Vec<Transaction>, rancor::Error>(&retrieved).unwrap();

        assert_eq!(deserialized, txs);
    }
}
