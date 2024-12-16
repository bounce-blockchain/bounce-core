use rocksdb::{DB};
use keccak_hash::keccak;
use crate::{ResetId, SlotId};
use crate::types::{CommitRecord, SignedCommitRecord};


const CR_CHAIN_PATH: &str = "store/cr_chain";
const NEGATIVE_CR_PATH: &str = "store/negative_cr";
const TX_DATA_PATH: &str = "store/tx_data";

pub struct CrChain {
    db: DB,
}

pub struct NegativeCr {
    db: DB,
}

pub struct TxData {
    db: DB,
}

impl CrChain {
    /**
    key is the hash of the commit record, and value is the commit record and the signature
    */
    pub fn new() -> Self {
        let db = DB::open_default(CR_CHAIN_PATH).unwrap();
        CrChain { db }
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

#[cfg(test)]
mod tests{
    //you should remove the store directory before and after running the tests
    use bls::min_pk::{SecretKey};
    use bls::min_pk::proof_of_possession::SecretKeyPop;
    use super::*;

    #[test]
    fn test_cr_chain() {
        let cr_chain = CrChain::new();
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
}
