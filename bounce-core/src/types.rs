use std::collections::BTreeMap;

use anyhow::{anyhow, Result};
use bitvec::prelude::*;
use keccak_hash::write_keccak;
use rkyv;
use rkyv::rancor::Error;
use rs_merkle::Hasher;
use serde::{Deserialize, Serialize};

use bls::min_pk::proof_of_possession::*;

use crate::{ResetId, SlotId};

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub enum State {
    Inactive,
    Ready,
    AwaitEndReset,
}

pub enum SenderType {
    MissionControl,
    GroundStation,
    SendingStation,
    Satellite,
}

#[derive(rkyv::Archive, Clone, Debug, rkyv::Serialize, rkyv::Deserialize, PartialEq, Eq)]
#[rkyv(
    compare(PartialEq),
    derive(Debug),
)]
pub struct Transaction(pub Vec<u8>);

#[derive(rkyv::Archive, Clone, Debug, rkyv::Serialize, rkyv::Deserialize, PartialEq, Eq)]
#[rkyv(
    compare(PartialEq),
    derive(Debug),
)]
pub struct TxInner {
    pub from: u64,
    pub to: u64,
    pub value: u64,
    pub data: Vec<u8>,
    pub seqnum: u64,
}

impl TxInner {
    pub fn new(from: u64, to: u64, value: u64, data: Vec<u8>, seqnum: u64) -> Self {
        Self {
            from,
            to,
            value,
            data,
            seqnum,
        }
    }
}

impl Transaction {
    pub fn new(from: u64, to: u64, value: u64, data: Vec<u8>, seqnum: u64) -> Self {
        let tx_inner = TxInner::new(from, to, value, data, seqnum);
        let encoded = rkyv::to_bytes::<Error>(&tx_inner).unwrap();

        Self(encoded.to_vec())
    }
}

impl AsRef<[u8]> for Transaction {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, PartialEq, Eq, Clone)]
#[rkyv(
// This will generate a PartialEq impl between our unarchived
// and archived types
    compare(PartialEq),
// Derives can be passed through to the generated type:
    derive(Debug),
)]
pub struct SignMerkleTreeRequest {
    pub txs: Vec<Transaction>,
    pub sender_ip: String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Keccak256 {}

impl Hasher for Keccak256 {
    type Hash = [u8; 32];

    fn hash(data: &[u8]) -> [u8; 32] {
        let mut output = [0u8; 32];
        write_keccak(data, &mut output);
        output
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct CommitRecord {
    /// Reset number
    pub reset_id: ResetId,
    /// Slot identifier
    pub slot_id: SlotId,
    /// The Transaction root hash
    pub txroots: Vec<SendingStationMerkleTreeGroup>,
    // The hash of the previous commit record
    pub prev: [u8; 32],
    //true for positive and false for negative commit record
    pub commit_flag: bool,

    pub used_as_reset: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct SignedCommitRecord {
    pub commit_record: CommitRecord,
    pub signature: Signature,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MultiSigned<T>
where
    T: serde::Serialize,
{
    pub payload: T,
    pub signers_bitvec: BitVec, // BitVec representing which signers signed the payload. For it work correctly, the order of the public keys of the signers must be the same for all agents.
    pub signature: Signature,
}

impl<T> MultiSigned<T>
where
    T: serde::Serialize,
{
    pub fn new(payload: T, signers_bitvec: BitVec, signatures: &[&Signature]) -> Self {
        let signature = Signature::aggregate(signatures).unwrap();
        Self {
            payload,
            signers_bitvec,
            signature,
        }
    }

    pub fn verify(&self, public_keys: &[&PublicKey]) -> Result<()> {
        if self.signers_bitvec.len() != public_keys.len() {
            return Err(anyhow!("Number of signers and public keys mismatch"));
        }

        let mut pks_refs = Vec::new();
        for (i, &pk) in public_keys.iter().enumerate() {
            if self.signers_bitvec[i] {
                pks_refs.push(pk);
            }
        }

        let paylod_bytes = bincode::serialize(&self.payload).unwrap();

        if self
            .signature
            .fast_aggregate_verify(&pks_refs, &paylod_bytes)
        {
            Ok(())
        } else {
            Err(anyhow!("Signature verification failed"))
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SendingStationMessage {
    pub reset_id: ResetId,
    pub slot_id: SlotId,
    pub txroot: Vec<MultiSigned<[u8; 32]>>,
    pub prev_cr: MultiSigned<CommitRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SendingStationMerkleTreeGroup {
    pub txroots: Vec<MultiSigned<[u8; 32]>>,
    pub ss_signature: Signature,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Start {
    pub satellite_slot_assignments: BTreeMap<SlotId, PublicKey>,
    pub sending_station_slot_assignments: BTreeMap<SlotId, Vec<PublicKey>>,
    pub ground_station_public_keys: Vec<PublicKey>,
    pub sending_station_public_keys: Vec<PublicKey>,
    pub satellite_public_keys: Vec<PublicKey>,
    pub t: u64,
    pub f: u32,

    pub genesis_record: MultiSigned<CommitRecord>, //this should be signed by the mission control.
}

#[cfg(test)]
mod tests {
    use rkyv::rancor;
    use rkyv::util::AlignedVec;
    use super::*;

    #[test]
    fn test_new() {
        let from_sk = SecretKey::generate();
        let from_pk = PublicKey::from(&from_sk);

        let to_sk = SecretKey::generate();
        let to_pk = PublicKey::from(&to_sk);

        let value = 123;
        let data = b"hello, world!".to_vec();

        let tx = Transaction::new(0, 1, value, data, 1);

        //let tx_inner = rkyv::from_bytes::<TxInner,rancor::Error>(&tx.0).unwrap();
        let tx_inner = unsafe { rkyv::access_unchecked::<ArchivedTxInner>(&tx.0) };

        assert_eq!(tx_inner.value, value);
    }

    #[test]
    fn test_tx_size() {
        let from_sk = SecretKey::generate();
        let from_pk = PublicKey::from(&from_sk);

        let to_sk = SecretKey::generate();
        let to_pk = PublicKey::from(&to_sk);

        let value = 0;
        let data = vec![];
        let id = "123".to_string();
        let tx = Transaction::new(0, 1, value, data, 1);

        println!("tx size: {}", tx.as_ref().len());
        println!("public key size: {}", std::mem::size_of::<PublicKey>());
        println!("tx size: {}", std::mem::size_of::<Transaction>());
    }
}
