use serde;

use bls::min_pk::proof_of_possession::*;
use rkyv::{Archive, Deserialize, Serialize};

#[derive(Archive, Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[rkyv(
    compare(PartialEq),
    derive(Debug),
)]
pub struct Transaction(pub Vec<u8>);

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct TxInner {
    pub from: PublicKey,
    pub to: PublicKey,
    pub value: u64,
    pub data: Vec<u8>,
}

impl TxInner {
    pub fn new(from: PublicKey, to: PublicKey, value: u64, data: Vec<u8>) -> Self {
        Self {
            from,
            to,
            value,
            data,
        }
    }
}

impl Transaction {
    pub fn new(from: PublicKey, to: PublicKey, value: u64, data: Vec<u8>) -> Self {
        let tx_inner = TxInner::new(from, to, value, data);
        let encoded = bincode::serialize(&tx_inner).unwrap();

        Self(encoded)
    }
}

impl AsRef<[u8]> for Transaction {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Archive, Deserialize, Serialize, Debug, PartialEq, Eq)]
#[rkyv(
// This will generate a PartialEq impl between our unarchived
// and archived types
    compare(PartialEq),
// Derives can be passed through to the generated type:
    derive(Debug),
)]
pub struct SignMerkleTreeRequest {
    pub root: [u8; 32],
    pub hashes: Vec<[u8; 32]>,
    pub txs: Vec<Transaction>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let from_sk = SecretKey::generate();
        let from_pk = PublicKey::from(&from_sk);

        let to_sk = SecretKey::generate();
        let to_pk = PublicKey::from(&to_sk);

        let value = 123;
        let data = b"hello, world!".to_vec();

        let tx = Transaction::new(from_pk, to_pk, value, data);

        let _tx_inner: TxInner = bincode::deserialize(tx.as_ref()).unwrap();
    }

    #[test]
    fn test_tx_size() {
        let from_sk = SecretKey::generate();
        let from_pk = PublicKey::from(&from_sk);

        let to_sk = SecretKey::generate();
        let to_pk = PublicKey::from(&to_sk);

        let value = 0;
        let data = vec![];
        let tx = Transaction::new(from_pk, to_pk, value, data);

        println!("tx size: {}", tx.as_ref().len());
        println!("public key size: {}", std::mem::size_of::<PublicKey>());
        println!("tx size: {}", std::mem::size_of::<Transaction>());
    }
}
