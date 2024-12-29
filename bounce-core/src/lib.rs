pub mod types;
pub mod common;

pub mod config;
pub mod communication {
    tonic::include_proto!("communication");
}

pub mod ss_mktree_handler;
pub mod ss_client_txs_receiver;
pub mod gs_mktree_handler;

pub mod storage_service;

pub type SlotId = u64;
pub type ResetId = u64;