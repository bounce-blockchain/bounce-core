pub mod types;
pub mod common;

pub mod config;
pub mod communication {
    tonic::include_proto!("communication");
}

pub mod ss_mktree_handler;
pub mod gs_mktree_handler;

pub type SlotId = u64;
pub type ResetId = u64;