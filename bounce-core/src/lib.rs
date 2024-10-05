pub mod types;
pub mod common;

pub mod config;
pub mod communication {
    tonic::include_proto!("communication");
}

pub type SlotId = u64;
pub type ResetId = u64;