pub mod types;
pub mod common;

pub mod config;
pub mod communication {
    tonic::include_proto!("communication");
}