use tonic::{transport::Server, Request, Response, Status};
use communication::{sat_service_server::{SatService, SatServiceServer}, Start, Response as GrpcResponse};
use crate::config::Config;

pub mod communication {
    tonic::include_proto!("communication");
}

#[derive(Default)]
pub struct Sat {}

#[tonic::async_trait]
impl SatService for Sat {
    async fn handle_start(
        &self,
        start: Request<Start>,
    ) -> Result<Response<GrpcResponse>, Status> {
        println!("Sat received a message from {}: {:?}", start.get_ref().sender, start.get_ref().content);

        let reply = communication::Response {
            message: format!("Sat processed the message: {}", start.get_ref().content),
        };

        Ok(Response::new(reply))
    }
}

pub async fn run_sat(config_file: &str, index: usize) -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::load_from_file(config_file);
    let sat_ip = &config.sat[index].ip;
    let addr = format!("{}:37131", sat_ip).parse()?;
    let sat = Sat::default();

    println!("Sat is listening on {}", addr);

    Server::builder()
        .add_service(SatServiceServer::new(sat))
        .serve(addr)
        .await?;

    Ok(())
}

use tokio::runtime::Runtime;
use std::env;

mod config;

fn main() {
    // Create a new Tokio runtime
    let rt = Runtime::new().unwrap();

    // Load the configuration file from command-line arguments
    let args: Vec<String> = env::args().collect();
    let config_file = &args[1];
    let index = args[2].parse::<usize>().expect("Index should be a valid number");

    // Start the Sat component
    rt.block_on(run_sat(config_file, index)).unwrap();
}
