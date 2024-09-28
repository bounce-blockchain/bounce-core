use tonic::{transport::Server, Request, Response, Status};
use communication::{ss_service_server::{SsService, SsServiceServer}, Message, Response as GrpcResponse};
use crate::config::Config;

pub mod communication {
    tonic::include_proto!("communication");
}

#[derive(Default)]
pub struct SS {}

#[tonic::async_trait]
impl SsService for SS {
    async fn handle_message(
        &self,
        request: Request<Message>,
    ) -> Result<Response<GrpcResponse>, Status> {
        println!("SS received a message from {}: {:?}", request.get_ref().sender, request.get_ref().content);

        let reply = communication::Response {
            message: format!("SS processed the message: {}", request.get_ref().content),
        };

        Ok(Response::new(reply))
    }
}

pub async fn run_ss(config_file: &str, index: usize) -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::load_from_file(config_file);
    let ss_ip = &config.ss[index].ip;
    let addr = format!("{}:37130", ss_ip).parse()?;
    let ss = SS::default();

    println!("SS is listening on {}", addr);

    Server::builder()
        .add_service(SsServiceServer::new(ss))
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

    // Start the SS component
    rt.block_on(run_ss(config_file, index)).unwrap();
}
