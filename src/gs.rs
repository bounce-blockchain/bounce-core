use tonic::{transport::Server, Request, Response, Status};
use communication::{gs_service_server::{GsService, GsServiceServer}, Message, Response as GrpcResponse};
use crate::config::Config;

pub mod communication {
    tonic::include_proto!("communication");
}

#[derive(Default)]
pub struct GS {}

#[tonic::async_trait]
impl GsService for GS {
    async fn handle_message(
        &self,
        request: Request<Message>,
    ) -> Result<Response<GrpcResponse>, Status> {
        println!("GS received a message from {}: {:?}", request.get_ref().sender, request.get_ref().content);

        let reply = communication::Response {
            message: format!("GS processed the message: {}", request.get_ref().content),
        };

        Ok(Response::new(reply))
    }
}

pub async fn run_gs(config_file: &str, index: usize) -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::load_from_file(config_file);
    let gs_ip = &config.gs[index].ip;
    let addr = format!("{}:37129", gs_ip).parse()?;
    let gs = GS::default();

    println!("GS is listening on {}", addr);

    Server::builder()
        .add_service(GsServiceServer::new(gs))
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

    // Start the GS component
    rt.block_on(run_gs(config_file, index)).unwrap();
}
