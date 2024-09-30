use tonic::{transport::Server, Request, Response, Status};
use communication::{mc_service_server::{McService, McServiceServer}, Start, Message, Response as GrpcResponse};
use crate::config::Config;
use tokio::runtime::Runtime;
use std::env;

pub mod config;

pub mod communication {
    tonic::include_proto!("communication");
}

#[derive(Default)]
pub struct MC {}

#[tonic::async_trait]
impl McService for MC {
    async fn handle_message(
        &self,
        request: Request<Message>,
    ) -> Result<Response<GrpcResponse>, Status> {
        println!("MC received a message from {}: {:?}", request.get_ref().sender, request.get_ref().content);

        let reply = communication::Response {
            message: format!("MC processed the message: {}", request.get_ref().content),
        };

        Ok(Response::new(reply))
    }
}

pub async fn run_mc(config_file: &str) -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::load_from_file(config_file);
    let mc_ip = &config.mc.ip;
    let addr = format!("{}:37128", mc_ip).parse()?;
    let mc = MC::default();

    println!("MC is listening on {}", addr);

    Server::builder()
        .add_service(McServiceServer::new(mc))
        .serve(addr)
        .await?;

    Ok(())
}

pub async fn send_start_message(config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    println!("Sending start message to all instances");
    for gs in &config.gs {
        let mut client = communication::gs_service_client::GsServiceClient::connect(format!("http://{}:37129", gs.ip)).await?;
        let request = tonic::Request::new(Start {
            content: "Start".into(),
            sender: "MC".into(),
        });
        let response = client.handle_start(request).await?;
        println!("Response from GS: {:?}", response.into_inner().message);
    }
    for ss in &config.ss {
        let mut client = communication::ss_service_client::SsServiceClient::connect(format!("http://{}:37130", ss.ip)).await?;
        let request = tonic::Request::new(Start {
            content: "Start".into(),
            sender: "MC".into(),
        });
        let response = client.handle_start(request).await?;
        println!("Response from SS: {:?}", response.into_inner().message);
    }
    for sat in &config.sat {
        let mut client = communication::sat_service_client::SatServiceClient::connect(format!("http://{}:37131", sat.ip)).await?;
        let request = tonic::Request::new(Start {
            content: "Start".into(),
            sender: "MC".into(),
        });
        let response = client.handle_start(request).await?;
        println!("Response from GS: {:?}", response.into_inner().message);
    }

    // Similarly, send the start message to GS and SAT instances.

    Ok(())
}


fn main() {
    let rt = Runtime::new().unwrap();
    let args: Vec<String> = env::args().collect();
    let config_file = &args[1];

    rt.block_on(async {
        let mc_runtime = run_mc(config_file);
        let config = config::Config::load_from_file(config_file);
        send_start_message(&config).await.unwrap();
        mc_runtime.await.unwrap();
    });
}