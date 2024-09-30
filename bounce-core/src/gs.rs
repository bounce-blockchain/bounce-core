use tonic::{transport::Server, Request, Response, Status};
use communication::{gs_service_server::{GsService, GsServiceServer}, Start, Response as GrpcResponse};
use bounce_core::types::{ArchivedSignMerkleTreeRequest, SignMerkleTreeRequest};
use bounce_core::common::*;
use bounce_core::config::Config;
use rkyv::{rancor};
use tokio::runtime::Runtime;
use std::env;

use std::net::{SocketAddr};
use tokio::io::{AsyncReadExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task;


pub mod communication {
    tonic::include_proto!("communication");
}

#[derive(Default)]
pub struct GS {
    config: Config,
}

#[tonic::async_trait]
impl GsService for GS {
    async fn handle_start(
        &self,
        start: Request<Start>,
    ) -> Result<Response<GrpcResponse>, Status> {
        println!("GS received a message from {}: {:?}", start.get_ref().sender, start.get_ref().content);

        let reply = GrpcResponse {
            message: format!("GS processed the message: {}", start.get_ref().content),
        };

        Ok(Response::new(reply))
    }

}

impl GS {
    pub fn default() -> Self {
        GS {
            config: Config::default(),
        }
    }

    pub fn new(config: Config) -> Self {
        GS {
            config,
        }
    }
}

pub async fn handle_connection<'a>(mut socket: TcpStream, ss_ips:Vec<String>) -> Result<(), Box<dyn std::error::Error>> {
    // Buffer for incoming data
    let mut buffer = Vec::new();
    let mut chunk = vec![0u8; 2*1024*1024]; // Read in 2 MB chunks

    loop {
        // Read data into the chunk
        let bytes_read = match socket.read(&mut chunk).await {
            Ok(0) => {
                // Connection closed by the client
                break;
            }
            Ok(n) => n,
            Err(e) => {
                eprintln!("Failed to read from socket: {:?}", e);
                return Err(Box::new(e));
            }
        };

        // Append the read data to the buffer
        buffer.extend_from_slice(&chunk[..bytes_read]);
    }

    output_current_time(&format!("Received {} bytes from a client", buffer.len()));

    let start = std::time::Instant::now();
    let archived = unsafe {rkyv::access_unchecked::<ArchivedSignMerkleTreeRequest>(&buffer)};
    //let sign_merkle_tree_request = rkyv::deserialize::<ArchivedSignMerkleTreeRequest, rancor::Error>(archived).unwrap();
    let elapsed_time = start.elapsed();
    println!("Deserialized {} bytes in {:.2?}", buffer.len(), elapsed_time);
    println!("Received sign_merkle_tree_request with {} txs", archived.txs.len());

    output_current_time("Received sign_merkle_tree_request");

    let mut client = communication::ss_service_client::SsServiceClient::connect(format!("http://{}:37130", ss_ips[0])).await?;
    let response = tonic::Request::new(GrpcResponse {
        message: "SignMerkleTreeResponse".into(),
    });
    client.handle_sign_merkle_tree_response(response).await?;

    Ok(())
}

pub async fn run_listener<'a>(addr: SocketAddr, ss_ips: Vec<String>) {
    let listener = TcpListener::bind(&addr).await.expect("Failed to bind");
    println!("Server listening on {}", addr);

    loop {
        match listener.accept().await {
            Ok((socket, _)) => {
                println!("Accepted connection from: {}", socket.peer_addr().unwrap());
                let ss_ips = ss_ips.clone();
                task::spawn(async move{
                    if let Err(e) = handle_connection(socket, ss_ips).await {
                        eprintln!("Failed to handle connection: {:?}", e);
                    }
                });
            }
            Err(e) => {
                eprintln!("Failed to accept connection: {:?}", e);
            }
        }
    }
}

pub async fn run_gs(config_file: &str, index: usize) -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::load_from_file(config_file);
    let gs_ip = &config.gs[index].ip;
    let addr = format!("{}:37129", gs_ip).parse()?;
    let gs = GS::new(config.clone());

    println!("GS is listening on {}", addr);

    // Define the ports you want to open
    let ports = vec![3100];
    let mut tasks = vec![];

    // Start a listener on each port
    let ss_ips = config.ss.iter().map(|ss| ss.ip.clone()).collect::<Vec<String>>();
    for port in ports {
        let addr: SocketAddr = format!("0.0.0.0:{}", port).parse().unwrap();
        tasks.push(task::spawn(run_listener(addr, ss_ips.clone())));
    }

    Server::builder()
        .add_service(GsServiceServer::new(gs))
        .serve(addr)
        .await?;

    Ok(())
}

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
