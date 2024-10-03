use tonic::{transport::Server, Request, Response, Status};
use communication::{ss_service_server::{SsService, SsServiceServer}, Start, Response as GrpcResponse};
use bounce_core::types::{Transaction, SignMerkleTreeRequest};
use bounce_core::config::Config;
use keccak_hash::keccak;
use rayon::prelude::*;
use rkyv::{rancor::Error};
use rand::Rng;
use rand::seq::SliceRandom;
use rand::thread_rng;
use std::net::{SocketAddr};
use tokio::io::{AsyncWriteExt};
use tokio::net::{TcpStream};
use bounce_core::common::*;
use tokio::runtime::Runtime;
use std::env;
use bls::min_pk::PublicKey;


pub mod communication {
    tonic::include_proto!("communication");
}

#[derive(Default)]
pub struct SS {
    config: Config,
    gs_tx_receiver_ports: Vec<u16>,
    transactions: Vec<Transaction>,
    tx_hashes: Vec<[u8; 32]>,
}

#[tonic::async_trait]
impl SsService for SS {
    async fn handle_start(
        &self,
        start: Request<Start>,
    ) -> Result<Response<GrpcResponse>, Status> {
        println!("SS received a message from {}: {:?}", start.get_ref().sender, start.get_ref().content);

        for i in 0..4 {
            println!("SS is sending sign_merkle_tree_request {}", i);
            self.send_sign_merkle_tree_request().await.expect("Failed to send transactions");
        }

        let reply = communication::Response {
            message: format!("SS processed the message: {}", start.get_ref().content),
        };

        Ok(Response::new(reply))
    }

    async fn handle_sign_merkle_tree_response(
        &self,
        response: Request<GrpcResponse>,
    ) -> Result<Response<GrpcResponse>, Status>{
        println!("SS received a sign_merkle_tree_response: {}", response.get_ref().message);
        output_current_time("");

        let reply = communication::Response {
            message: "ACK".to_string(),
        };

        Ok(Response::new(reply))
    }
}

impl SS {
    pub fn default() -> Self {
        SS {
            transactions: Vec::new(),
            tx_hashes: Vec::new(),
            config: Config::default(),
            gs_tx_receiver_ports: vec![3100],
        }
    }
    pub fn new(config: Config) -> Self {
        SS {
            transactions: Vec::new(),
            tx_hashes: Vec::new(),
            config,
            gs_tx_receiver_ports: vec![3100],
        }
    }
    pub fn add_transaction(&mut self, tx: Transaction) {
        self.transactions.push(tx);
    }
    pub fn add_all_transactions(&mut self, txs: Vec<Transaction>) {
        self.transactions.extend(txs);
    }
    pub fn add_tx_hash(&mut self, tx_hash: [u8; 32]) {
        self.tx_hashes.push(tx_hash);
    }
    pub fn add_all_tx_hashes(&mut self, tx_hashes: Vec<[u8; 32]>) {
        self.tx_hashes.extend(tx_hashes);
    }
    pub fn get_transactions(&self) -> &Vec<Transaction> {
        &self.transactions
    }
    pub fn get_tx_hashes(&self) -> &Vec<[u8; 32]> {
        &self.tx_hashes
    }

    pub async fn send_sign_merkle_tree_request(&self) -> std::io::Result<()> {
        let sign_merkle_tree_request = SignMerkleTreeRequest {
            root: <[u8; 32]>::try_from(vec![0u8; 32]).unwrap(),
            txs: self.transactions.clone(),
            hashes: self.tx_hashes.clone(),
        };
        let gs_ip = &self.config.gs[0].ip;
        let addr: SocketAddr = format!("{}:{}", gs_ip, self.gs_tx_receiver_ports[0]).parse().unwrap();
        println!("Spawning process to send sign_merkle_tree_request to {}", addr);
        tokio::spawn(async move {
            match TcpStream::connect(&addr).await {
                Ok(mut stream) => {
                    println!("Connected to {}", addr);
                    let serialized_data= rkyv::to_bytes::<Error>(&sign_merkle_tree_request).unwrap();

                    // Measure the time taken to send data
                    let start = std::time::Instant::now();
                    println!("Sending sign_merkle_tree_request...");

                    // Send the serialized data
                    if let Err(e) = stream.write_all(&serialized_data).await {
                        eprintln!("Failed to send sign_merkle_tree_request: {:?}", e);
                        return;
                    }

                    // Drop the stream to close the connection
                    drop(stream);

                    // Calculate elapsed time
                    let elapsed = start.elapsed();
                    output_current_time(&format!("sign_merkle_tree_request sent. Time elapsed: {:?}", elapsed))

                }
                Err(e) => {
                    eprintln!("Failed to connect to {}: {:?}", addr, e);
                }
            }
        }).await.unwrap();

        Ok(())
    }
}

pub async fn run_ss(config_file: &str, index: usize) -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::load_from_file(config_file);
    let ss_ip = &config.ss[index].ip;
    let addr = format!("{}:37130", ss_ip).parse()?;

    let mut ss = SS::new(config);

    println!("SS is generating transactions");
    //generate 1million transactions
    let mut rng = rand::thread_rng();
    let mut data = [0u8; 256];
    rng.fill(&mut data);
    let data = data.to_vec();
    for i in 0..1000000 {
        let tx = Transaction::new(
            PublicKey::default(),
            PublicKey::default(),
            i,
            data.clone(),
        );
        ss.add_transaction(tx);
    }
    let tx_hashes = ss.get_transactions()
        .par_iter()
        .map(|tx| keccak(tx.as_ref()).into())
        .collect::<Vec<[u8; 32]>>();
    ss.add_all_tx_hashes(tx_hashes);
    println!("SS generated {} transactions", ss.get_transactions().len());

    println!("SS is listening on {}", addr);

    Server::builder()
        .add_service(SsServiceServer::new(ss))
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

    // Start the SS component
    rt.block_on(run_ss(config_file, index)).unwrap();
}
