use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use communication::{ss_merkle_tree_handler_service_server::SsMerkleTreeHandlerService, SignMerkleTreeResponse, Response as GrpcResponse};
use rand::Rng;
use rkyv::rancor::Error;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::mpsc::{UnboundedSender};
use tokio::sync::RwLock;
use tokio::task::JoinSet;
use tonic::{Request, Response, Status};
use bls::min_pk::{PublicKey, SecretKey};
use crate::common::output_current_time;
use crate::config::Config;
use crate::types::{SignMerkleTreeRequest, Transaction};

pub mod communication {
    tonic::include_proto!("communication");
}

pub struct SsMerkleTreeHandler {
    pub config: Config,
    pub my_ip: String,
    pub gs_tx_receiver_ports: Vec<u16>,
    pub sender_to_ss: UnboundedSender<[u8; 32]>,

    pub secret_key: SecretKey,
    pub ground_station_public_keys: Vec<PublicKey>,
    pub f: u32,

    pub transactions: Vec<Transaction>,
    pub root:Option<[u8; 32]>,
}

pub struct SsMerkleTreeHandlerLockService {
    ss_merkle_tree_handler: Arc<RwLock<SsMerkleTreeHandler>>,
}

#[tonic::async_trait]
impl SsMerkleTreeHandlerService for SsMerkleTreeHandlerLockService {
    async fn handle_sign_merkle_tree_response(
        &self,
        request: Request<SignMerkleTreeResponse>,
    ) -> Result<Response<GrpcResponse>, Status> {
        let request = request.into_inner();
        let root: [u8; 32] = request.root.try_into().expect("Expected a response with root of 32 bytes");
        let signature = request.signature;
        let mut ss = self.ss_merkle_tree_handler.write().await;
        ss.handle_sign_merkle_tree_response(root, signature).await;

        let reply = communication::Response {
            message: "ACK".to_string(),
        };

        Ok(Response::new(reply))
    }
}

impl SsMerkleTreeHandler{

    pub fn spawn(config: Config, my_ip:String, secret_key: SecretKey, ground_station_public_keys: Vec<PublicKey>, f: u32, sender_to_ss: UnboundedSender<[u8; 32]>) -> Self {
        // Generate 1_000_000 random transactions to send to the Ground Station.
        // This is for benchmarking purposes.
        println!("Mktree_handler Generating 1_000_000 random transactions...");
        let start = std::time::Instant::now();
        let mut txs = Vec::new();
        for i in 0..1_000_000 {
            let mut rng = rand::thread_rng();
            let mut data = [0u8; 256];
            rng.fill(&mut data);
            let data = data.to_vec();
            let tx = Transaction::new(
                PublicKey::default(),
                PublicKey::default(),
                i,
                data,
            );
            txs.push(tx);
        }
        let elapsed = start.elapsed();
        println!("Mktree_handler Generated 1_000_000 random transactions in {:?}", elapsed);

        SsMerkleTreeHandler {
            config,
            my_ip,
            gs_tx_receiver_ports: vec![3100],
            sender_to_ss,

            secret_key,
            ground_station_public_keys,
            f,

            transactions: txs,
            root: None,
        }
    }

    pub async fn send_sign_merkle_tree_request(&mut self) -> std::io::Result<Duration> {
        let sign_merkle_tree_request = SignMerkleTreeRequest {
            txs: std::mem::take(&mut self.transactions),
            sender_ip: self.my_ip.clone(),
        };
        let first_start = std::time::Instant::now();
        let start = std::time::Instant::now();
        let serialized_data = rkyv::to_bytes::<Error>(&sign_merkle_tree_request).unwrap();
        let elapsed = start.elapsed();
        println!("Serialized sign_merkle_tree_request in {:?}", elapsed);

        self.root = None;

        // Do compression when network is slow
        // let cursor = std::io::Cursor::new(serialized_data);
        //
        // let start = std::time::Instant::now();
        // let compressed_data = zstd::stream::encode_all(cursor, -22).unwrap();
        // let elapsed = start.elapsed();
        // println!("Compressed sign_merkle_tree_request in {:?}", elapsed);

        let sharable_data = Arc::new(serialized_data);

        let gs_ips = self.config.gs.iter().map(|gs| gs.ip.clone()).collect::<Vec<String>>();

        let mut join_set = JoinSet::new();
        for gs_ip in &gs_ips[0..std::cmp::min(3, gs_ips.len())] {
            let addr: SocketAddr = format!("{}:{}", gs_ip, self.gs_tx_receiver_ports[0]).parse().unwrap();
            println!("Spawning process to send sign_merkle_tree_request to {}", addr);
            let sharable_data = Arc::clone(&sharable_data);
            join_set.spawn(async move {
                let start = std::time::Instant::now();
                match TcpStream::connect(&addr).await {
                    Ok(mut stream) => {
                        let elapsed = start.elapsed();
                        println!("Connected to {} in {:?}", addr, elapsed);
                        output_current_time("Sending sign_merkle_tree_request...");

                        // Send the serialized data
                        let start = std::time::Instant::now();
                        if let Err(e) = stream.write_all(&sharable_data).await {
                            eprintln!("Failed to send sign_merkle_tree_request: {:?}", e);
                            return;
                        }
                        let elapsed = start.elapsed();
                        println!("Thread sent sign_merkle_tree_request in {:?}", elapsed);

                        // Drop the stream to close the connection
                        drop(stream);
                    }
                    Err(e) => {
                        eprintln!("Failed to connect to {}: {:?}", addr, e);
                    }
                }
            });
        }
        let elapsed = start.elapsed();
        println!("Spawned all workers in {:?}", elapsed);

        let start = std::time::Instant::now();
        join_set.join_all().await;
        let elapsed = start.elapsed();
        output_current_time(&format!("sign_merkle_tree_request sent. Time elapsed: {:?}", elapsed));

        let last_elapsed = first_start.elapsed();
        println!("Total time elapsed in method: {:?}", last_elapsed);

        Ok(elapsed)
    }

    pub async fn handle_sign_merkle_tree_response(&mut self, root: [u8;32], signature: Vec<u8>) {
        println!("Received sign_merkle_tree_response with root: {:?}", root);
        if self.root.is_none() {
            self.root = Some(root);
            self.sender_to_ss.send(root).unwrap();
        }
    }
}