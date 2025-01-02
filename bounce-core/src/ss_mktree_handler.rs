use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bitvec::bitvec;
use rand::Rng;
use rkyv::rancor::Error;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio::sync::RwLock;
use tokio::task::JoinSet;
use tonic::{Request, Response, Status};
use tonic::transport::Server;

use bls::min_pk::{PublicKey, SecretKey, Signature};
use bls::min_pk::proof_of_possession::SignaturePop;
use communication::{Response as GrpcResponse, SignMerkleTreeResponse, ss_merkle_tree_handler_service_server::{SsMerkleTreeHandlerService, SsMerkleTreeHandlerServiceServer}};
use slot_clock::SlotMessage;

use crate::common::output_current_time;
use crate::config::Config;
use crate::types::{MultiSigned, SenderType, SignMerkleTreeRequest, Transaction};

pub mod communication {
    tonic::include_proto!("communication");
}

pub struct SsMerkleTreeHandler {
    pub config: Config,
    pub my_ip: String,
    pub gs_tx_receiver_ports: Vec<u16>,
    pub sender_to_ss: UnboundedSender<MultiSigned<[u8; 32]>>,
    pub client_txs_receiver: UnboundedReceiver<Vec<Transaction>>,

    pub secret_key: SecretKey,
    pub ground_station_public_keys: Vec<PublicKey>,
    pub f: u32,

    pub transactions: Vec<Transaction>,

    pub processed_roots: Vec<[u8; 32]>,
    pub root_to_sigs: HashMap<[u8; 32], Vec<Signature>>,
}

pub struct SsMerkleTreeHandlerLockService {
    pub ss_merkle_tree_handler: Arc<RwLock<SsMerkleTreeHandler>>,
}

pub fn run_grpc_server(ss_merkle_tree_handler: Arc<RwLock<SsMerkleTreeHandler>>, addr: SocketAddr) {
    let ss_merkle_tree_handler_lock_service = SsMerkleTreeHandlerLockService {
        ss_merkle_tree_handler,
    };

    let svc = SsMerkleTreeHandlerServiceServer::new(ss_merkle_tree_handler_lock_service);

    println!("SsMerkleTreeHandlerService listening on {}", addr);

    tokio::spawn(async move {
        Server::builder()
            .add_service(svc)
            .serve(addr)
            .await
            .unwrap();
    });
}

pub fn run_slot_listener(ss_merkle_tree_handler: Arc<RwLock<SsMerkleTreeHandler>>, mut slot_receive: tokio::sync::broadcast::Receiver<SlotMessage>) {
    tokio::spawn(async move {
        loop {
            let slog_msg = slot_receive.recv().await;
            match slog_msg {
                Ok(msg) => {
                    if msg == SlotMessage::SlotThreshold1 {
                        println!("SS merkle tree handler reach timer threshold, sending the sign_merkle_tree_request");
                        // Send the sign_merkle_tree_request
                        let mut ss_mk_tree_handler = ss_merkle_tree_handler.write().await;
                        ss_mk_tree_handler.send_sign_merkle_tree_request().await.unwrap();
                    }
                }
                Err(e) => {
                    eprintln!("Failed to receive SlotMessage: {:?}", e);
                }
            }
        }
    });
}

#[tonic::async_trait]
impl SsMerkleTreeHandlerService for SsMerkleTreeHandlerLockService {
    async fn handle_sign_merkle_tree_response(
        &self,
        request: Request<SignMerkleTreeResponse>,
    ) -> Result<Response<GrpcResponse>, Status> {
        let request = request.into_inner();
        let root: [u8; 32] = request.root.try_into().expect("Expected a response with root of 32 bytes");
        let signature: [u8; 96] = request.signature.try_into().expect("Expected a response with signature of 96 bytes");
        let signature = Signature::from_bytes(&signature).expect("Failed to convert the signature bytes to Signature");
        let mut ss = self.ss_merkle_tree_handler.write().await;
        ss.handle_sign_merkle_tree_response(root, signature).await;

        let reply = communication::Response {
            message: "ACK".to_string(),
        };

        Ok(Response::new(reply))
    }
}

impl SsMerkleTreeHandler {
    pub fn new(config: Config, my_ip: String, secret_key: SecretKey, ground_station_public_keys: Vec<PublicKey>, f: u32, sender_to_ss: UnboundedSender<MultiSigned<[u8; 32]>>) -> Self {
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
                0,
                1,
                i,
                data,
                1,
            );
            txs.push(tx);
        }
        let elapsed = start.elapsed();
        println!("Mktree_handler Generated 1_000_000 random transactions in {:?}", elapsed);

        //Spawn a thread for the ss_client_txs_receiver
        let (client_txs_sender, client_txs_receiver) = tokio::sync::mpsc::unbounded_channel();
        let mut ss_client_txs_receiver = crate::ss_client_txs_receiver::SsClientTxsReceiver::new(client_txs_sender);
        crate::ss_client_txs_receiver::run_ss_client_txs_receiver(ss_client_txs_receiver);


        SsMerkleTreeHandler {
            config,
            my_ip,
            gs_tx_receiver_ports: vec![3100],
            sender_to_ss,
            client_txs_receiver,

            secret_key,
            ground_station_public_keys,
            f,

            transactions: txs,

            processed_roots: Vec::new(),
            root_to_sigs: HashMap::new(),
        }
    }

    pub fn verify_signature(&self, signature: &Signature, msg: &[u8], sender: SenderType) -> bool {
        match sender {
            SenderType::GroundStation => {
                self.ground_station_public_keys.iter().any(|pk| signature.verify(pk, msg))
            }
            _ => false,
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
        //println!("Serialized sign_merkle_tree_request in {:?}", elapsed);

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
            //println!("Spawning process to send sign_merkle_tree_request to {}", addr);
            let sharable_data = Arc::clone(&sharable_data);
            join_set.spawn(async move {
                let start = std::time::Instant::now();
                match TcpStream::connect(&addr).await {
                    Ok(mut stream) => {
                        let elapsed = start.elapsed();
                        //println!("Connected to {} in {:?}", addr, elapsed);
                        output_current_time("Sending sign_merkle_tree_request...");

                        // Send the serialized data
                        let start = std::time::Instant::now();
                        if let Err(e) = stream.write_all(&sharable_data).await {
                            eprintln!("Failed to send sign_merkle_tree_request: {:?}", e);
                            return;
                        }
                        let elapsed = start.elapsed();
                        //println!("Thread sent sign_merkle_tree_request in {:?}", elapsed);

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
        //println!("Spawned all workers in {:?}", elapsed);

        let start = std::time::Instant::now();
        join_set.join_all().await;
        let elapsed = start.elapsed();
        //output_current_time(&format!("sign_merkle_tree_request sent. Time elapsed: {:?}", elapsed));

        let last_elapsed = first_start.elapsed();
        //println!("Total time elapsed in method: {:?}", last_elapsed);

        Ok(elapsed)
    }

    pub async fn handle_sign_merkle_tree_response(&mut self, root: [u8; 32], signature: Signature) {
        let start = std::time::Instant::now();
        if !self.verify_signature(&signature, &root, SenderType::GroundStation) {
            eprintln!("Failed to verify the signature of the sign_merkle_tree_response");
            return;
        }
        //println!("Received sign_merkle_tree_response with root: {:?}", root);
        if self.processed_roots.contains(&root) {
            //println!("Already process this root.");
            return;
        }
        self.root_to_sigs.entry(root).or_default().push(signature);
        let sigs = self.root_to_sigs.get(&root).unwrap();
        if sigs.len() as u32 >= self.f + 1 {
            println!("Aggregating {} signatures for merkle tree", sigs.len());
            let mut signers_bitvec = bitvec![0; self.ground_station_public_keys.len()];
            for (i, pk) in self.ground_station_public_keys.iter().enumerate() {
                for sig in sigs.iter() {
                    if sig.verify(pk, &bincode::serialize(&root).unwrap()) {
                        signers_bitvec.set(i, true);
                        println!("Signature verified for ground station {}", i);
                        break;
                    }
                }
            }
            // Make sure that f+1 distinct and known ground stations signed the merkle tree
            if signers_bitvec.count_ones() as u32 >= self.f + 1 {
                let sigs_refs = sigs.iter().collect::<Vec<_>>();
                let multi_signed = MultiSigned::new(
                    root,
                    signers_bitvec,
                    &sigs_refs,
                );

                println!(
                    "MultiSigned MerkleTree verified: {:?}",
                    multi_signed
                        .verify(&self.ground_station_public_keys.iter().collect::<Vec<_>>())
                );
                println!("Received enough signatures for the root. Queueing to send to the Satellite");
                self.processed_roots.push(root);
                // Send the multi-signed root to the SS
                self.sender_to_ss.send(multi_signed).unwrap();
                println!("Aggregated signatures {:?}\n", start.elapsed());
                self.root_to_sigs.remove(&root);
            } else {
                println!("f+1 check failed. Duplicate or unknown signatures for merkle tree");
            }
        }
    }
}