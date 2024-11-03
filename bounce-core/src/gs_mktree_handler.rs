use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use keccak_hash::keccak;
use rayon::prelude::*;
use rs_merkle::MerkleTree;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use bls::min_pk::proof_of_possession::SecretKeyPop;
use bls::min_pk::SecretKey;
use crate::common::output_current_time;
use crate::communication;
use crate::communication::SignMerkleTreeResponse;
use crate::types::{ArchivedSignMerkleTreeRequest, Keccak256};

pub struct GsMerkleTreeHandler {
    pub secret_key: SecretKey,
    pub my_ip: String,
    pub gs_map: HashMap<String, HashSet<String>>,
}

impl GsMerkleTreeHandler {
    pub fn new(secret_key: SecretKey, my_ip:String) -> Self {
        GsMerkleTreeHandler {
            secret_key,
            my_ip,
            gs_map: HashMap::new(),
        }
    }

    pub async fn handle_connection(&self, mut socket: TcpStream) -> Result<(), Box<dyn std::error::Error>> {
        // Buffer for incoming data
        let mut buffer = Vec::new();
        let mut chunk = vec![0u8; 2 * 1024 * 1024]; // Read in 2 MB chunks

        let start = std::time::Instant::now();
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
        let elapsed_time = start.elapsed();
        println!("Received {} bytes in {:.2?}", buffer.len(), elapsed_time);

        output_current_time(&format!("Received {} bytes from a client", buffer.len()));

        let shared_buffer = Arc::new(buffer);

        let gs_peers = self.gs_map.get(&self.my_ip);
        let mut gossip_join_set = JoinSet::new();
        if gs_peers.is_some()&&!gs_peers.unwrap().is_empty() {
            println!("Gossiping to other GSs: {:?}", self.gs_map.get(&self.my_ip));
            let start = std::time::Instant::now();
            for gs_ip in self.gs_map.get(&self.my_ip).unwrap() {
                let sharable_data = shared_buffer.clone();
                let gs_ip = gs_ip.clone();
                gossip_join_set.spawn({
                    async move {
                        let mut socket = TcpStream::connect(format!("{}:3100", gs_ip)).await.unwrap();
                        match socket.write_all(&sharable_data).await {
                            Ok(_) => {
                                println!("Sent {} bytes to {}", sharable_data.len(), gs_ip);
                            }
                            Err(e) => {
                                eprintln!("Failed to write to socket: {:?}", e);
                            }
                        }
                        drop(socket);
                    }
                });
            }
            let elapsed_time = start.elapsed();
            println!("Spawned threads to gossip to other GSs in {:.2?}", elapsed_time);
        }

        // let start = std::time::Instant::now();
        // let decompressed = zstd::stream::decode_all(Cursor::new(&**shared_buffer)).unwrap();
        // let elapsed_time = start.elapsed();
        // println!("Decompressed {} bytes in {:.2?}", decompressed.len(), elapsed_time);

        let start = std::time::Instant::now();
        let archived = unsafe { rkyv::access_unchecked::<ArchivedSignMerkleTreeRequest>(&shared_buffer) };
        //let sign_merkle_tree_request = rkyv::deserialize::<ArchivedSignMerkleTreeRequest, rancor::Error>(archived).unwrap();
        let elapsed_time = start.elapsed();
        println!("Deserialized {} bytes in {:.2?}", shared_buffer.len(), elapsed_time);
        println!("Received sign_merkle_tree_request with {} txs from {}", archived.txs.len(), archived.sender_ip);

        output_current_time("Received sign_merkle_tree_request");

        if archived.txs.is_empty() {
            println!("Received an empty sign_merkle_tree_request. Not processing.");
            return Ok(());
        }

        //process the request
        let start = std::time::Instant::now();
        let hashes = archived.txs
            .par_iter()
            .map(|tx| keccak(&tx.0).into())
            .collect::<Vec<[u8; 32]>>();
        let duration = start.elapsed();
        println!("Hashing of txs: {:?}", duration);

        let start = std::time::Instant::now();
        let mt = MerkleTree::<Keccak256>::from_leaves(&hashes);
        let duration = start.elapsed();
        println!("Build MerkleTree: {:?}", duration);
        if mt.root().is_none() {
            println!("MerkleTree root is None. Not processing.");
            return Ok(());
        }

        let root = mt.root().unwrap().to_vec();
        let mut client = communication::ss_merkle_tree_handler_service_client::SsMerkleTreeHandlerServiceClient::connect(format!("http://{}:37140", archived.sender_ip)).await?;
        let mut sign_mk_response = tonic::Request::new(SignMerkleTreeResponse {
            signature: self.secret_key.sign(&root).to_bytes().to_vec(),
            root,
        });
        sign_mk_response.metadata_mut().insert("gs_ip", self.my_ip.parse().unwrap());
        client.handle_sign_merkle_tree_response(sign_mk_response).await?;

        let start = std::time::Instant::now();
        gossip_join_set.join_all().await;
        let duration = start.elapsed();
        println!("Awaiting Gossiping to other GSs: {:?}", duration);

        Ok(())
    }

}

pub async fn run_listener(gs_mktree_handler:GsMerkleTreeHandler, addr: SocketAddr) {
    let listener = TcpListener::bind(&addr).await.expect("Failed to bind");
    println!("Server listening on {}", addr);

    let shared_gs_mktree_handler = Arc::new(gs_mktree_handler);

    loop {
        match listener.accept().await {
            Ok((socket, _)) => {
                println!("Accepted connection from: {}", socket.peer_addr().unwrap());
                let gs_mktree_handler = Arc::clone(&shared_gs_mktree_handler);
                tokio::task::spawn(async move {
                    if let Err(e) = gs_mktree_handler.handle_connection(socket).await {
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