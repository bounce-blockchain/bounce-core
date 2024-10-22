use std::collections::{HashMap, HashSet};
use tonic::{transport::Server, Request, Response, Status};
use communication::{gs_service_server::{GsService, GsServiceServer}, Start, Response as GrpcResponse, SignMerkleTreeResponse};
use bounce_core::types::{ArchivedSignMerkleTreeRequest, Keccak256};
use bounce_core::common::*;
use bounce_core::config::Config;
use rayon::prelude::*;
use tokio::runtime::Runtime;
use std::env;
use std::io::Cursor;
use std::net::{SocketAddr};
use std::sync::Arc;
use std::time::Instant;
use keccak_hash::keccak;
use rs_merkle::MerkleTree;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tokio::task;
use tokio::task::JoinSet;
use bls::min_pk::{PublicKey, SecretKey};
use key_manager::keyloader;

pub mod communication {
    tonic::include_proto!("communication");
}

pub struct GS {
    config: Config,

    secret_key: SecretKey,

    // Public keys of other Ground Stations and this one.
    ground_station_public_keys: Vec<PublicKey>,
    sending_station_public_keys: Vec<PublicKey>,
    satellite_public_keys: Vec<PublicKey>,
    mission_control_public_keys: Vec<PublicKey>,
    f: u32,
    mc_limit: f32, // The fraction of Mission Control signatures required to accept a message. Default is 0.7.
}

pub struct GSLockService {
    gs: Arc<RwLock<GS>>,
}

#[tonic::async_trait]
impl GsService for GSLockService {
    async fn handle_start(
        &self,
        start: Request<Start>,
    ) -> Result<Response<GrpcResponse>, Status> {
        println!("GS received a Start message from MC with t: {}", start.get_ref().t);
        let mut gs = self.gs.write().await;

        gs.start(start.into_inner());

        let reply = GrpcResponse {
            message: "GS processed the start message".to_string(),
        };

        Ok(Response::new(reply))
    }
}

impl GS {
    pub fn new(config: Config, secret_key: SecretKey, mission_control_public_keys: Vec<PublicKey>) -> Self {
        GS {
            config,
            secret_key,
            ground_station_public_keys: Vec::new(),
            sending_station_public_keys: Vec::new(),
            satellite_public_keys: Vec::new(),
            mission_control_public_keys,
            f: 0,
            mc_limit: 0.7,
        }
    }

    pub fn start(&mut self, start: Start) {
        log::info!(
            "Received start message with {} number of ground stations",
            start.ground_station_public_keys.len()
        );
        self.ground_station_public_keys = start.ground_station_public_keys.iter().map(|pk| PublicKey::from_bytes(&pk.value).unwrap()).collect();
        self.sending_station_public_keys = start.sending_station_public_keys.iter().map(|pk| PublicKey::from_bytes(&pk.value).unwrap()).collect();
        self.satellite_public_keys = start.satellite_public_keys.iter().map(|pk| PublicKey::from_bytes(&pk.value).unwrap()).collect();
        self.f = start.f;

        println!("GS started with f: {}", self.f);
    }
}

pub async fn handle_connection(mut socket: TcpStream, ss_ips: Vec<String>, gs_map: HashMap<String, HashSet<String>>, my_ip: String) -> Result<(), Box<dyn std::error::Error>> {
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

    let gs_peers = gs_map.get(&my_ip).unwrap();
    let mut gossip_join_set = JoinSet::new();
    if gs_peers.len() > 0 {
        println!("Gossiping to other GSs: {:?}", gs_map.get(&my_ip));
        let start = std::time::Instant::now();
        let sharable_data = Arc::new(buffer.clone());
        let elapsed_time = start.elapsed();
        println!("Cloned {} bytes in {:.2?}", sharable_data.len(), elapsed_time);
        let start = std::time::Instant::now();
        for gs_ip in gs_map.get(&my_ip).unwrap() {
            let sharable_data = sharable_data.clone();
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

    let start = std::time::Instant::now();
    let decompressed = zstd::stream::decode_all(Cursor::new(buffer)).unwrap();
    let elapsed_time = start.elapsed();
    println!("Decompressed {} bytes in {:.2?}", decompressed.len(), elapsed_time);

    let start = std::time::Instant::now();
    let archived = unsafe { rkyv::access_unchecked::<ArchivedSignMerkleTreeRequest>(&decompressed) };
    //let sign_merkle_tree_request = rkyv::deserialize::<ArchivedSignMerkleTreeRequest, rancor::Error>(archived).unwrap();
    let elapsed_time = start.elapsed();
    println!("Deserialized {} bytes in {:.2?}", decompressed.len(), elapsed_time);
    println!("Received sign_merkle_tree_request with {} txs", archived.txs.len());

    output_current_time("Received sign_merkle_tree_request");

    //process the request
    let start = Instant::now();
    let hashes = archived.txs
        .par_iter()
        .map(|tx| keccak(&tx.0).into())
        .collect::<Vec<[u8; 32]>>();
    let duration = start.elapsed();
    println!("Hashing of txs: {:?}", duration);

    let start = Instant::now();
    let mt = MerkleTree::<Keccak256>::from_leaves(&hashes);
    let duration = start.elapsed();
    println!("Build MerkleTree: {:?}", duration);

    let mut client = communication::ss_service_client::SsServiceClient::connect(format!("http://{}:37130", ss_ips[0])).await?;
    let sign_mk_response = tonic::Request::new(SignMerkleTreeResponse {
        signature: vec![],
        root: mt.root().unwrap().to_vec(),
    });
    client.handle_sign_merkle_tree_response(sign_mk_response).await?;

    let start = Instant::now();
    gossip_join_set.join_all().await;
    let duration = start.elapsed();
    println!("Gossiping to other GSs: {:?}", duration);

    Ok(())
}

pub async fn run_listener(addr: SocketAddr, ss_ips: Vec<String>, gs_map: HashMap<String, HashSet<String>>, my_ip: String) {
    let listener = TcpListener::bind(&addr).await.expect("Failed to bind");
    println!("Server listening on {}", addr);

    loop {
        match listener.accept().await {
            Ok((socket, _)) => {
                println!("Accepted connection from: {}", socket.peer_addr().unwrap());
                let ss_ips = ss_ips.clone();
                let gs_map = gs_map.clone();
                let my_ip = my_ip.clone();
                task::spawn(async move {
                    if let Err(e) = handle_connection(socket, ss_ips, gs_map, my_ip).await {
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
    let addr = "0.0.0.0:37129".to_string().parse()?;

    let secret_key = keyloader::read_private_key(format!("gs{:02}", index).as_str());
    let mission_control_public_keys = keyloader::read_mc_public_keys(config.mc.num_keys);

    let gs = GS::new(config.clone(), secret_key, mission_control_public_keys);

    println!("GS is listening on {}", addr);

    // Define the ports you want to open
    let ports = vec![3100];
    let mut tasks = vec![];

    // Start a ss listener on each port
    let ss_ips = config.ss.iter().map(|ss| ss.ip.clone()).collect::<Vec<String>>();
    let mut gs_ips = config.gs.iter().map(|gs| gs.ip.clone()).collect::<Vec<String>>();
    let my_ip = gs_ips[index].clone();
    gs_ips.insert(0, "dummy".to_string());
    gs_ips.insert(1, "dummy".to_string());
    let mut gs_map: HashMap<String, HashSet<String>> = HashMap::new();
    for (i, gs) in gs_ips.iter().enumerate() {
        if i < 2 {
            continue;
        }
        let mut set = HashSet::new();
        if i * 3 - 1 < gs_ips.len() {
            set.insert(gs_ips[i * 3 - 1].clone());
        }
        if i * 3 < gs_ips.len() {
            set.insert(gs_ips[i * 3].clone());
        }
        if i * 3 + 1 < gs_ips.len() {
            set.insert(gs_ips[i * 3 + 1].clone());
        }
        gs_map.insert(gs.clone(), set);
    }
    println!("GS map: {:?}", gs_map);
    for port in ports {
        let addr: SocketAddr = format!("0.0.0.0:{}", port).parse().unwrap();
        tasks.push(task::spawn(run_listener(addr, ss_ips.clone(), gs_map.clone(), my_ip.clone())));
    }

    Server::builder()
        .add_service(GsServiceServer::new(GSLockService {
            gs: Arc::new(RwLock::new(gs)),
        }))
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
