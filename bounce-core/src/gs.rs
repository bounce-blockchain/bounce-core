use tonic::{transport::Server, Request, Response, Status};
use communication::{gs_service_server::{GsService, GsServiceServer}, Start, Response as GrpcResponse, SignMerkleTreeResponse};
use bounce_core::types::{ArchivedSignMerkleTreeRequest, Keccak256, RetransmissionRequest};
use bounce_core::common::*;
use bounce_core::config::Config;
use rayon::prelude::*;
use tokio::runtime::Runtime;
use std::env;
use std::collections::{HashMap, HashSet};
use std::net::{SocketAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use keccak_hash::keccak;
use rkyv::rancor;
use rs_merkle::MerkleTree;
use socket2::Socket;
use tokio::io::{AsyncReadExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::RwLock;
use tokio::task;
use tokio::time::timeout;
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

pub async fn handle_connection(mut socket: TcpStream, ss_ips: Vec<String>) -> Result<(), Box<dyn std::error::Error>> {
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

    let start = std::time::Instant::now();
    let archived = unsafe { rkyv::access_unchecked::<ArchivedSignMerkleTreeRequest>(&buffer) };
    //let sign_merkle_tree_request = rkyv::deserialize::<ArchivedSignMerkleTreeRequest, rancor::Error>(archived).unwrap();
    let elapsed_time = start.elapsed();
    println!("Deserialized {} bytes in {:.2?}", buffer.len(), elapsed_time);
    println!("Received sign_merkle_tree_request with {} txs", archived.txs.len());

    output_current_time("Received sign_merkle_tree_request");

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

    Ok(())
}

pub async fn run_listener(addr: SocketAddr, ss_ips: Vec<String>) {
    // let listener = TcpListener::bind(&addr).await.expect("Failed to bind");
    // println!("Server listening on {}", addr);
    //
    // loop {
    //     match listener.accept().await {
    //         Ok((socket, _)) => {
    //             println!("Accepted connection from: {}", socket.peer_addr().unwrap());
    //             let ss_ips = ss_ips.clone();
    //             task::spawn(async move{
    //                 if let Err(e) = handle_connection(socket, ss_ips).await {
    //                     eprintln!("Failed to handle connection: {:?}", e);
    //                 }
    //             });
    //         }
    //         Err(e) => {
    //             eprintln!("Failed to accept connection: {:?}", e);
    //         }
    //     }
    // }
    run_listener_multicast(ss_ips).await.unwrap();
}

pub async fn run_listener_multicast(ss_ips: Vec<String>) -> Result<(), Box<dyn std::error::Error>> {
    const MAX_UDP_PACKET_SIZE: usize = 65_507;
    const TIMEOUT_DURATION: Duration = Duration::from_secs(2);  // Timeout for retransmission

    let multicast_addr: Ipv4Addr = "239.255.0.1".parse().unwrap();
    let port = 3102;

    let socket = UdpSocket::bind(("0.0.0.0", port)).await?;
    let std_socket = socket.into_std()?;
    let socket2_socket = Socket::from(std_socket);
    let recv_buffer_size = socket2_socket.recv_buffer_size()?;
    println!("Current receive buffer size: {} bytes", recv_buffer_size);
    socket2_socket.set_recv_buffer_size(8 * 1024 * 1024)?; // 8 MB buffer
    let recv_buffer_size = socket2_socket.recv_buffer_size()?;
    println!("New receive buffer size: {} bytes", recv_buffer_size);
    let socket = UdpSocket::from_std(socket2_socket.into())?;

    if let Err(e) = socket.join_multicast_v4(multicast_addr, Ipv4Addr::UNSPECIFIED) {
        eprintln!("Failed to join multicast group: {:?}", e);
        return Err(Box::new(e));
    }

    println!("Server listening on multicast group {}:{}", multicast_addr, port);

    let mut buffer = vec![0u8; MAX_UDP_PACKET_SIZE];
    let mut message_fragments: HashMap<u32, Vec<Option<Vec<u8>>>> = HashMap::new();
    let mut received_lengths: HashMap<u32, usize> = HashMap::new();
    let mut waiting_for_chunks: HashMap<u32, HashSet<u32>> = HashMap::new();
    let mut message_sender_addr: HashMap<u32, SocketAddr> = HashMap::new();

    loop {
        // Use a timeout for receiving packets to handle missing packets
        let (bytes_received, src_addr) = match timeout(TIMEOUT_DURATION, socket.recv_from(&mut buffer)).await{
            Ok(Ok((bytes_received, src_addr))) => (bytes_received, src_addr),
            Ok(Err(e)) => {
                eprintln!("Failed to receive from socket: {:?}", e);
                continue;
            }
            Err(_) => {
                for (&message_id, missing_set) in &waiting_for_chunks {
                    if !missing_set.is_empty() {
                        println!("Requesting retransmission for message {}: missing {} chunks ", message_id, missing_set.len());

                        // Send retransmission request for missing chunks
                        let retransmission_request = RetransmissionRequest {
                            message_id,
                            missing_chunks: missing_set.iter().copied().collect(),
                        };

                        let serialized_request = bincode::serialize(&retransmission_request).unwrap();
                        println!("request len: {}", serialized_request.len());
                        socket.send_to(&serialized_request, message_sender_addr[&message_id]).await?;
                    }
                }
                continue;
            }
        };
        // Deserialize the header and the chunk
        let (message_id, sequence_number, total_chunks): (u32, u32, u32) = bincode::deserialize(&buffer[..12]).unwrap();
        let chunk = &buffer[12..bytes_received];

        // Store the sender address for retransmission requests
        message_sender_addr.insert(message_id, src_addr);

        // Initialize storage for fragments if this is the first chunk of the message
        let entry = message_fragments.entry(message_id).or_insert_with(|| vec![None; total_chunks as usize]);

        // Store the received chunk in the correct position
        entry[sequence_number as usize] = Some(chunk.to_vec());

        // Track how many chunks have been received
        *received_lengths.entry(message_id).or_insert(0) += 1;

        // Track missing chunks if this is the first time we see the message
        let missing_set = waiting_for_chunks.entry(message_id).or_insert_with(|| (0..total_chunks).collect());
        missing_set.remove(&sequence_number);

        // If all chunks have been received, reassemble the message
        if received_lengths[&message_id] == total_chunks as usize {
            println!("Reassembling message {} from {} chunks", message_id, total_chunks);

            let mut full_message = Vec::new();
            for chunk in message_fragments.remove(&message_id).unwrap() {
                full_message.extend(chunk.unwrap()); // Combine chunks in order
            }

            // Process the reassembled message
            process_data(&full_message, &vec![]).await?;

            // Remove tracking entries
            received_lengths.remove(&message_id);
            waiting_for_chunks.remove(&message_id);
        }
    }
}


async fn process_data(data: &[u8], ss_ips: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    println!("Processing reassembled data of size: {}", data.len());

    // Here you would handle the fully reassembled message
    // (e.g., deserialize it and perform the desired action)

    let start = std::time::Instant::now();
    let archived = unsafe { rkyv::access_unchecked::<ArchivedSignMerkleTreeRequest>(data) };
    //let sign_merkle_tree_request = rkyv::deserialize::<ArchivedSignMerkleTreeRequest, rancor::Error>(archived).unwrap();
    let elapsed_time = start.elapsed();
    println!("Deserialized {} bytes in {:.2?}", data.len(), elapsed_time);
    println!("Received sign_merkle_tree_request with {} txs", archived.txs.len());

    output_current_time("Received sign_merkle_tree_request");
    /*
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
    */
    Ok(())
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
    for port in ports {
        let addr: SocketAddr = format!("0.0.0.0:{}", port).parse().unwrap();
        tasks.push(task::spawn(run_listener(addr, ss_ips.clone())));
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
