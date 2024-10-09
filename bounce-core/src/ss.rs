use std::collections::{BTreeMap, HashSet};
use std::env;
use std::sync::Arc;
use communication::{ss_service_server::{SsService, SsServiceServer}, Start, Response as GrpcResponse};
use bounce_core::types::{Transaction, SignMerkleTreeRequest, State};
use bounce_core::config::Config;
use bounce_core::common::*;
use bounce_core::{ResetId, SlotId};
use bls::min_pk::{PublicKey, SecretKey};
use keccak_hash::keccak;
use key_manager::keyloader;
use rayon::prelude::*;
use rkyv::{rancor::Error};
use rand::Rng;
//use rand::seq::SliceRandom;
//use rand::thread_rng;
use std::net::{SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncWriteExt};
use tokio::net::{TcpStream};
use tokio::runtime::{Builder, Runtime};
use tokio::sync::RwLock;
use tonic::{transport::Server, Request, Response, Status};

pub mod communication {
    tonic::include_proto!("communication");
}

fn average_duration(durations: &[Duration]) -> Duration {
    let total: Duration = durations.iter().sum();
    total / (durations.len() as u32)
}

fn median_duration(mut durations: Vec<Duration>) -> Duration {
    durations.sort();
    let mid = durations.len() / 2;

    if durations.len() % 2 == 0 {
        let a = durations[mid - 1];
        let b = durations[mid];
        (a + b) / 2
    } else {
        durations[mid]
    }
}

fn confidence_interval_90(durations: &mut Vec<Duration>) -> (Duration, Duration) {
    durations.sort();

    let len = durations.len();
    let lower_idx = (len as f64 * 0.05).round() as usize;
    let upper_idx = (len as f64 * 0.95).round() as usize;
    if upper_idx == len {
        return (durations[lower_idx], durations[upper_idx - 1]);
    }

    let lower = durations[lower_idx];
    let upper = durations[upper_idx];

    (lower, upper)
}

pub struct SS {
    config: Config,
    gs_tx_receiver_ports: Vec<u16>,

    secret_key: SecretKey,
    state: State,
    slot_id: SlotId,
    reset_id: ResetId,
    // SlotIds to public keys of sending stations/satellties.
    slot_assignments: BTreeMap<SlotId, HashSet<PublicKey>>,
    ground_station_public_keys: Vec<PublicKey>,
    mission_control_public_keys: Vec<PublicKey>,
    f: u32,
    mc_limit: f32, // The fraction of Mission Control signatures required to accept a message. Default is 0.7.

    transactions: Vec<Transaction>,
    tx_hashes: Vec<[u8; 32]>,
}

pub struct SSLockService {
    ss: Arc<RwLock<SS>>,
}

#[tonic::async_trait]
impl SsService for SSLockService {
    async fn handle_start(
        &self,
        start: Request<Start>,
    ) -> Result<Response<GrpcResponse>, Status> {
        println!("SS received a Start message from MC with t: {}", start.get_ref().t);
        let mut ss = self.ss.write().await;

        ss.start(start.into_inner());

        let start = std::time::Instant::now();
        let sign_merkle_tree_request = SignMerkleTreeRequest {
            root: <[u8; 32]>::try_from(vec![0u8; 32]).unwrap(),
            txs: std::mem::take(&mut ss.transactions),
            hashes: std::mem::take(&mut ss.tx_hashes),
        };
        let elapsed = start.elapsed();
        println!("Created sign_merkle_tree_request in {:?}", elapsed);


        let mut durations = Vec::new();
        let mut total_times = Vec::new();
        for i in 0..20 {
            println!("SS is sending sign_merkle_tree_request {}", i);
            let start = std::time::Instant::now();
            let duration = ss.send_sign_merkle_tree_request(&sign_merkle_tree_request).await.expect("Failed to send transactions");
            let elapsed = start.elapsed();
            println!("sign_merkle_tree_request {} sent. Total Time: {:?}", i, elapsed);
            durations.push(duration);
            total_times.push(elapsed);
        }

        let avg = average_duration(&durations);
        println!("Average Duration: {:?}", avg);

        let median = median_duration(durations.clone());
        println!("Median Duration: {:?}", median);

        let (ci_lower, ci_upper) = confidence_interval_90(&mut durations.clone());
        println!(
            "90% Confidence Interval: [{:?}, {:?}]",
            ci_lower, ci_upper
        );

        let total_avg = average_duration(&total_times);
        println!("Total Average Duration: {:?}", total_avg);

        let total_median = median_duration(total_times.clone());
        println!("Total Median Duration: {:?}", total_median);

        let (total_ci_lower, total_ci_upper) = confidence_interval_90(&mut total_times.clone());
        println!(
            "Total 90% Confidence Interval: [{:?}, {:?}]",
            total_ci_lower, total_ci_upper
        );

        let reply = communication::Response {
            message: "SS processed the start message".to_string(),
        };

        Ok(Response::new(reply))
    }

    async fn handle_sign_merkle_tree_response(
        &self,
        response: Request<GrpcResponse>,
    ) -> Result<Response<GrpcResponse>, Status> {
        println!("SS received a sign_merkle_tree_response: {}", response.get_ref().message);
        output_current_time("");

        let reply = communication::Response {
            message: "ACK".to_string(),
        };

        Ok(Response::new(reply))
    }
}

impl SS {
    pub fn new(config: Config, secret_key: SecretKey, mission_control_public_keys: Vec<PublicKey>) -> Self {
        SS {
            config,
            secret_key,
            ground_station_public_keys: vec![],
            mission_control_public_keys,
            f: 0,
            mc_limit: 0.7,
            state: State::Inactive,
            slot_id: 0,
            reset_id: 0,
            transactions: Vec::new(),
            tx_hashes: Vec::new(),
            gs_tx_receiver_ports: vec![3100],
            slot_assignments: BTreeMap::new(),
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

    pub fn start(&mut self, start: Start) {
        self.state = State::Ready;
        self.ground_station_public_keys = start.ground_station_public_keys.iter().map(|pk| PublicKey::from_bytes(&pk.value).unwrap()).collect();
        self.slot_assignments = BTreeMap::new();
        for (slot_id, public_keys) in start.sending_station_slot_assignments.iter() {
            self.slot_assignments.insert(*slot_id, HashSet::from_iter(public_keys.public_keys.iter().map(|pk| PublicKey::from_bytes(&pk.value).unwrap())));
        }
        self.f = start.f;
        println!("SS started with f: {}", self.f);
    }

    pub async fn send_sign_merkle_tree_request(&self, sign_merkle_tree_request:&SignMerkleTreeRequest) -> std::io::Result<Duration> {
        let first_start = std::time::Instant::now();
        let start = std::time::Instant::now();
        let serialized_data = rkyv::to_bytes::<Error>(sign_merkle_tree_request).unwrap();
        let elapsed = start.elapsed();
        println!("Serialized sign_merkle_tree_request in {:?}", elapsed);

        let sharable_data = Arc::new(serialized_data);

        let gs_ips = self.config.gs.iter().map(|gs| gs.ip.clone()).collect::<Vec<String>>();

        let start = std::time::Instant::now();
        let runtime = Builder::new_multi_thread()
            .worker_threads(gs_ips.len())
            .thread_name("mk-request-sender")
            .build()
            .unwrap();
        let mut handles = vec![];
        for gs_ip in gs_ips {
            let addr: SocketAddr = format!("{}:{}", gs_ip, self.gs_tx_receiver_ports[0]).parse().unwrap();
            println!("Spawning process to send sign_merkle_tree_request to {}", addr);
            let sharable_data = Arc::clone(&sharable_data);
            let handle = runtime.spawn(async move {
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
            handles.push(handle);
        }
        let elapsed = start.elapsed();
        println!("Spawned all workers in {:?}", elapsed);

        let start = std::time::Instant::now();
        for handle in handles {
            handle.await.unwrap();
        }
        let elapsed = start.elapsed();
        output_current_time(&format!("sign_merkle_tree_request sent. Time elapsed: {:?}", elapsed));

        let last_elapsed = first_start.elapsed();
        println!("Total time elapsed in method: {:?}", last_elapsed);

        Ok(elapsed)
    }
}

pub async fn run_ss(config_file: &str, index: usize) -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::load_from_file(config_file);
    let addr = "0.0.0.0:37130".to_string().parse()?;

    let secret_key = keyloader::read_private_key(format!("ss{:02}", index).as_str());
    let mission_control_public_keys = keyloader::read_mc_public_keys(config.mc.num_keys);

    let mut ss = SS::new(config, secret_key, mission_control_public_keys);

    println!("SS is generating transactions");
    //generate 1million transactions
    let mut rng = rand::thread_rng();
    let mut data = [0u8; 256];
    rng.fill(&mut data);
    let data = data.to_vec();
    for i in 0..1_000_000 {
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
        .add_service(SsServiceServer::new(SSLockService {
            ss: Arc::new(RwLock::new(ss)),
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

    // Start the SS component
    rt.block_on(run_ss(config_file, index)).unwrap();
}
