use std::env;
use std::net::SocketAddr;
use std::sync::{Arc};
use std::time::{Duration, UNIX_EPOCH};
use keccak_hash::keccak;
use rand::Rng;
use rayon::prelude::*;
use rs_merkle::MerkleTree;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio::sync::RwLock;
use bounce_core::config::Config;
use bounce_core::types::{Keccak256, SignMerkleTreeRequest, Transaction};
use bounce_core::communication::{ss_merkle_tree_handler_service_server::{SsMerkleTreeHandlerService, SsMerkleTreeHandlerServiceServer}, SignMerkleTreeResponse, Response as GrpcResponse};
use tonic::{transport::Server, Request, Response, Status};
use bls::min_pk::PublicKey;
use bounce_core::common::output_current_time;
use bounce_core::communication;

fn confidence_interval_90(durations: &mut [u128]) -> (u128, u128) {
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

struct Benchmark {
    pub config: Config,
    pub my_ip: String,
    pub sending_time_stamp: u128,
    pub receiving_time_elapsed: Vec<u128>,
    pub receiving_time_for_first_response: Vec<u128>,
    pub receiving_time_for_half_response: Vec<u128>,
    pub receiving_time_for_all_response: Vec<u128>,
    pub current_received: usize,
    pub txs: Vec<Transaction>,
    pub root: [u8; 32],
    pub iterations: u32,
    pub target_iterations: u32,
    pub total_time: u128,
    pub sending_time: u128,
}

impl Benchmark {
    pub fn new(config: Config, my_ip: String, txs: Vec<Transaction>, root:[u8; 32], target_iterations:u32) -> Benchmark {
        Benchmark {
            receiving_time_elapsed: vec![0; config.gs.len()],
            receiving_time_for_first_response: vec![],
            receiving_time_for_half_response: vec![],
            receiving_time_for_all_response: vec![],
            config,
            my_ip,
            sending_time_stamp: 0,
            current_received: 0,
            txs,
            root,
            iterations: 0,
            target_iterations,
            total_time: 0,
            sending_time: 0,
        }
    }

    pub async fn run_benchmark(&mut self){
        self.iterations += 1;
        println!("\nRunning benchmark iteration {}", self.iterations);
        let txs = self.txs.clone();
        let sign_merkle_tree_request = SignMerkleTreeRequest {
            txs,
            sender_ip: self.my_ip.clone(),
        };
        let elapsed = self.send_sign_merkle_tree_request(&sign_merkle_tree_request).await.unwrap();
        self.total_time += elapsed.as_millis();

    }

    pub async fn send_sign_merkle_tree_request(&mut self, sign_merkle_tree_request:&SignMerkleTreeRequest) -> std::io::Result<Duration> {
        let current_time = std::time::SystemTime::now();
        self.sending_time_stamp = current_time.duration_since(UNIX_EPOCH).expect("Time went backwards").as_millis();
        println!("Sending sign_merkle_tree_request at {}", self.sending_time_stamp);

        let first_start = std::time::Instant::now();
        let start = std::time::Instant::now();
        let serialized_data = rkyv::to_bytes::<rkyv::rancor::Error>(sign_merkle_tree_request).unwrap();
        let elapsed = start.elapsed();
        println!("Serialized sign_merkle_tree_request in {:?}", elapsed);

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
        for gs_ip in &gs_ips[0..std::cmp::min(self.config.fanout.fanout, gs_ips.len())] {
            let addr: SocketAddr = format!("{}:{}", gs_ip, 3100).parse().unwrap();
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
        self.sending_time += elapsed.as_millis();

        let last_elapsed = first_start.elapsed();
        println!("Total time elapsed in method: {:?}", last_elapsed);

        Ok(last_elapsed)
    }
}

struct BenchmarkLockService {
    pub benchmark: Arc<RwLock<Benchmark>>,
}

#[tonic::async_trait]
impl SsMerkleTreeHandlerService for BenchmarkLockService {
    async fn handle_sign_merkle_tree_response(
        &self,
        request: Request<SignMerkleTreeResponse>,
    ) -> Result<Response<GrpcResponse>, Status> {
        let metadata = request.metadata().clone();
        let gs_ip = metadata.get("gs_ip").unwrap().to_str().unwrap();
        let request = request.into_inner();
        let root: [u8; 32] = request.root.try_into().expect("Expected a response with root of 32 bytes");

        let mut benchmark = self.benchmark.write().await;

        let current_time = std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis();
        let sending_time = benchmark.sending_time_stamp;
        let elapsed = current_time - sending_time;
        benchmark.current_received += 1;
        let current_received = benchmark.current_received;
        benchmark.receiving_time_elapsed[current_received-1] += elapsed;
        if current_received == 1 {
            println!("Updating first response time");
            benchmark.receiving_time_for_first_response.push(elapsed);
        }
        if current_received == (benchmark.config.gs.len()+1) / 2 {
            println!("Updating half response time");
            benchmark.receiving_time_for_half_response.push(elapsed);
        }
        if current_received == benchmark.config.gs.len() {
            println!("Updating all response time");
            benchmark.receiving_time_for_all_response.push(elapsed);
        }
        println!("\nReceived sign_merkle_tree_response from {} at {}, which elapsed {}", gs_ip, current_time, elapsed);
        println!("root matches: {:?}", benchmark.root == root);

        if benchmark.current_received == benchmark.config.gs.len() {
            benchmark.current_received = 0;
            if benchmark.iterations < benchmark.target_iterations {
                benchmark.run_benchmark().await;
            } else {
                println!("Benchmark finished");
                println!("Average Total time: {}ms", benchmark.total_time/benchmark.target_iterations as u128);
                println!("Average Sending time: {}ms", benchmark.sending_time/benchmark.target_iterations as u128);
                let (lower, upper) = confidence_interval_90(&mut benchmark.receiving_time_for_first_response);
                println!("90% confidence interval for receiving the first response: [{}, {}]", lower, upper);
                let (lower, upper) = confidence_interval_90(&mut benchmark.receiving_time_for_half_response);
                println!("90% confidence interval for receiving half of the responses: [{}, {}]", lower, upper);
                let (lower, upper) = confidence_interval_90(&mut benchmark.receiving_time_for_all_response);
                println!("90% confidence interval for receiving all responses: [{}, {}]", lower, upper);
                println!("Average Receiving time: {:?}", benchmark.receiving_time_elapsed.iter().map(|x| x/benchmark.target_iterations as u128).collect::<Vec<u128>>());
            }
        }

        let reply = communication::Response {
            message: "ACK".to_string(),
        };

        Ok(Response::new(reply))
    }
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    let config_file = &args[1];
    let index = args[2].parse::<usize>().expect("Index should be a valid number");

    let config = Config::load_from_file(config_file);
    let addr = "0.0.0.0:37140".to_string().parse().unwrap();

    let my_ip = config.ss[index].ip.clone();

    let num_txs = 1_000_000;
    println!("Mktree_handler Generating {} random transactions...", num_txs);
    let start = std::time::Instant::now();
    let mut txs = Vec::new();
    for i in 0..num_txs {
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
    println!("Mktree_handler Generated {} random transactions in {:?}", num_txs, elapsed);
    let start = std::time::Instant::now();
    let tx_hashes = txs
        .par_iter()
        .map(|tx| keccak(tx.as_ref()).into())
        .collect::<Vec<[u8; 32]>>();
    let elapsed = start.elapsed();
    println!("Hashed {} transactions in {:?}", tx_hashes.len(), elapsed);
    let start = std::time::Instant::now();
    let mt = MerkleTree::<Keccak256>::from_leaves(&tx_hashes);
    let duration = start.elapsed();
    println!("Merkle tree built in {:?}", duration);

    let benchmark = Benchmark::new(config, my_ip, txs, mt.root().unwrap(), 20);
    let benchmark_lock = Arc::new(RwLock::new(benchmark));

    let benchmark_service = BenchmarkLockService {
        benchmark: Arc::clone(&benchmark_lock),
    };

    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(3)).await; // wait for the server to start
        let mut benchmark = benchmark_lock.write().await;
        benchmark.run_benchmark().await;
    });

    Server::builder()
        .add_service(SsMerkleTreeHandlerServiceServer::new(benchmark_service))
        .serve(addr)
        .await
        .unwrap();
}