use std::env;
use std::net::SocketAddr;
use std::sync::{Arc};
use std::time::{Duration, UNIX_EPOCH};
use std::io::Write;
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
    pub my_port: u16,
    pub sending_time_stamp: Vec<u128>,
    pub receiving_time_elapsed: Vec<Vec<u128>>,
    pub num_received: Vec<usize>,
    pub num_bench_completed: usize,
    pub txs: Vec<Vec<Transaction>>,
    pub root: [u8; 32],
    pub total_time: u128,
    pub sending_time: u128,
    pub all_root_matched: bool,
    pub total_benchmarks: usize,
}

impl Benchmark {
    pub fn new(config: Config, my_ip: String, my_port: u16, txs: Vec<Vec<Transaction>>, total_benchmarks:usize) -> Benchmark {
        Benchmark {
            receiving_time_elapsed: vec![vec![]; total_benchmarks],
            num_received: vec![0; total_benchmarks],
            config,
            my_ip,
            my_port,
            sending_time_stamp: vec![0; total_benchmarks],
            num_bench_completed: 0,
            txs,
            root: [0; 32],
            total_time: 0,
            sending_time: 0,
            all_root_matched: true,
            total_benchmarks,
        }
    }

    pub async fn run_benchmark(&mut self){
        //self.root = [0; 32];
        for i in 0..self.total_benchmarks {
            let current_time = std::time::SystemTime::now();
            self.sending_time_stamp[i] = current_time.duration_since(UNIX_EPOCH).expect("Time went backwards").as_millis();
            println!("Sending sign_merkle_tree_request at {}", self.sending_time_stamp[i]);
            println!("Benchmark {}", i);
            let start = std::time::Instant::now();
            let sign_merkle_tree_request = SignMerkleTreeRequest {
                txs: std::mem::take(&mut self.txs[i]),
                sender_ip: self.my_ip.clone(),
                sender_port: self.my_port,
                bench_id: i as u32,
            };
            let elapsed = start.elapsed();
            println!("Create sign_merkle_tree_request in {:?}", elapsed);
            let elapsed = self.send_sign_merkle_tree_request(&sign_merkle_tree_request).await.unwrap();
            self.total_time += elapsed.as_millis();

            // let start = std::time::Instant::now();
            // let tx_hashes = sign_merkle_tree_request.txs
            //     .par_iter()
            //     .map(|tx| keccak(tx.as_ref()).into())
            //     .collect::<Vec<[u8; 32]>>();
            // let elapsed = start.elapsed();
            // println!("Hashed {} transactions in {:?}", tx_hashes.len(), elapsed);
            // let start = std::time::Instant::now();
            // let mt = MerkleTree::<Keccak256>::from_leaves(&tx_hashes);
            // let duration = start.elapsed();
            // println!("Merkle tree built in {:?}", duration);
            // self.root = mt.root().unwrap();
        }
    }

    pub async fn send_sign_merkle_tree_request(&mut self, sign_merkle_tree_request:&SignMerkleTreeRequest) -> std::io::Result<Duration> {
        let first_start = std::time::Instant::now();
        let start = std::time::Instant::now();
        println!("Serializing sign_merkle_tree_request with {} txs", sign_merkle_tree_request.txs.len());
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
        output_current_time(&format!("sign_merkle_tree_request sent. Sending overhead: {:?}", elapsed));
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
        let gs_ip = gs_ip.to_string();
        let bench_id = metadata.get("bench_id").unwrap().to_str().unwrap().parse::<usize>().unwrap();
        let request = request.into_inner();
        let root: [u8; 32] = request.root.try_into().expect("Expected a response with root of 32 bytes");
        let benchmark = Arc::clone(&self.benchmark);

        tokio::task::spawn(async move {
            let mut benchmark = benchmark.write().await;

            let current_time = std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_millis();
            let elapsed = current_time - benchmark.sending_time_stamp[bench_id];
            benchmark.num_received[bench_id] += 1;
            benchmark.receiving_time_elapsed[bench_id].push(elapsed);
            println!("\nReceived sign_merkle_tree_response from {} at {}, which elapsed {}", gs_ip, current_time, elapsed);
            println!("root matches: {:?}", benchmark.root == root);
            if benchmark.root != root {
                benchmark.all_root_matched = false;
            }

            if benchmark.num_received[bench_id] == benchmark.config.gs.len() {
                benchmark.num_bench_completed += 1;
                if benchmark.num_bench_completed == benchmark.total_benchmarks {
                    println!("Benchmark finished");
                    println!("All root matched: {:?}", benchmark.all_root_matched);
                    println!("Total time: {}ms", benchmark.total_time);
                    let serialized = bincode::serialize(&benchmark.receiving_time_elapsed).unwrap();
                    let mut file = std::fs::File::create("receiving_time_elapsed_tiled.bin").unwrap();
                    file.write_all(&serialized).unwrap();
                    println!("data written to receiving_time_elapsed_tiled.bin");
                    let serialized = bincode::serialize(&benchmark.sending_time_stamp).unwrap();
                    let mut file = std::fs::File::create("sending_time_stamp.bin").unwrap();
                    file.write_all(&serialized).unwrap();
                    println!("data written to sending_time_stamp.bin");
                }
            }
        });

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
    let root = mt.root().unwrap();

    let num_benchmarks = 20;
    let mut txs_tiled = Vec::new();
    for i in 0..num_benchmarks {
        txs_tiled.push(txs.clone());
    }
    let elapsed = start.elapsed();
    println!("Mktree_handler Generated {} random transactions in {:?}", num_txs, elapsed);

    let mut benchmark = Benchmark::new(config.clone(), my_ip.clone(), 37140, txs_tiled, num_benchmarks);
    benchmark.root = root;
    let benchmark_lock = Arc::new(RwLock::new(benchmark));
    let benchmark_service = BenchmarkLockService {
        benchmark: Arc::clone(&benchmark_lock),
    };
    let addr:SocketAddr = format!("{}:{}", my_ip, 37140).parse().unwrap();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(3)).await; // wait for the server to start
        let mut benchmark = benchmark_lock.write().await;
        benchmark.run_benchmark().await;
    });

    Server::builder()
        .add_service(SsMerkleTreeHandlerServiceServer::new(benchmark_service))
        .serve(addr.clone())
        .await
        .unwrap();
}