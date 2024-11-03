use std::collections::{HashMap, HashSet};
use tonic::{transport::Server, Request, Response, Status};
use communication::{gs_service_server::{GsService, GsServiceServer}, Response as GrpcResponse};
use bounce_core::config::Config;
use tokio::runtime::Runtime;
use std::env;
use std::net::{SocketAddr};
use std::sync::Arc;
use bitvec::bitvec;
use tokio::sync::RwLock;
use bls::min_pk::{PublicKey, SecretKey, Signature};
use bls::min_pk::proof_of_possession::*;
use bounce_core::gs_mktree_handler::GsMerkleTreeHandler;
use bounce_core::gs_mktree_handler;
use bounce_core::types::{MultiSigned, SenderType, SignedCommitRecord, Start};
use key_manager::keyloader;

pub mod communication {
    tonic::include_proto!("communication");
}

pub struct GS {
    config: Config,
    my_ip: String,

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
        start: Request<communication::Start>,
    ) -> Result<Response<GrpcResponse>, Status> {
        println!("GS received a Start message from MC");
        let mut gs = self.gs.write().await;

        let start = start.into_inner();
        let deserialized_sigs = start.signatures.iter().map(|sig| Signature::from_bytes(&sig).unwrap()).collect::<Vec<Signature>>();

        let verified = gs.verify_mission_control_signature(&deserialized_sigs, &start.start_message);
        if !verified {
            return Err(Status::unauthenticated(format!("Failed to verify Mission Control signatures on Sending Station: {}", gs.my_ip)));
        }

        let deserialized_start_msg = bincode::deserialize(&start.start_message);
        if deserialized_start_msg.is_err() {
            return Err(Status::invalid_argument("Failed to serialize start message"));
        }
        let deserialized_start_msg:Start = deserialized_start_msg.unwrap();

        gs.start(deserialized_start_msg);

        let reply = GrpcResponse {
            message: "GS processed the start message".to_string(),
        };

        Ok(Response::new(reply))
    }

    async fn handle_commit_record(
        &self,
        request: Request<communication::SignedCommitRecord>,
    ) -> Result<Response<GrpcResponse>, Status> {
        let request = request.into_inner();
        let gs = self.gs.read().await;

        let deserialize = bincode::deserialize(&request.signed_commit_record);
        if deserialize.is_err() {
            return Err(Status::invalid_argument("Failed to deserialize the signed commit record"));
        }
        let signed_commit_record: SignedCommitRecord = deserialize.unwrap();
        let start = std::time::Instant::now();
        gs.handle_commit_record(signed_commit_record).await;
        let elapsed = start.elapsed();
        println!("GS processed the commit record in {:?}", elapsed);

        let reply = GrpcResponse {
            message: "GS processed the commit record".to_string(),
        };

        Ok(Response::new(reply))
    }

    async fn handle_sign_commit_record_request(&self, request: Request<communication::SignedCommitRecord>) -> Result<Response<communication::Signature>, Status> {
        let request = request.into_inner();
        let gs = self.gs.read().await;

        let deserialize = bincode::deserialize(&request.signed_commit_record);
        if deserialize.is_err() {
            return Err(Status::invalid_argument("Failed to deserialize the signed commit record"));
        }
        let signed_commit_record: SignedCommitRecord = deserialize.unwrap();
        let commit_record = signed_commit_record.commit_record;
        let commit_record_signature = signed_commit_record.signature;
        if !gs.verify_signature(&commit_record_signature, &bincode::serialize(&commit_record).unwrap(), SenderType::Satellite) {
            return Err(Status::unauthenticated("Failed to verify the signature of the commit record"));
        }

        let signature = gs.secret_key.sign(&bincode::serialize(&commit_record).unwrap());

        Ok(Response::new(communication::Signature {
            value: signature.to_bytes().to_vec(),
        }))
    }
}

impl GS {
    pub fn new(config: Config, my_ip: String, secret_key: SecretKey, mission_control_public_keys: Vec<PublicKey>) -> Self {
        GS {
            config,
            my_ip,
            secret_key,
            ground_station_public_keys: Vec::new(),
            sending_station_public_keys: Vec::new(),
            satellite_public_keys: Vec::new(),
            mission_control_public_keys,
            f: 0,
            mc_limit: 0.7,
        }
    }

    pub fn verify_signature(&self, signature: &Signature, msg: &[u8], sender: SenderType) -> bool {
        match sender {
            SenderType::GroundStation => {
                self.ground_station_public_keys.iter().any(|pk| signature.verify(pk, msg))
            }
            SenderType::SendingStation => {
                self.ground_station_public_keys.iter().any(|pk| signature.verify(pk, msg))
            }
            SenderType::Satellite => {
                self.ground_station_public_keys.iter().any(|pk| signature.verify(pk, msg))
            }
            _ => false,
        }
    }

    pub fn verify_mission_control_signature(&self, signatures: &[Signature], msg: &[u8]) -> bool {
        if self.mission_control_public_keys.is_empty() || signatures.len() as f32 / (self.mission_control_public_keys.len() as f32) < self.mc_limit {
            return false;
        }
        let mut verified = 0;
        for (_, sig) in signatures.iter().enumerate() {
            if self.mission_control_public_keys.iter().any(|pk| sig.verify(pk, msg)) {
                verified += 1;
            }
        }
        log::debug!(
            "Verified {} out of {} received Mission Control signatures, using {} public keys",
            verified,
            signatures.len(),
            self.mission_control_public_keys.len()
        );
        (verified as f32) / (self.mission_control_public_keys.len() as f32) >= self.mc_limit
    }

    pub fn start(&mut self, start: Start) {
        log::info!(
            "Received start message with {} number of ground stations",
            start.ground_station_public_keys.len()
        );
        self.ground_station_public_keys = start.ground_station_public_keys;
        self.sending_station_public_keys = start.sending_station_public_keys;
        self.satellite_public_keys = start.satellite_public_keys;
        self.f = start.f;

        println!("GS started with f: {}", self.f);
    }

    pub async fn handle_commit_record(&self, signed_commit_record: SignedCommitRecord) {
        let serialized_signed_commit_record = bincode::serialize(&signed_commit_record).unwrap();
        let commit_record = signed_commit_record.commit_record;
        println!("GS received a commit record from SAT with roots: {:?}", commit_record.txroots);
        println!("Send to other GSs");
        let serialized_commit_record = bincode::serialize(&commit_record).unwrap();

        let start = std::time::Instant::now();
        let mut signatures = vec![self.secret_key.sign(&serialized_commit_record)];
        for gs in &self.config.gs {
            if gs.ip == self.my_ip {
                continue;
            }
            let mut client = communication::gs_service_client::GsServiceClient::connect(format!("http://{}:37129", gs.ip)).await.unwrap();
            let request = tonic::Request::new(communication::SignedCommitRecord {
                signed_commit_record: serialized_signed_commit_record.clone(),
            });
            let response = client.handle_sign_commit_record_request(request).await.unwrap();
            let response = response.into_inner();
            let signature = Signature::from_bytes(&response.value).unwrap();
            signatures.push(signature);
        }
        let elapsed = start.elapsed();
        println!("GSs gathered the signatures for commit record in {:?}", elapsed);

        let signatures = signatures.iter().collect::<Vec<&Signature>>();

        let multi_signed_commit_record = MultiSigned::new(commit_record, bitvec![1; self.config.gs.len()], &signatures);
        println!("GSs multi signed the commit record. Sending to Sending Stations.");
        let start = std::time::Instant::now();
        for ss in &self.config.ss {
            let mut client = communication::ss_service_client::SsServiceClient::connect(format!("http://{}:37130", ss.ip)).await.unwrap();
            let request = tonic::Request::new(communication::MultiSignedCommitRecord {
                multi_signed_commit_record: bincode::serialize(&multi_signed_commit_record).unwrap(),
            });
            let response = client.handle_multi_signed_commit_record(request).await.unwrap();
            println!("Response from SS: {:?}", response.into_inner().message);
        }
        let elapsed = start.elapsed();
        println!("GSs sent the multi signed commit record to SSs in {:?}", elapsed);
    }
}

pub async fn run_gs(config_file: &str, index: usize) -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::load_from_file(config_file);
    let addr = "0.0.0.0:37129".to_string().parse()?;

    let secret_key = keyloader::read_private_key(format!("gs{:02}", index).as_str());
    let mission_control_public_keys = keyloader::read_mc_public_keys(config.mc.num_keys);

    let gs_ips = config.gs.iter().map(|gs| gs.ip.clone()).collect::<Vec<String>>();
    let my_ip = gs_ips[index].clone();

    let gs = GS::new(config.clone(), my_ip.clone(), secret_key.clone(), mission_control_public_keys);

    println!("GS is listening on {}", addr);

    // Define the ports you want to open
    let ports = vec![3100];
    let mut tasks = vec![];

    // Start a sign-merkle-request listener on each port
    let gs_map = build_tree(gs_ips, config.fanout.fanout);
    println!("GS map: {:?}", gs_map);
    for port in ports {
        let addr: SocketAddr = format!("0.0.0.0:{}", port).parse().unwrap();
        let gs_mktree_handler = GsMerkleTreeHandler::new(secret_key.clone(), my_ip.clone());
        tasks.push(tokio::task::spawn(gs_mktree_handler::run_listener(gs_mktree_handler, addr)));
    }

    Server::builder()
        .add_service(GsServiceServer::new(GSLockService {
            gs: Arc::new(RwLock::new(gs)),
        }))
        .serve(addr)
        .await?;

    Ok(())
}

fn build_tree(gs_ips:Vec<String>, fanout: usize) -> HashMap<String, HashSet<String>> {
    let mut tree: HashMap<String, HashSet<String>> = HashMap::new();
    let n = gs_ips.len();
    for i in 1..=n {
        let children_start = i * fanout + 1;
        let children_end = (i + 1) * fanout + 1;

        for child in children_start..children_end {
            if child > n {
                break;
            }

            tree.entry(gs_ips[i-1].clone()).or_insert_with(HashSet::new).insert(gs_ips[child-1].clone());
        }
    }

    tree
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
