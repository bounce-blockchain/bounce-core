use std::collections::{HashMap, HashSet};
use tonic::{transport::Server, Request, Response, Status};
use communication::{gs_service_server::{GsService, GsServiceServer}, Start, Response as GrpcResponse};
use bounce_core::config::Config;
use tokio::runtime::Runtime;
use std::env;
use std::net::{SocketAddr};
use std::sync::Arc;
use tokio::sync::RwLock;
use bls::min_pk::{PublicKey, SecretKey};
use bounce_core::gs_mktree_handler::GsMerkleTreeHandler;
use bounce_core::gs_mktree_handler;
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

pub async fn run_gs(config_file: &str, index: usize) -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::load_from_file(config_file);
    let addr = "0.0.0.0:37129".to_string().parse()?;

    let secret_key = keyloader::read_private_key(format!("gs{:02}", index).as_str());
    let mission_control_public_keys = keyloader::read_mc_public_keys(config.mc.num_keys);

    let gs = GS::new(config.clone(), secret_key.clone(), mission_control_public_keys);

    println!("GS is listening on {}", addr);

    // Define the ports you want to open
    let ports = vec![3100];
    let mut tasks = vec![];

    // Start a sign-merkle-request listener on each port
    let gs_ips = config.gs.iter().map(|gs| gs.ip.clone()).collect::<Vec<String>>();
    let my_ip = gs_ips[index].clone();
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
