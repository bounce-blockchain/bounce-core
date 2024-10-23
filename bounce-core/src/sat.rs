use std::collections::BTreeMap;
use tonic::{transport::Server, Request, Response, Status};
use communication::{sat_service_server::{SatService, SatServiceServer}, Start, Response as GrpcResponse};
use crate::config::Config;
use tokio::sync::RwLock;

pub mod communication {
    tonic::include_proto!("communication");
}

pub struct Sat {
    config: Config,
    secret_key: SecretKey,
    state: State,
    //sending_station_messages: Vec<SendingStationMessage>,
    //dummy_sending_station_message: Option<SendingStationMessage>,
    slot_id: SlotId,
    reset_id: ResetId,
    mission_control_public_keys: Vec<PublicKey>,
    ground_station_public_keys: Vec<PublicKey>,
    sending_station_public_keys: Vec<PublicKey>,
    f: u32,
    mc_limit: f32, // The fraction of Mission Control signatures required to accept a message. Default is 0.7.
    // reset_received: Option<Reset>,
    // last_positive_opt: Option<CommitRecord>,
    // first_negative_opt: Option<CommitRecord>,
    slot_assignments: BTreeMap<SlotId, PublicKey>,
}

pub struct SatLockService {
    sat: Arc<RwLock<Sat>>,
}

#[tonic::async_trait]
impl SatService for SatLockService {
    async fn handle_start(
        &self,
        start: Request<Start>,
    ) -> Result<Response<GrpcResponse>, Status> {
        println!("Sat received a Start message from MC with t: {}", start.get_ref().t);
        let mut sat = self.sat.write().await;

        sat.start(start.into_inner());

        let reply = communication::Response {
            message: "Sat processed the start message".to_string(),
        };

        Ok(Response::new(reply))
    }
}

impl Sat {
    pub fn new(config: Config, secret_key: SecretKey, mission_control_public_keys: Vec<PublicKey>) -> Self {
        Sat {
            config,
            secret_key,
            mission_control_public_keys,
            ground_station_public_keys: vec![],
            sending_station_public_keys: vec![],
            f: 0,
            mc_limit: 0.7,
            slot_assignments: BTreeMap::new(),
            slot_id: 0,
            reset_id: 0,
            // sending_station_messages: Vec::new(),
            // dummy_sending_station_message: None,
            // last_positive_opt: None,
            // first_negative_opt: None,
            state: State::Inactive,
            // reset_received: None,
        }
    }

    pub fn start(&mut self, start: Start) {
        self.state = State::Ready;
        self.ground_station_public_keys = start.ground_station_public_keys.iter().map(|pk| PublicKey::from_bytes(&pk.value).unwrap()).collect();
        self.sending_station_public_keys = start.sending_station_public_keys.iter().map(|pk| PublicKey::from_bytes(&pk.value).unwrap()).collect();
        self.slot_assignments = start.satellite_slot_assignments.iter().map(|(slot_id, pk)| {
            (*slot_id, PublicKey::from_bytes(&pk.value).unwrap())
        }).collect();

        self.f = start.f;

        println!("Sat started with f: {}", self.f);
    }
}

pub async fn run_sat(config_file: &str, index: usize) -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::load_from_file(config_file);
    let sat_ip = &config.sat[index].ip;
    let addr = format!("{}:37131", sat_ip).parse()?;

    let secret_key = keyloader::read_private_key(format!("sat{:02}", index).as_str());
    let mission_control_public_keys = keyloader::read_mc_public_keys(config.mc.num_keys);

    let sat = Sat::new(config,secret_key, mission_control_public_keys);

    println!("Sat is listening on {}", addr);

    Server::builder()
        .add_service(SatServiceServer::new(SatLockService {
            sat: Arc::new(RwLock::new(sat)),
        }))
        .serve(addr)
        .await?;

    Ok(())
}

use tokio::runtime::Runtime;
use std::env;
use std::sync::Arc;
use bls::min_pk::{PublicKey, SecretKey};
use bounce_core::{ResetId, SlotId};
use bounce_core::types::State;
use key_manager::keyloader;

mod config;

fn main() {
    // Create a new Tokio runtime
    let rt = Runtime::new().unwrap();

    // Load the configuration file from command-line arguments
    let args: Vec<String> = env::args().collect();
    let config_file = &args[1];
    let index = args[2].parse::<usize>().expect("Index should be a valid number");

    // Start the Sat component
    rt.block_on(run_sat(config_file, index)).unwrap();
}
