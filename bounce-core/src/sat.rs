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

    clock_send: tokio::sync::mpsc::UnboundedSender<u64>,

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

        let (clock_send, clock_recv) = tokio::sync::mpsc::unbounded_channel();
        let (slot_send, mut slot_receive) = tokio::sync::broadcast::channel(9);

        let start = start.into_inner();
        let t = start.t;
        sat.start(start,clock_send);

        let sat_service = self.sat.clone();
        tokio::spawn(async move {
            loop {
                let slog_msg = slot_receive.recv().await;
                match slog_msg {
                    Ok(msg) => {
                        match msg {
                            SlotMessage::SlotTick => {
                                let mut sat = sat_service.write().await;
                                sat.handle_slot_tick().await;
                            }
                            _ => {}
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed to receive SlotMessage: {:?}", e);
                    }
                }
            }
        });

        let mut slot_timer = SlotClock::new(5000, 500, 4000, slot_send, clock_recv);
        tokio::spawn(async move { if (slot_timer.start().await).is_err() {} });

        sat.clock_send.send(t).unwrap();

        let reply = communication::Response {
            message: "Sat processed the start message".to_string(),
        };

        Ok(Response::new(reply))
    }

    async fn handle_sending_station_message(
        &self,
        request: Request<communication::SendingStationMessage>,
    ) -> Result<Response<GrpcResponse>, Status> {
        let request = request.into_inner();
        let deserialized_ss_msg = bincode::deserialize(&request.sending_station_message);
        if deserialized_ss_msg.is_err() {
            return Err(Status::invalid_argument("Failed to deserialize SendingStationMessage"));
        }
        let sending_station_message:SendingStationMessage = deserialized_ss_msg.unwrap();
        let deserialized_sig = Signature::from_bytes(&request.signature);
        if deserialized_sig.is_err() {
            return Err(Status::invalid_argument("Failed to deserialize Signature"));
        }
        let signature:Signature = deserialized_sig.unwrap();

        let mut sat = self.sat.write().await;
        sat.handle_sending_station_message(sending_station_message, signature);


        let reply = communication::Response {
            message: "ACK".to_string(),
        };

        Ok(Response::new(reply))
    }
}

impl Sat {
    pub fn new(config: Config, secret_key: SecretKey, mission_control_public_keys: Vec<PublicKey>) -> Self {
        Sat {
            config,
            secret_key,
            clock_send: tokio::sync::mpsc::unbounded_channel().0,
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

    pub fn start(&mut self, start: Start, clock_send: tokio::sync::mpsc::UnboundedSender<u64>) {
        self.state = State::Ready;
        self.ground_station_public_keys = start.ground_station_public_keys.iter().map(|pk| PublicKey::from_bytes(&pk.value).unwrap()).collect();
        self.sending_station_public_keys = start.sending_station_public_keys.iter().map(|pk| PublicKey::from_bytes(&pk.value).unwrap()).collect();
        self.slot_assignments = start.satellite_slot_assignments.iter().map(|(slot_id, pk)| {
            (*slot_id, PublicKey::from_bytes(&pk.value).unwrap())
        }).collect();

        self.f = start.f;

        self.clock_send = clock_send;

        println!("Sat started with f: {}", self.f);
    }

    pub fn handle_sending_station_message(&mut self, message: SendingStationMessage, signature: Signature) {
        println!("Sat received a SendingStationMessage: {:?} with signature: {:?}", message.txroot[0].payload, signature);
    }

    pub async fn handle_slot_tick(&mut self) {
        self.slot_id += 1;
        println!("Slot tick. Sat is at slot {}", self.slot_id);
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
use bls::min_pk::{PublicKey, SecretKey, Signature};
use bounce_core::{ResetId, SlotId};
use bounce_core::types::{SendingStationMessage, State};
use key_manager::keyloader;
use slot_clock::{SlotClock, SlotMessage};

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
