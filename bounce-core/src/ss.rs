use std::collections::{BTreeMap, HashSet};
use std::env;
use std::sync::Arc;
use communication::{ss_service_server::{SsService, SsServiceServer}, Start, Response as GrpcResponse};
use bounce_core::types::{Transaction, State, Keccak256};
use bounce_core::config::Config;
use bounce_core::{ResetId, SlotId};
use bls::min_pk::{PublicKey, SecretKey};
use key_manager::keyloader;
use rayon::prelude::*;
use tokio::runtime::{Runtime};
use tokio::sync::RwLock;
use tonic::{transport::Server, Request, Response, Status};
use bounce_core::ss_mktree_handler::SsMerkleTreeHandler;
use slot_clock::{SlotClock, SlotMessage};

pub mod communication {
    tonic::include_proto!("communication");
}

pub struct SS {
    config: Config,
    gs_tx_receiver_ports: Vec<u16>,
    my_ip: String,

    clock_send: tokio::sync::mpsc::UnboundedSender<u64>,
    slot_receive: tokio::sync::broadcast::Receiver<SlotMessage>,
    receiver_from_mkt_handler: tokio::sync::mpsc::UnboundedReceiver<[u8; 32]>,

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

        let (clock_send, clock_recv) = tokio::sync::mpsc::unbounded_channel();
        let (slot_send, mut slot_receive) = tokio::sync::broadcast::channel(9);
        let (sender_to_ss, receiver_from_mkt_handler) = tokio::sync::mpsc::unbounded_channel();

        let mut ss = self.ss.write().await;
        let start = start.into_inner();
        ss.start(start.clone(),clock_send, receiver_from_mkt_handler);

        let ss_service = self.ss.clone();
        tokio::spawn(async move {
            loop {
                let slog_msg = slot_receive.recv().await;
                match slog_msg {
                    Ok(msg) => {
                        println!("Received SlotMessage: {:?}", msg);
                        match msg {
                            SlotMessage::SlotTick => {
                                let mut ss = ss_service.write().await;
                                ss.handle_slot_tick();
                            }
                            SlotMessage::SlotThreshold1 => {}
                            SlotMessage::SlotThreshold2 => {
                                let mut ss = ss_service.write().await;
                                ss.send_ss_message();
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed to receive SlotMessage: {:?}", e);
                    }
                }
            }
        });

        let mut ss_mk_tree_handler = SsMerkleTreeHandler::spawn(ss.config.clone(), ss.my_ip.clone(), ss.secret_key.clone(), ss.ground_station_public_keys.clone(), ss.f, sender_to_ss);
        let mut mk_tree_handler_slot_receive = slot_send.subscribe();
        tokio::spawn(async move {
            loop {
                let slog_msg = mk_tree_handler_slot_receive.recv().await;
                match slog_msg {
                    Ok(msg) => {
                        println!("Received SlotMessage: {:?}", msg);
                        if msg == SlotMessage::SlotThreshold1 {
                            // Send the sign_merkle_tree_request
                            ss_mk_tree_handler.send_sign_merkle_tree_request().await.unwrap();
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

        ss.clock_send.send(start.t).unwrap();

        let reply = communication::Response {
            message: "SS processed the start message".to_string(),
        };

        Ok(Response::new(reply))
    }
}

impl SS {
    pub fn new(config: Config, secret_key: SecretKey, mission_control_public_keys: Vec<PublicKey>, my_ip:String) -> Self {
        SS {
            config,
            secret_key,
            my_ip,
            clock_send: tokio::sync::mpsc::unbounded_channel().0,
            slot_receive: tokio::sync::broadcast::channel(1).1,
            receiver_from_mkt_handler: tokio::sync::mpsc::unbounded_channel().1,
            ground_station_public_keys: vec![],
            mission_control_public_keys,
            f: 0,
            mc_limit: 0.7,
            state: State::Inactive,
            slot_id: 0,
            reset_id: 0,
            gs_tx_receiver_ports: vec![3100],
            slot_assignments: BTreeMap::new(),
        }
    }

    pub fn start(&mut self, start: Start, clock_send: tokio::sync::mpsc::UnboundedSender<u64>, receiver_from_mkt_handler: tokio::sync::mpsc::UnboundedReceiver<[u8;32]>) {
        self.state = State::Ready;
        self.ground_station_public_keys = start.ground_station_public_keys.iter().map(|pk| PublicKey::from_bytes(&pk.value).unwrap()).collect();
        self.slot_assignments = BTreeMap::new();
        for (slot_id, public_keys) in start.sending_station_slot_assignments.iter() {
            self.slot_assignments.insert(*slot_id, HashSet::from_iter(public_keys.public_keys.iter().map(|pk| PublicKey::from_bytes(&pk.value).unwrap())));
        }
        self.f = start.f;
        self.clock_send = clock_send;
        self.receiver_from_mkt_handler = receiver_from_mkt_handler;

        println!("SS started with f: {}", self.f);
    }

    pub fn handle_slot_tick(&mut self) {
        self.slot_id += 1;
    }

    pub fn send_ss_message(&mut self) {
        let root = self.receiver_from_mkt_handler.try_recv();
        if root.is_ok() {
            let root = root.unwrap();
            println!("SS is sending a msg to satellite with root {:?}", root);
        } else {
            println!("SS does not have a root to send");
        }
    }
}

pub async fn run_ss(config_file: &str, index: usize) -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::load_from_file(config_file);
    let addr = "0.0.0.0:37130".to_string().parse()?;

    let secret_key = keyloader::read_private_key(format!("ss{:02}", index).as_str());
    let mission_control_public_keys = keyloader::read_mc_public_keys(config.mc.num_keys);
    let my_ip = config.ss[index].ip.clone();
    let ss = SS::new(config, secret_key, mission_control_public_keys, my_ip);

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
    let rt = Runtime::new().unwrap();

    let args: Vec<String> = env::args().collect();
    let config_file = &args[1];
    let index = args[2].parse::<usize>().expect("Index should be a valid number");

    rt.block_on(run_ss(config_file, index)).unwrap();
}
