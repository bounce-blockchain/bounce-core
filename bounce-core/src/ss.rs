use std::collections::{BTreeMap, HashSet};
use std::env;
use std::sync::Arc;
use keccak_hash::keccak;
use communication::{ss_service_server::{SsService, SsServiceServer}, Response as GrpcResponse, MultiSignedCommitRecord};
use bounce_core::types::{Start, State, SendingStationMessage, MultiSigned, CommitRecord, SenderType};
use bounce_core::config::Config;
use bounce_core::{ResetId, SlotId};
use bls::min_pk::{PublicKey, SecretKey};
use key_manager::keyloader;
use tokio::runtime::{Runtime};
use tokio::sync::RwLock;
use tonic::{transport::Server, Request, Response, Status};
use bls::min_pk::proof_of_possession::*;
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
    receiver_from_mkt_handler: tokio::sync::mpsc::UnboundedReceiver<MultiSigned<[u8; 32]>>,

    secret_key: SecretKey,
    state: State,
    slot_id: SlotId,
    reset_id: ResetId,
    prev_cr: Option<MultiSigned<CommitRecord>>,
    // SlotIds to public keys of sending stations/satellties.
    ss_slot_assignments: BTreeMap<SlotId, HashSet<PublicKey>>,
    sat_slot_assignments: BTreeMap<SlotId, PublicKey>,
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
        start: Request<communication::Start>,
    ) -> Result<Response<GrpcResponse>, Status> {
        println!("SS received a Start message from MC");

        let (clock_send, clock_recv) = tokio::sync::mpsc::unbounded_channel();
        let (slot_send, mut slot_receive) = tokio::sync::broadcast::channel(9);
        let (sender_to_ss, receiver_from_mkt_handler) = tokio::sync::mpsc::unbounded_channel();

        let mut ss = self.ss.write().await;
        let start = start.into_inner();

        let deserialized_sigs = start.signatures.iter().map(|sig| Signature::from_bytes(&sig).unwrap()).collect::<Vec<Signature>>();

        let verified = ss.verify_mission_control_signature(&deserialized_sigs, &start.start_message);
        if !verified {
            return Err(Status::unauthenticated(format!("Failed to verify Mission Control signatures on Sending Station: {}", ss.my_ip)));
        }

        let deserialized_start_msg = bincode::deserialize(&start.start_message);
        if deserialized_start_msg.is_err() {
            return Err(Status::invalid_argument("Failed to serialize start message"));
        }
        let deserialized_start_msg: Start = deserialized_start_msg.unwrap();
        let t = deserialized_start_msg.t;
        ss.start(deserialized_start_msg, clock_send, receiver_from_mkt_handler);

        let ss_service = self.ss.clone();
        tokio::spawn(async move {
            loop {
                let slog_msg = slot_receive.recv().await;
                match slog_msg {
                    Ok(msg) => {
                        match msg {
                            SlotMessage::SlotTick => {
                                let mut ss = ss_service.write().await;
                                ss.handle_slot_tick();
                            }
                            SlotMessage::SlotThreshold1 => {}
                            SlotMessage::SlotThreshold2 => {
                                println!("SS reaches SlotThreshold2");
                                let mut ss = ss_service.write().await;
                                ss.send_ss_message().await;
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed to receive SlotMessage: {:?}", e);
                    }
                }
            }
        });

        let ss_mk_tree_handler = bounce_core::ss_mktree_handler::SsMerkleTreeHandler::new(ss.config.clone(), ss.my_ip.clone(), ss.secret_key.clone(), ss.ground_station_public_keys.clone(), ss.f, sender_to_ss);
        let ss_mk_tree_handler_lock = Arc::new(RwLock::new(ss_mk_tree_handler));
        bounce_core::ss_mktree_handler::run_grpc_server(ss_mk_tree_handler_lock.clone(), "0.0.0.0:37140".parse().unwrap());
        bounce_core::ss_mktree_handler::run_slot_listener(ss_mk_tree_handler_lock, slot_send.subscribe());

        let mut slot_timer = SlotClock::new(5000, 500, 4000, slot_send, clock_recv);
        tokio::spawn(async move { if (slot_timer.start().await).is_err() {} });

        ss.clock_send.send(t).unwrap();

        let reply = communication::Response {
            message: "SS processed the start message".to_string(),
        };

        Ok(Response::new(reply))
    }

    async fn handle_multi_signed_commit_record(&self, request: Request<MultiSignedCommitRecord>) -> Result<Response<GrpcResponse>, Status> {
        let request = request.into_inner();
        let mut ss = self.ss.write().await;
        let deserialized_multi_signed_cr = bincode::deserialize(&request.multi_signed_commit_record);
        if deserialized_multi_signed_cr.is_err() {
            return Err(Status::invalid_argument("Failed to deserialize MultiSignedCommitRecord"));
        }
        let verified = ss.handle_multi_signed_commit_record(deserialized_multi_signed_cr.unwrap());
        Ok(Response::new(GrpcResponse {
            message: format!("SS processed the MultiSignedCommitRecord: {}", verified),
        }))
    }
}

impl SS {
    pub fn new(config: Config, secret_key: SecretKey, mission_control_public_keys: Vec<PublicKey>, my_ip: String) -> Self {
        SS {
            config,
            secret_key,
            my_ip,
            clock_send: tokio::sync::mpsc::unbounded_channel().0,
            slot_receive: tokio::sync::broadcast::channel(1).1,
            receiver_from_mkt_handler: tokio::sync::mpsc::unbounded_channel().1,
            prev_cr: None,
            ground_station_public_keys: vec![],
            mission_control_public_keys,
            f: 0,
            mc_limit: 0.7,
            state: State::Inactive,
            slot_id: 0,
            reset_id: 0,
            gs_tx_receiver_ports: vec![3100],
            ss_slot_assignments: BTreeMap::new(),
            sat_slot_assignments: BTreeMap::new(),
        }
    }

    pub fn verify_signature(&self, signature: &Signature, msg: &[u8], sender: SenderType) -> bool {
        match sender {
            SenderType::GroundStation => {
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

    pub fn start(&mut self, start: Start, clock_send: tokio::sync::mpsc::UnboundedSender<u64>, receiver_from_mkt_handler: tokio::sync::mpsc::UnboundedReceiver<MultiSigned<[u8; 32]>>) {
        self.state = State::Ready;
        self.ground_station_public_keys = start.ground_station_public_keys;
        self.ss_slot_assignments = BTreeMap::new();
        for (slot_id, public_keys) in start.sending_station_slot_assignments.iter() {
            self.ss_slot_assignments.insert(*slot_id, HashSet::from_iter(public_keys.iter().cloned()));
        }
        self.sat_slot_assignments = start.satellite_slot_assignments;
        self.f = start.f;
        self.clock_send = clock_send;
        self.receiver_from_mkt_handler = receiver_from_mkt_handler;
        self.prev_cr = Some(start.genesis_record);

        println!("SS started with f: {}", self.f);
    }

    pub fn handle_slot_tick(&mut self) {
        self.slot_id += 1;
        println!("Slot tick. SS is at slot {}", self.slot_id);
    }

    pub fn handle_multi_signed_commit_record(&mut self, multi_signed_cr: MultiSigned<CommitRecord>) -> bool {
        let start = std::time::Instant::now();
        let pks_refs: Vec<&PublicKey> = self.ground_station_public_keys.iter().collect();
        if !multi_signed_cr.verify(&pks_refs).is_ok() {
            println!("Failed to verify CommitRecord signature");
            return false;
        }

        let cr = multi_signed_cr.payload.clone();
        if cr.reset_id != self.reset_id {
            println!("Received a CommitRecord with reset_id {} but expected reset_id {}", cr.reset_id, self.reset_id);
            return false;
        }
        if cr.slot_id != self.slot_id {
            println!("Received a CommitRecord with slot_id {} but expected slot_id {}", cr.slot_id, self.slot_id);
            return false;
        }
        if self.prev_cr.is_some() {
            let serialized_prev_cr = bincode::serialize(&self.prev_cr.as_ref().unwrap().payload);
            if serialized_prev_cr.is_err() {
                println!("Failed to serialize the previous commit record");
                return false;
            }
            if cr.prev != <[u8; 32]>::from(keccak(serialized_prev_cr.unwrap())) {
                println!("Received a CommitRecord with invalid prev hash");
                return false;
            }
        }
        //do additional checks here

        self.prev_cr = Some(multi_signed_cr);
        println!("Received a Multi-Signed CommitRecord with reset_id {}, slot_id {}, prev {:?}, commit_flag {}, used_as_reset {}", cr.reset_id, cr.slot_id, cr.prev, cr.commit_flag, cr.used_as_reset);
        let elapsed = start.elapsed();
        println!("SS processed a Multi-Signed CommitRecord in {:?}", elapsed);

        true
    }

    pub async fn send_ss_message(&mut self) {
        if self.prev_cr.is_none() {
            println!("SS does not have a previous commit record to prepare a message");
            return;
        }
        let start = std::time::Instant::now();
        let mut multi_signed_roots = Vec::new();
        loop {
            let multi_signed_root = self.receiver_from_mkt_handler.try_recv();
            if multi_signed_root.is_err() {
                break;
            }
            multi_signed_roots.push(multi_signed_root.unwrap());
        }
        let next_slot = self.slot_id + 1;
        let sending_station_message = SendingStationMessage {
            reset_id: self.reset_id,
            slot_id: next_slot,
            txroot: multi_signed_roots,
            prev_cr: self.prev_cr.clone().unwrap(),
        };

        let serialized_ss_msg = bincode::serialize(&sending_station_message).unwrap();
        let signature = self.secret_key.sign(&serialized_ss_msg);
        let elapsed = start.elapsed();
        println!("SS prepared a message for slot {} in {:?}", next_slot, elapsed);

        let sat_ip = self.config.sat[0].ip.clone();
        let sat = communication::sat_service_client::SatServiceClient::connect(format!("http://{}:37131", sat_ip)).await;
        if sat.is_err() {
            println!("Failed to connect to SAT");
            return;
        }
        let mut sat = sat.unwrap();
        let request = tonic::Request::new(communication::SendingStationMessage {
            sending_station_message: serialized_ss_msg,
            signature: Vec::from(signature.to_bytes()),
        });
        let response = sat.handle_sending_station_message(request).await;
        if response.is_err() {
            println!("Failed to send message to SAT: {:?}", response.err().unwrap());
            return;
        }
        let response = response.unwrap();
        println!("Response from SAT: {:?}", response.into_inner().message);
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
