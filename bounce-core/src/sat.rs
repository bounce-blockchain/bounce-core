use std::collections::BTreeMap;
use std::env;
use std::sync::Arc;

use keccak_hash::keccak;
use tokio::runtime::Runtime;
use tokio::sync::RwLock;
use tonic::{Request, Response, Status, transport::Server};

use bls::min_pk::{PublicKey, SecretKey, Signature};
use bls::min_pk::proof_of_possession::{SecretKeyPop, SignaturePop};
use bounce_core::{ResetId, SlotId};
use bounce_core::config::Config;
use bounce_core::types::{CommitRecord, SenderType, SendingStationMerkleTreeGroup, SendingStationMessage, SignedCommitRecord, Start, State};
use communication::{Response as GrpcResponse, sat_service_server::{SatService, SatServiceServer}};
use key_manager::keyloader;
use slot_clock::{SlotClock, SlotMessage};

pub mod communication {
    tonic::include_proto!("communication");
}

pub struct Sat {
    config: Config,
    secret_key: SecretKey,

    clock_send: tokio::sync::mpsc::UnboundedSender<u64>,

    state: State,
    sending_station_messages: Vec<(SendingStationMessage, Signature)>,
    dummy_sending_station_message: Option<(SendingStationMessage, Signature)>,
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
        start: Request<communication::Start>,
    ) -> Result<Response<GrpcResponse>, Status> {
        println!("Sat received a Start message from MC");
        let mut sat = self.sat.write().await;

        let (clock_send, clock_recv) = tokio::sync::mpsc::unbounded_channel();
        let (slot_send, mut slot_receive) = tokio::sync::broadcast::channel(9);

        let start = start.into_inner();
        let deserialized_sigs = start.signatures.iter().map(|sig| Signature::from_bytes(sig).unwrap()).collect::<Vec<Signature>>();

        let verified = sat.verify_mission_control_signature(&deserialized_sigs, &start.start_message);
        if !verified {
            return Err(Status::unauthenticated(format!("Failed to verify Mission Control signatures on Satellite with pk: {:?}", sat.secret_key.sk_to_pk())));
        }

        let deserialized_start_msg = bincode::deserialize(&start.start_message);
        if deserialized_start_msg.is_err() {
            return Err(Status::invalid_argument("Failed to serialize start message"));
        }
        let deserialized_start_msg: bounce_core::types::Start = deserialized_start_msg.unwrap();

        let t = deserialized_start_msg.t;
        sat.start(deserialized_start_msg, clock_send);

        let sat_service = self.sat.clone();
        tokio::spawn(async move {
            loop {
                let slog_msg = slot_receive.recv().await;
                match slog_msg {
                    Ok(msg) => {
                        if msg == SlotMessage::SlotTick {
                            let mut sat = sat_service.write().await;
                            sat.handle_slot_tick().await;
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed to receive SlotMessage: {:?}", e);
                    }
                }
            }
        });

        let mut slot_timer = SlotClock::new(10000, 500, 9000, slot_send, clock_recv);
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
        println!("Sat received a SendingStationMessage");
        let request = request.into_inner();
        let deserialized_ss_msg = bincode::deserialize(&request.sending_station_message);
        if deserialized_ss_msg.is_err() {
            return Err(Status::invalid_argument("Failed to deserialize SendingStationMessage"));
        }
        let sending_station_message: SendingStationMessage = deserialized_ss_msg.unwrap();
        let deserialized_sig = Signature::from_bytes(&request.signature);
        if deserialized_sig.is_err() {
            return Err(Status::invalid_argument("Failed to deserialize Signature"));
        }
        let signature: Signature = deserialized_sig.unwrap();

        let mut sat = self.sat.write().await;
        if !sat.verify_signature(&signature, &request.sending_station_message, SenderType::SendingStation) {
            return Err(Status::unauthenticated("Failed to verify the signature of the SendingStationMessage"));
        }
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
            sending_station_messages: Vec::new(),
            dummy_sending_station_message: None,
            // last_positive_opt: None,
            // first_negative_opt: None,
            state: State::Inactive,
            // reset_received: None,
        }
    }

    pub fn verify_signature(&self, signature: &Signature, msg: &[u8], sender: SenderType) -> bool {
        match sender {
            SenderType::GroundStation => {
                self.ground_station_public_keys.iter().any(|pk| signature.verify(pk, msg))
            }
            SenderType::SendingStation => {
                self.sending_station_public_keys.iter().any(|pk| signature.verify(pk, msg))
            }
            _ => false,
        }
    }

    pub fn verify_mission_control_signature(&self, signatures: &[Signature], msg: &[u8]) -> bool {
        if self.mission_control_public_keys.is_empty() || signatures.len() as f32 / (self.mission_control_public_keys.len() as f32) < self.mc_limit {
            return false;
        }
        let mut verified = 0;
        for sig in signatures.iter() {
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

    pub fn start(&mut self, start: Start, clock_send: tokio::sync::mpsc::UnboundedSender<u64>) {
        self.state = State::Ready;
        self.ground_station_public_keys = start.ground_station_public_keys;
        self.sending_station_public_keys = start.sending_station_public_keys;
        self.slot_assignments = start.satellite_slot_assignments;
        self.f = start.f;
        self.clock_send = clock_send;

        println!("Sat started with f: {}", self.f);
    }

    pub fn handle_sending_station_message(&mut self, mut message: SendingStationMessage, signature: Signature) {
        let start = std::time::Instant::now();
        if !self.verify_sending_station_message(&message) {
            println!("Failed to verify the SendingStationMessage");
            return;
        }
        println!("Verified the SendingStationMessage");
        let mkt_start = std::time::Instant::now();
        let mut verified_roots = Vec::new();
        let gs_pk_refs: Vec<&PublicKey> = self.ground_station_public_keys.iter().collect();
        for root in &message.txroot {
            if root.signers_bitvec.count_ones() as u32 >= self.f + 1 && root.verify(&gs_pk_refs).is_ok() {
                verified_roots.push(root.clone());
            } else {
                println!("Failed to verify txroot: {:?}", root);
                println!("# signers: {}", root.signers_bitvec.count_ones());
            }
        }
        let elapsed_mkt = mkt_start.elapsed();
        println!("Elapsed time to verify {} txroots: {:?}", &message.txroot.len(), elapsed_mkt);
        message.txroot = verified_roots;
        if message.txroot.is_empty() {
            println!("No valid txroots found in the SendingStationMessage. Treating it as a dummy message");
            self.dummy_sending_station_message = Some((message, signature));
        } else {
            self.sending_station_messages.push((message, signature));
        }

        println!("Saved a SendingStationMessage");
        let elapsed = start.elapsed();
        println!("Elapsed time to verify and save the SendingStationMessage: {:?}", elapsed);
    }

    fn verify_sending_station_message(&self, message: &SendingStationMessage) -> bool {
        if message.slot_id != self.slot_id + 1 {
            println!("Slot ID mismatch. Expected: {}, Received: {}", self.slot_id, message.slot_id);
            return false;
        }
        if message.reset_id != self.reset_id {
            println!("Reset ID mismatch. Expected: {}, Received: {}", self.reset_id, message.reset_id);
            return false;
        }
        let multi_signed_prev_commit = &message.prev_cr;
        let gs_pk_refs: Vec<&PublicKey> = self.ground_station_public_keys.iter().collect();
        if !(multi_signed_prev_commit.signers_bitvec.count_ones() as u32 >= self.f + 1 && multi_signed_prev_commit.verify(&gs_pk_refs).is_ok()) {
            println!("Signatures on the previous commit record. Required: at least {}, Received: {}", self.f + 1, multi_signed_prev_commit.signers_bitvec.count_ones());
            println!("Signature verification failed");
            println!("trying to verify mission control signatures");
            let mc_pk_refs: Vec<&PublicKey> = self.mission_control_public_keys.iter().collect();
            if multi_signed_prev_commit.verify(&mc_pk_refs).is_err() {
                println!("Failed to verify the previous commit record");
                return false;
            }
            println!("Verified the previous commit record with Mission Control signatures");
        }
        let prev_cr = &multi_signed_prev_commit.payload;
        if !prev_cr.commit_flag {
            println!("The previous commit record is not a commit record");
            return false;
        }
        if !prev_cr.used_as_reset && prev_cr.slot_id != self.slot_id {
            println!("Slot ID mismatch. Expected: {}, Received: {}", self.slot_id, prev_cr.slot_id);
            return false;
        }
        if !prev_cr.used_as_reset && prev_cr.reset_id != self.reset_id {
            println!("Reset ID mismatch. Expected: {}, Received: {}", self.reset_id, prev_cr.reset_id);
            return false;
        }

        true
    }

    pub async fn handle_slot_tick(&mut self) {
        self.slot_id += 1;
        println!("Slot tick. Sat is at slot {}", self.slot_id);
        let start = std::time::Instant::now();
        let mut cr = CommitRecord {
            reset_id: self.reset_id,
            slot_id: self.slot_id,
            txroots: Vec::new(),
            prev: [0u8; 32],
            commit_flag: false,
            used_as_reset: false,
        };
        if self.sending_station_messages.is_empty() {
            if let Some(dummy_msg) = std::mem::take(&mut self.dummy_sending_station_message) {
                let serialized_prev_cr = bincode::serialize(&dummy_msg.0.prev_cr.payload);
                if serialized_prev_cr.is_err() {
                    println!("Failed to serialize the previous commit record");
                    return;
                }
                cr.prev = <[u8; 32]>::from(keccak(serialized_prev_cr.unwrap()));
                cr.commit_flag = true;
            }
        } else {
            let serialized_prev_cr = bincode::serialize(&self.sending_station_messages.last().unwrap().0.prev_cr.payload);
            if serialized_prev_cr.is_err() {
                println!("Failed to serialize the previous commit record");
                return;
            }
            cr.prev = <[u8; 32]>::from(keccak(serialized_prev_cr.unwrap()));
            cr.commit_flag = true;
            let mut txroots = Vec::new();
            for msg in std::mem::take(&mut self.sending_station_messages) {
                txroots.push(SendingStationMerkleTreeGroup {
                    txroots: msg.0.txroot,
                    ss_signature: msg.1,
                });
            }
            cr.txroots = txroots;
        }

        let signature = self.secret_key.sign(&bincode::serialize(&cr).unwrap());
        let signed_cr = SignedCommitRecord {
            commit_record: cr,
            signature,
        };
        let elapsed = start.elapsed();
        println!("Elapsed time to create and sign the commit record: {:?}", elapsed);

        println!("Sending commit record to GS");
        let gs_ip = self.config.gs[0].ip.clone();
        let serialized_cr = bincode::serialize(&signed_cr).unwrap();
        let client = communication::gs_service_client::GsServiceClient::connect(format!("http://{}:37129", gs_ip)).await;
        if client.is_err() {
            println!("Failed to connect to GS");
            return;
        }
        let mut client = client.unwrap();
        let request = tonic::Request::new(communication::SignedCommitRecord {
            signed_commit_record: serialized_cr,
        });
        let response = client.handle_commit_record(request).await;
        if response.is_err() {
            println!("Failed to send message to GS");
            return;
        }
        let response = response.unwrap();
        println!("Response from GS: {:?}", response.into_inner().message);
    }
}

pub async fn run_sat(config_file: &str, index: usize) -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::load_from_file(config_file);
    let sat_ip = &config.sat[index].ip;
    let addr = "0.0.0.0:37131".to_string().parse()?;

    let secret_key = keyloader::read_private_key(format!("sat{:02}", index).as_str());
    let mission_control_public_keys = keyloader::read_mc_public_keys(config.mc.num_keys);

    let sat = Sat::new(config, secret_key, mission_control_public_keys);

    println!("Sat is listening on {}", addr);

    Server::builder()
        .add_service(SatServiceServer::new(SatLockService {
            sat: Arc::new(RwLock::new(sat)),
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

    // Start the Sat component
    rt.block_on(run_sat(config_file, index)).unwrap();
}
