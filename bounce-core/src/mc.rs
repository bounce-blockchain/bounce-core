use std::collections::{BTreeMap};
use tonic::{transport::Server, Request, Response, Status};
use communication::{mc_service_server::{McService, McServiceServer}, Message, Response as GrpcResponse};
use crate::config::Config;
use rand::seq::SliceRandom;
use tokio::runtime::Runtime;
use std::env;
use keccak_hash::{keccak};
use bls::min_pk::{PublicKey, SecretKey};
use bls::min_pk::proof_of_possession::SecretKeyPop;
use bounce_core::{ResetId, SlotId};
use bounce_core::types::{CommitRecord, Start, State};
use key_manager::keyloader;

pub mod config;

pub mod communication {
    tonic::include_proto!("communication");
}

pub struct MC {
    secret_keys: Vec<SecretKey>,
    state: State,
    reset_id: ResetId,
    f: u32,
    //status_responses: Vec<StatusResponse>,
    last_pos_cr_map: BTreeMap<ResetId, CommitRecord>,
    first_neg_cr_map: BTreeMap<ResetId, CommitRecord>,
    //prev_reset_msg: Option<Reset>,
    //received_confirm_reset_from_satellites : HashSet<PublicKey>,
    //signed_confirm_resets: Vec<SignedConfirmReset>,

    satellite_public_keys: Vec<PublicKey>,
    ground_station_public_keys: Vec<PublicKey>,
    sending_public_keys: Vec<PublicKey>,

    sending_station_slot_assignments: BTreeMap<SlotId, Vec<PublicKey>>,
    satellite_slot_assignments: BTreeMap<SlotId, PublicKey>,
}

impl MC {
    pub fn new(
        secret_keys: Vec<SecretKey>,
        sending_public_keys: Vec<PublicKey>,
        ground_station_public_keys: Vec<PublicKey>,
        satellite_public_keys: Vec<PublicKey>,
    ) -> Self {

        MC {
            secret_keys,
            state: State::Inactive,
            reset_id: 0,
            f: ground_station_public_keys.len() as u32 - 1,
            //status_responses: Vec::new(),
            last_pos_cr_map: BTreeMap::new(),
            first_neg_cr_map: BTreeMap::new(),
            // prev_reset_msg: None,
            // received_confirm_reset_from_satellites: HashSet::new(),
            // signed_confirm_resets: Vec::new(),
            satellite_public_keys,
            ground_station_public_keys,
            sending_public_keys,

            sending_station_slot_assignments: BTreeMap::new(),
            satellite_slot_assignments: BTreeMap::new(),
        }
    }
    pub async fn send_start_message(&self, config: &Config, sending_station_slot_assignments:BTreeMap<SlotId,Vec<PublicKey>>, satellite_slot_assignments:BTreeMap<SlotId,PublicKey>) -> Result<(), Box<dyn std::error::Error>> {
        let t = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
            + 10000) as u64;

        let hash = keccak("genesis-record".as_bytes()).to_fixed_bytes();

        let genesis_record = CommitRecord{
            reset_id: 0,
            slot_id: 0,
            txroot: vec![hash],
            prev: [0u8;32],
            commit_flag: true,
            used_as_reset: false,
        };

        let start = Start {
            satellite_slot_assignments,
            sending_station_slot_assignments,
            ground_station_public_keys: self.ground_station_public_keys.clone(),
            sending_station_public_keys: self.sending_public_keys.clone(),
            satellite_public_keys: self.satellite_public_keys.clone(),
            t,
            f: 0,
            genesis_record,
        };
        let serialized_start = bincode::serialize(&start).unwrap();
        let signatures:Vec<Vec<u8>> = self.secret_keys.iter().map(|sk| {
            sk.sign(&serialized_start).to_bytes().to_vec()
        }).collect();
        println!("Sending start message to all instances");
        for gs in &config.gs {
            let mut client = communication::gs_service_client::GsServiceClient::connect(format!("http://{}:37129", gs.ip)).await?;
            let request = tonic::Request::new(communication::Start{
                start_message: serialized_start.clone(),
                signatures: signatures.clone(),
            });
            let response = client.handle_start(request).await?;
            println!("Response from GS: {:?}", response.into_inner().message);
        }
        for ss in &config.ss {
            let mut client = communication::ss_service_client::SsServiceClient::connect(format!("http://{}:37130", ss.ip)).await?;
            let request = tonic::Request::new(communication::Start{
                start_message: serialized_start.clone(),
                signatures: signatures.clone(),
            });
            let response = client.handle_start(request).await?;
            println!("Response from SS: {:?}", response.into_inner().message);
        }
        for sat in &config.sat {
            let mut client = communication::sat_service_client::SatServiceClient::connect(format!("http://{}:37131", sat.ip)).await?;
            let request = tonic::Request::new(communication::Start{
                start_message: serialized_start.clone(),
                signatures: signatures.clone(),
            });
            let response = client.handle_start(request).await?;
            println!("Response from Sat: {:?}", response.into_inner().message);
        }

        Ok(())
    }
}

#[tonic::async_trait]
impl McService for MC {
    async fn handle_message(
        &self,
        request: Request<Message>,
    ) -> Result<Response<GrpcResponse>, Status> {
        println!("MC received a message from {}: {:?}", request.get_ref().sender, request.get_ref().content);

        let reply = communication::Response {
            message: format!("MC processed the message: {}", request.get_ref().content),
        };

        Ok(Response::new(reply))
    }
}

pub async fn run_mc(config_file: &str) -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::load_from_file(config_file);
    let addr = "0.0.0.0:37128".to_string().parse()?;

    let mut secret_keys = Vec::new();
    for i in 0..config.mc.num_keys {
        let secret_key = keyloader::read_private_key(format!("mc{:02}", i).as_str());
        secret_keys.push(secret_key);
    }

    let mut sending_station_public_keys = Vec::new();
    for i in 0..config.mc.num_ss {
        let public_key = keyloader::read_public_key(format!("ss{:02}", i).as_str());
        sending_station_public_keys.push(public_key);
    }

    let mut satellite_public_keys = Vec::new();
    for i in 0..config.mc.num_sat {
        let public_key = keyloader::read_public_key(format!("sat{:02}", i).as_str());
        satellite_public_keys.push(public_key);
    }

    let mut ground_station_public_keys = Vec::new();
    for i in 0..config.mc.num_gs {
        let public_key = keyloader::read_public_key(format!("gs{:02}", i).as_str());
        println!("GS public key: {:?}", public_key);
        ground_station_public_keys.push(public_key);
    }

    let sending_station_slot_assignments = generate_sending_station_slot_assignments(&sending_station_public_keys, 0);
    let satellite_slot_assignments = generate_satellite_slot_assignments(&satellite_public_keys, 0);

    let mc = MC::new(secret_keys, sending_station_public_keys, ground_station_public_keys, satellite_public_keys);


    mc.send_start_message(&config, sending_station_slot_assignments, satellite_slot_assignments).await.unwrap();

    println!("MC is listening on {}", addr);

    Server::builder()
        .add_service(McServiceServer::new(mc))
        .serve(addr)
        .await?;

    Ok(())
}

pub fn generate_sending_station_slot_assignments(sending_station_pks:&[PublicKey], starting_slot:u64) -> BTreeMap<SlotId, Vec<PublicKey>> {
    let mut slot_assignments = BTreeMap::new();

    // let's first run for 100 slots
    // All sending stations are assigned to it.
    for slot in starting_slot..(starting_slot+100) {
        slot_assignments
            .entry(slot)
            .or_insert_with(Vec::new)
            .extend(sending_station_pks);
    }

    slot_assignments
}

pub fn generate_satellite_slot_assignments(satellite_pks:&[PublicKey], starting_slot:u64) -> BTreeMap<SlotId, PublicKey> {
    let mut slot_assignments = BTreeMap::new();

    // let's first run for 100 slots
    // For each slot, we make sure that only one satellite is assigned to it.
    for slot in starting_slot..(starting_slot+100) {
        let satellite = satellite_pks.choose(&mut rand::thread_rng()).unwrap();
        slot_assignments.insert(slot, *satellite);
    }

    slot_assignments
}


fn main() {
    let rt = Runtime::new().unwrap();
    let args: Vec<String> = env::args().collect();
    let config_file = &args[1];

    rt.block_on(async {
        let mc_runtime = run_mc(config_file);
        mc_runtime.await.unwrap();
    });
}