use std::fmt::format;
use std::fs::File;
use std::io::{Read, Result};
use std::path::Path;
use bls::min_pk::{SecretKey, PublicKey};

pub fn read_private_key(component_id: &str) -> SecretKey {
    // Construct the file path for the private key
    let private_key_path = format!("keys/min_pk/{}.secret.key", component_id);

    // Load the private key from the file
    let private_key = load_bls_secret_key(&private_key_path);

    private_key
}

pub fn read_mc_public_keys(num_mc_keys:u32) -> Vec<PublicKey> {
    // Load the configuration to get the number of MC keys
    let mut public_keys = Vec::new();

    // Read MC public keys based on the number defined in the config
    for mc_id in 1..=num_mc_keys {
        let public_key_path = format!("keys/min_pk/mc{:02}.public.key", mc_id);
        if Path::new(&public_key_path).exists() {
            let public_key = load_bls_public_key(&public_key_path);
            public_keys.push(public_key);
        }
    }

    public_keys
}


pub fn load_bls_public_key(filename: &str) -> PublicKey {
    // Read the contents of the key file
    let mut file = File::open(filename).expect(format!("Failed to open file: {}", filename).as_str());
    let mut key_bytes = Vec::new();
    file.read_to_end(&mut key_bytes).expect(format!("Failed to read file: {}", filename).as_str());

    // Parse the key as a BLS public key
    let public_key = PublicKey::from_bytes(&key_bytes).expect("Failed to parse BLS public key");
    log::debug!("Successfully loaded BLS public key from file: {}", filename);

    public_key
}

pub fn load_bls_secret_key(filename: &str) -> SecretKey {
    // Read the contents of the key file
    let mut file = File::open(filename).expect(format!("Failed to open file: {}", filename).as_str());
    let mut key_bytes = Vec::new();
    file.read_to_end(&mut key_bytes).expect(format!("Failed to read file: {}", filename).as_str());

    // Parse the key as a BLS secret key
    let secret_key = SecretKey::from_bytes(&key_bytes).expect("Failed to parse BLS secret key");

    secret_key
}
