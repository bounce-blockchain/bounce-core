use serde::Deserialize;
use std::fs;

#[derive(Debug, Deserialize, Default, Clone)]
pub struct Config {
    pub mc: MCComponent,
    pub ss: Vec<Component>,
    pub gs: Vec<Component>,
    pub sat: Vec<Component>,
    pub fanout: Fanout,
}
#[derive(Debug, Deserialize, Default, Clone)]
pub struct MCComponent {
    pub ip: String,
    pub num_keys: u32,
    pub num_ss: u32,
    pub num_gs: u32,
    pub num_sat: u32,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct Component {
    pub ip: String,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct Fanout {
    pub fanout: usize,
}

impl Config {
    pub fn load_from_file(file_path: &str) -> Self {
        let config_content = fs::read_to_string(file_path).expect("Failed to read config file");
        toml::from_str(&config_content).expect("Failed to parse config file")
    }
}
