use serde::Deserialize;
use std::fs;

#[derive(Debug, Deserialize, Default, Clone)]
pub struct Config {
    pub mc: Component,
    pub ss: Vec<Component>,
    pub gs: Vec<Component>,
    pub sat: Vec<Component>,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct Component {
    pub ip: String,
}

impl Config {
    pub fn load_from_file(file_path: &str) -> Self {
        let config_content = fs::read_to_string(file_path).expect("Failed to read config file");
        toml::from_str(&config_content).expect("Failed to parse config file")
    }
}
