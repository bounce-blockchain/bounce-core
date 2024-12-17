# Bounce
Implementation for the book [High Performance, Low Energy, and Trustworthy Blockchains Using Satellites](https://www.nowpublishers.com/article/Details/NET-070).

Legacy [repo](https://github.com/bounce-blockchain/bounce-rs) implemented using libp2p.
## Installation
```bash
git clone https://github.com/lapisliu/bounce-core.git
cd bounce-core
cargo build --release
```

## Usage
Change the ip address and the number of nodes in the `config.toml` file.
The following commands will run locally with one node each for the Mission Control, the Sending Station, the Ground Station, and the Satellite.
If you have multiple nodes for each type, you need to change the last parameter of the following commands to the node id starting from 0.
```bash
cargo run --release --bin ss -- config-local.toml 0
```
```bash
cargo run --release --bin gs -- config-local.toml 0
```
```bash
cargo run --release --bin sat -- config-local.toml 0
```
Make sure all the above components are running. Then run the following command to start the Mission Control.
```bash
cargo run --release --bin mc -- config-local.toml
```