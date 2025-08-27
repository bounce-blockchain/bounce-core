# Bounce
Official implementation of **[Bounce: A High Performance Satellite-Based Blockchain System](https://doi.org/10.3390/network5020009)**

## Authors
**Xiaoteng (Frank) Liu** · **Taegyun Kim** · **Dennis E. Shasha**

> If you use this code, please cite the paper (see **BibTeX** below).
> This code is available only for research purposes. For any other purposes, please contact the authors.

---

## Abstract
Blockchains are designed to produce a secure, append-only sequence of transactions. Establishing transaction sequentiality is typically achieved by consensus protocols that either prevent forks entirely (no-forking-ever) or make forks short-lived. The main challenges are achieving this no-forking condition while also delivering high throughput, low response time, and low energy costs.

This paper presents the Bounce blockchain protocol along with throughput and response-time experiments. The core of Bounce is a set of satellites that partition time slots. The satellite for slot i signs a commit record that includes the hash of the commit record of slot i−1 as well as a sequence of zero or more Merkle-tree roots, where each corresponding Merkle tree contains thousands or millions of transactions. The ledger consists of the transactions in the sequence of Merkle trees corresponding to the roots of the sequence of commit records. Thus, the satellites act as arbiters that decide the next block(s) for the blockchain. Satellites orbiting Earth are harder to tamper with and harder to isolate than terrestrial data centers, though our protocol could also operate with terrestrial data centers.

Under reasonable assumptions—intermittently failing but non-Byzantine (i.e., non-traitorous) satellites, possibly Byzantine ground stations, and “exposure-averse” administrators—the Bounce system achieves high availability and a no-fork-ever blockchain. Our experiments show high transactional throughput (5.2 million transactions per two-second slot), low response time (less than three seconds for “premium” transactions and less than ten seconds for “economy” transactions), and minimal energy consumption (under 0.05 joules per transaction). Moreover, given five additional cloud sites of the kinds currently available in CloudLab (Clemson), the design could achieve throughputs of 15.2 million transactions per two-second slot with the same response-time profile.

## Installation
```bash
git clone https://github.com/lapisliu/bounce-core.git
cd bounce-core
cargo build --release
```

## Usage
Change the IP addresses and the number of nodes in `config-local.toml`. `config.toml` contains an example experiment setup with 10 ground stations.

The following commands run locally with **one node each** for the Mission Control (`mc`), Sending Station (`ss`), Ground Station (`gs`), and Satellite (`sat`).
If you have multiple nodes of a type, change the last parameter to the **node id** starting from `0`.

Run each of these in a separate terminal:
```bash
# Sending Station
cargo run --release --bin ss -- config-local.toml 0
```
```bash
# Ground Station
cargo run --release --bin gs -- config-local.toml 0
```
```bash
# Satellite
cargo run --release --bin sat -- config-local.toml 0
```
When all components above are running, start Mission Control:
```bash
cargo run --release --bin mc -- config-local.toml
```

## BibTeX
```bibtex
@Article{network5020009,
  AUTHOR = {Liu, Xiaoteng and Kim, Taegyun and Shasha, Dennis E.},
  TITLE = {Bounce: A High Performance Satellite-Based Blockchain System},
  JOURNAL = {Network},
  VOLUME = {5},
  YEAR = {2025},
  NUMBER = {2},
  ARTICLE-NUMBER = {9},
  URL = {https://www.mdpi.com/2673-8732/5/2/9},
  ISSN = {2673-8732},
  DOI = {10.3390/network5020009}
}
```

## Legacy Repo
The `bls` implemention is adapted from our legacy repo [bounce-rs](https://github.com/bounce-blockchain/bounce-rs), where [libp2p](https://libp2p.io/) was used as the communication protocol.
