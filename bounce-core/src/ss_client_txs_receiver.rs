// This source code can be freely used for research purposes.
// For any other purpose, please contact the authors.

use tokio::sync::mpsc::UnboundedSender;
use crate::types::Transaction;

pub struct SsClientTxsReceiver {
    pub client_txs_sender: UnboundedSender<Vec<Transaction>>, //send to the ss_mktree_handler to be processed
    pub txs: Vec<Transaction>,
}

impl SsClientTxsReceiver {
    pub fn new(client_txs_sender: UnboundedSender<Vec<Transaction>>) -> Self {
        SsClientTxsReceiver {
            client_txs_sender,
            txs: Vec::new(),
        }
    }

    pub fn send_txs(&mut self) {
        if !self.txs.is_empty() {
            let txs = std::mem::take(&mut self.txs);
            self.client_txs_sender.send(txs).unwrap();
        }
    }
}

pub fn run_ss_client_txs_receiver(mut ss_client_txs_receiver: SsClientTxsReceiver) {
    //send the transactions to the ss_mktree_handler every second if there are any
    tokio::spawn(async move {
        loop {
            ss_client_txs_receiver.send_txs();
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }
    });
}