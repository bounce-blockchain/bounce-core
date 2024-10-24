use std::error::Error;
use tokio::{select, sync::mpsc, time};

/// The SlotClock keeps notifies the protocol when a new slot starts
/// Also, there are two slot thresholds
/// 1. The first threshold is when the Sending Station sends Merkle Tree to Ground Station
/// for signing
/// 2. The second threshold is when the Sending Station sends Sending Station Message to the
/// Satellite.

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SlotMessage {
    SlotTick,
    SlotThreshold1,
    SlotThreshold2,
}

#[derive(Debug)]
pub struct SlotClock {
    t1_offset_ms: u64,
    t2_offset_ms: u64,
    protocol_send: tokio::sync::broadcast::Sender<SlotMessage>,
    clock_recv: mpsc::UnboundedReceiver<u64>,
    slot_interval: time::Interval,
    t1_interval: time::Interval,
    t2_interval: time::Interval,
    started: bool,
}

impl SlotClock {
    pub fn new(
        slot_duration_ms: u64,
        t1_offset_ms: u64,
        t2_offset_ms: u64,
        protocol_send: tokio::sync::broadcast::Sender<SlotMessage>,
        clock_recv: mpsc::UnboundedReceiver<u64>,
    ) -> Self {
        SlotClock {
            t1_offset_ms,
            t2_offset_ms,
            protocol_send,
            clock_recv,
            slot_interval: time::interval(time::Duration::from_millis(slot_duration_ms)),
            t1_interval: time::interval(time::Duration::from_millis(slot_duration_ms)),
            t2_interval: time::interval(time::Duration::from_millis(slot_duration_ms)),
            started: false,
        }
    }

    pub async fn reset(&mut self, start_time: u64) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        if start_time > now {
            let slot_duration_ms: u64 = self.slot_interval.period().as_millis() as u64;
            log::info!(
                "Resetting the clock to start at {}",
                start_time + slot_duration_ms
            );
            if !self.started {
                self.started = true;
            }
            self.t1_interval.reset_after(time::Duration::from_millis(
                start_time - now + self.t1_offset_ms,
            ));
            self.t2_interval.reset_after(time::Duration::from_millis(
                start_time - now + self.t2_offset_ms,
            ));
            self.slot_interval.reset_after(time::Duration::from_millis(
                start_time - now + slot_duration_ms,
            ));
        }
    }

    pub async fn start(&mut self) -> Result<(), Box<dyn Error>> {
        loop {
            select! {
                Some(t) = self.clock_recv.recv() => {
                    self.reset(t).await;
                }
                _ = self.slot_interval.tick() => {
                    if self.started {
                        self.protocol_send.send(SlotMessage::SlotTick).unwrap();
                    }
                }
                _ = self.t1_interval.tick() => {
                    if self.started {
                        self.protocol_send.send(SlotMessage::SlotThreshold1).unwrap();
                    }
                }
                _ = self.t2_interval.tick() => {
                    if self.started {
                        self.protocol_send.send(SlotMessage::SlotThreshold2).unwrap();
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn test_slot_clock_restart() {
        let slot_duration = 1000;
        let threshold_offset = 2000;

        let (protocol_send, mut protocol_recv) = tokio::sync::broadcast::channel(3);
        let (clock_send, clock_recv) = mpsc::unbounded_channel();

        let mut slot_clock = SlotClock::new(
            slot_duration,
            threshold_offset,
            threshold_offset,
            protocol_send,
            clock_recv,
        );

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    Ok(msg) = protocol_recv.recv() => {
                        if let SlotMessage::SlotTick = msg {
                            println!(
                                "{:?}",
                                std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap()
                                    .as_secs()
                            );
                        }
                    }
                }
            }
        });

        tokio::spawn(async move {
            slot_clock.start().await.unwrap();
        });

        println!("Configure to start in 3 seconds");
        clock_send
            .send(
                (std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis()
                    + 3000) as u64,
            )
            .unwrap();

        println!("Run for 10 seconds");
        tokio::time::sleep(time::Duration::from_secs(10)).await;

        println!("Reconfigured to start in 7 seconds");
        clock_send
            .send(
                (std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis()
                    + 7000) as u64,
            )
            .unwrap();

        tokio::time::sleep(time::Duration::from_secs(12)).await;
    }

    #[tokio::test]
    async fn test_slot_threshold() {
        let slot_duration = 5000;
        let threshold_offset = 2000;
        let threshold_offset2 = 4000;

        let (protocol_send, mut protocol_recv) = tokio::sync::broadcast::channel(3);
        let (clock_send, clock_recv) = mpsc::unbounded_channel();

        let mut slot_clock = SlotClock::new(
            slot_duration,
            threshold_offset,
            threshold_offset2,
            protocol_send,
            clock_recv,
        );

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    Ok(msg) = protocol_recv.recv() => {
                        match msg {
                            SlotMessage::SlotTick => {
                                println!(
                                    "{:?}: Tick",
                                    std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap()
                                        .as_secs()
                                );
                            },
                            SlotMessage::SlotThreshold1 => {
                                println!(
                                    "{:?}: Threshold",
                                    std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap()
                                        .as_secs()
                                );
                            },
                            _ => {}
                        }
                    }
                }
            }
        });

        tokio::spawn(async move {
            slot_clock.start().await.unwrap();
        });

        println!("Configure to start in 3 seconds");
        let t = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
            + 3000) as u64;
        clock_send.send(t).unwrap();

        tokio::time::sleep(time::Duration::from_secs(18)).await;
    }
}
