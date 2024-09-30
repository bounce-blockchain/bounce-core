use std::time::{SystemTime, UNIX_EPOCH};

pub fn output_current_time(msg: &str) {
    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    let in_ms = since_the_epoch.as_millis();
    println!("{} at {}\n", msg, in_ms);
}