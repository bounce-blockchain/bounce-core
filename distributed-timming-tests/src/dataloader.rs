use std::fs;

fn main() -> std::io::Result<()> {
    let content = fs::read("receiving_time_elapsed.bin")?;
    let data: Vec<Vec<u128>> = bincode::deserialize(&content).expect("Failed to deserialize");
    println!("Loaded data: {:?}", data);

    Ok(())
}