use std::fs;
use std::fs::File;
use std::io::{Read, Write};
use serde_json::to_writer_pretty;


fn main() -> std::io::Result<()> {
    // let content = fs::read("receiving_time_elapsed_5.bin")?;
    // let data: Vec<Vec<u128>> = bincode::deserialize(&content).expect("Failed to deserialize");
    // println!("Loaded data: {:?}", data);
    let mut data: Vec<Vec<u128>> = Vec::new();
    for i in 0..10 {
        let content = fs::read(format!("receiving_time_elapsed_{}.bin", i))?;
        let cur_data: Vec<Vec<u128>> = bincode::deserialize(&content).expect("Failed to deserialize");
        //make the cur_data a single vector
        let mut cur_data_single: Vec<u128> = Vec::new();
        for d in cur_data {
            for dd in d {
                cur_data_single.push(dd);
            }
        }
        data.push(cur_data_single);
    }


    for d in &data {
        println!("{:?}", d);
    }
    println!("Data length: {}", data.len());
    // let mut sum = 0;
    // for d in &data[19] {
    //     sum += d;
    // }
    // println!("Average: {}", sum / data[19].len() as u128);

    // Write the data as JSON to a file
    let json_file = File::create("receiving_time_elapsed_100_benchmarks.json").unwrap();
    to_writer_pretty(json_file, &data).unwrap();
    //
    println!("Data has been reserialized into JSON");
    Ok(())
}