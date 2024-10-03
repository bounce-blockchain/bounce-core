use clap::{Parser};
use bls::min_pk::{SecretKey};
use std::{
    fs::File,
    io::{prelude::*, BufWriter},
};

#[derive(Parser)]
struct Args {
    #[clap(long, short)]
    outfile_prefix: String,
}
/**
 * Generate a BLS secret key and a corresponding public key.
 * Usage: keygen --outfile-prefix <outfile_prefix>
 * Output: <outfile_prefix>.secret.key, <outfile_prefix>.public.key
 */
fn main() {
    let args = Args::parse();

    let (sk_bytes, pk_bytes) = {
            let key = SecretKey::generate();
            (key.to_bytes(), key.sk_to_pk().to_bytes().to_vec())
    };

    let mut sk_writer =
        BufWriter::new(File::create(args.outfile_prefix.clone() + ".secret.key").unwrap());

    let _ = sk_writer.write(&sk_bytes).unwrap();

    let mut pk_writer =
        BufWriter::new(File::create(args.outfile_prefix + ".public.key").unwrap());

    let _ = pk_writer.write(&pk_bytes).unwrap();
}
