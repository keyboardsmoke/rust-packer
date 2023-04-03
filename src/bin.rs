use std::{num::ParseIntError, path::PathBuf};
use clap::Parser;

pub mod packer;


#[derive(Debug, Clone, Parser)]
#[command(name="Rust binary packer", author="Andrew Artz", version="1.0", about="Rust binary packer", long_about=None)]
struct CliOptions
{
    #[clap(short, long)]
    bin: PathBuf,

    #[clap(short, long)]
    out: PathBuf,

    #[clap(short, long)]
    key: Option<String>
}

fn make_key(key_string: String) -> anyhow::Result<Vec<u8>, ParseIntError>
{
    println!("Making key from {}", key_string);
    (0..key_string.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&key_string[i..i + 2], 16))
        .collect()
}

fn main() -> anyhow::Result<(), std::io::Error>
{
    let opts = CliOptions::parse();

    println!("Input binary [{}]", opts.bin.to_str().unwrap());
    println!("Output binary [{}]", opts.out.to_str().unwrap());

    let mut key_vec = if opts.key.is_none() {
        println!("Warning: Using static development key.");
        let static_key: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];
        static_key.to_vec()
    } else {
        let opt_key = opts.key.unwrap();
        let key = make_key(opt_key.clone());
        if key.is_err() {
            println!("Unable to decode key string [{}].", opt_key);
            return Err(std::io::Error::from_raw_os_error(1));
        }
        key.unwrap()
    };

    print!("Key bytes [");
    key_vec
        .iter()
        .enumerate()
        .for_each(|(_, p)| {
            print!("{:02X}", p);
        });
    println!("]");

    if packer::pack(opts.bin, opts.out, &mut key_vec).is_ok() {
        return Ok(());
    }
    Err(std::io::Error::last_os_error())
}