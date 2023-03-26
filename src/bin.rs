use std::num::ParseIntError;

use clap::{Command, arg};

pub mod packer;

fn make_key(key_string: String) -> anyhow::Result<Vec<u8>, ParseIntError>
{
    println!("Making key from {}", key_string);
    (0..key_string.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&key_string[i..i + 2], 16))
        .collect()
}

fn make_arguments(bin: &mut String, out: &mut String, key: &mut String) -> bool
{
    let matches = Command::new("rust-packer")
        .color(clap::ColorChoice::Always)
        .arg(arg!(--bin <VALUE>).required(true))
        .arg(arg!(--out <VALUE>).required(true))
        .arg(arg!(--key <VALUE>).required(true))
        .get_matches();

    let bin_value = matches.get_one::<String>("bin");
    if bin_value.is_none() {
        return false;
    }
    bin.clone_from(bin_value.unwrap());
    let out_value = matches.get_one::<String>("out");
    if out_value.is_none() {
        return false;
    }
    out.clone_from(out_value.unwrap());
    let key_value = matches.get_one::<String>("key");
    if key_value.is_none() {
        return false;
    }
    key.clone_from(key_value.unwrap());
    return true;
}

fn main() -> anyhow::Result<(), std::io::Error>
{
    let mut opt_bin = String::new();
    let mut opt_out = String::new();
    let mut opt_key = String::new();
    if make_arguments(&mut opt_bin, &mut opt_out, &mut opt_key) == false {
        println!("Failed to parse command line arguments.");
        return Err(std::io::Error::from_raw_os_error(1));
    }
    let key = make_key(opt_key.clone());
    if key.is_err() {
        println!("Unable to decode key string [{}].", opt_key);
        return Err(std::io::Error::from_raw_os_error(1));
    }

    let key_vec = key.unwrap();

    print!("Key bytes [");
    key_vec
        .iter()
        .enumerate()
        .for_each(|(_, p)| {
            print!("{:02X}", p);
        });
    println!("]");

    if packer::pack(opt_bin, opt_out, key_vec).is_ok() {
        return Ok(());
    }
    Err(std::io::Error::last_os_error())
}