use std::{num::ParseIntError};

use clap::{Command, arg, ArgMatches};

pub mod packer;

fn make_key(key_string: String) -> anyhow::Result<Vec<u8>, ParseIntError>
{
    println!("Making key from {}", key_string);
    (0..key_string.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&key_string[i..i + 2], 16))
        .collect()
}

fn get_argument(matches: ArgMatches, name: &str) -> anyhow::Result<String, std::io::Error>
{
    let res = matches.get_one::<String>(name);
    if res.is_none() {
        println!("Unable to find required argument \"{}\", exiting...", name);
        return Err(std::io::Error::from_raw_os_error(1));
    }

    Ok(res.unwrap().to_owned())
}

fn main() -> anyhow::Result<(), std::io::Error>
{
    let matches = Command::new("rust-packer")
        .color(clap::ColorChoice::Always)
        .arg(arg!(--bin <VALUE>).required(true))
        .arg(arg!(--out <VALUE>).required(true))
        .arg(arg!(--key <VALUE>).required(true))
        .get_matches();

    let opt_bin = get_argument(matches.clone(), "bin")?;
    let opt_out = get_argument(matches.clone(), "out")?;
    let opt_key = get_argument(matches.clone(), "key")?;

    println!("Input binary [{}]", opt_bin);
    println!("Output binary [{}]", opt_out);

    let key_vec = if opt_key.is_empty() {
        println!("Warning: Using static development key.");
        let static_key: [u8; 3] = [0x50, 0xBE, 0x17];
        static_key.to_vec()
    } else {
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

    if packer::pack(opt_bin, opt_out, key_vec).is_ok() {
        return Ok(());
    }
    Err(std::io::Error::last_os_error())
}