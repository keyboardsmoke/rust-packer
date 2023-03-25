use std::borrow::Borrow;
use std::num::ParseIntError;

use arg_parse::ArgParser;
use arg_parse::config;

pub mod packer;

const LONG_OPTIONS: &'static [config::LongOption] = &[
   config::LongOption{name: "bin", value_count: 1},
   config::LongOption{name: "out", value_count: 1},
   config::LongOption{name: "key", value_count: 1}
];
const SHORT_OPTIONS: &'static [config::ShortOption] = &[];
const NON_OPTIONS: &'static [config::NonOption] = &[];
const PARSER_ROOT_CMD: config::Config = config::Config::from(SHORT_OPTIONS, LONG_OPTIONS, NON_OPTIONS);
static PARSER: ArgParser = ArgParser::from(PARSER_ROOT_CMD);

fn make_key(key_string: String) -> Result<Vec<u8>, ParseIntError>
{
    println!("Making key from {}", key_string);
    (0..key_string.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&key_string[i..i + 2], 16))
        .collect()
}

fn main() -> Result<(), std::io::Error>
{
    let root_cmd = PARSER.parse();
    if root_cmd.is_err() {
        println!("Failed to parse command line arguments.");
        return Err(std::io::Error::from_raw_os_error(1));
    }

    let root = root_cmd.unwrap();
    let opts = root.long_options.to_vec();

    let mut opt_bin = String::new();
    let mut opt_out = String::new();
    let mut opt_key = String::new();

    for opt in opts {
        if opt.name == "bin" {
            opt_bin = opt.values.first().unwrap().to_string();
        } else if opt.name == "out" {
            opt_out = opt.values.first().unwrap().to_string();
        } else if opt.name == "key" {
            opt_key = opt.values.first().unwrap().to_string();
        } else {
            // How?
            println!("Unrecognized option passed to arguments {}", opt.name.to_string());
            return Err(std::io::Error::from_raw_os_error(1));
        }
    }

    if opt_bin.is_empty() {
        println!("You must provide a --bin argument.");
        return Err(std::io::Error::from_raw_os_error(1));
    }

    if opt_out.is_empty() {
        println!("You must provide a --out argument.");
        return Err(std::io::Error::from_raw_os_error(1));
    } 

    if opt_key.is_empty() {
        println!("You must provide a --key argument.");
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