#![warn(clippy::all)]

use std::{io::{Read, self}, io::Write};
use std::fs;

use winapi::um::winnt::{IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_HEADERS64, IMAGE_NT_SIGNATURE};

mod encryption;

#[path = "shared/mem.rs"]
mod mem;

fn get_file_buffer(filename: String, buffer: &mut Vec<u8>) -> io::Result<()>
{
    let mut f = fs::File::open(filename)?;
    f.read_to_end(buffer)?;
    Ok(())
}

fn write_file_buffer(buffer: &Vec<u8>, output_filename: String) -> Result<(), String>
{
    let f = fs::File::options().read(true).write(true).create(true).open(output_filename);
    if f.is_err() {
        return Err("Unable to open file.".to_string());
    }
    let mut file = f.unwrap();
    if file.write_all(&buffer).is_err() {
        return Err("Unable to write file.".to_string());
    }
    Ok(())
}

pub fn pack(filename: String, output_filename: String, _key: Vec<u8>) -> Result<(), String>
{
    let mut buffer = Vec::new();
    get_file_buffer(filename, &mut buffer).or(Err("Unable to open file for reading.".to_string()))?;
    
    // If i want to use data 'in place'
    // let (head, body, tail) = unsafe { buffer.align_to::<IMAGE_DOS_HEADER>() };

    let dos: IMAGE_DOS_HEADER = mem::cast_offset_from_vec::<IMAGE_DOS_HEADER>(&buffer, 0);
    
    if dos.e_magic.ne(&IMAGE_DOS_SIGNATURE) {
        return Err("Invalid DOS signature.".to_string());
    }

    let ntstart = dos.e_lfanew as usize;
    let nts: IMAGE_NT_HEADERS64 = mem::cast_offset_from_vec::<IMAGE_NT_HEADERS64>(&buffer, ntstart);

    if nts.Signature.ne(&IMAGE_NT_SIGNATURE) {
        return Err("Invalid NT signature.".to_string());
    }

    // Run steps
    encryption::pack(&mut buffer, dos, nts)?;

    // Print and write
    println!("Successfully ran all packer steps.");
    write_file_buffer(&buffer, output_filename)?;
    Ok(())
}