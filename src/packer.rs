//cl#![warn(clippy::all)]

use std::path::PathBuf;
use std::{io::Read, io::Write};
use std::fs;
use exe::{PE, Buffer};
mod encryption;
mod exception;

fn get_file_buffer(filename: PathBuf, buffer: &mut Vec<u8>) -> anyhow::Result<(), anyhow::Error>
{
    let mut f = fs::File::options().read(true).write(false).create(false).create_new(false).open(filename)?;
    f.read_to_end(buffer)?;
    Ok(())
}

fn write_file_buffer(buffer: &Vec<u8>, output_filename: PathBuf) -> anyhow::Result<(), anyhow::Error>
{
    let mut f = fs::File::options().write(true).create(true).open(output_filename)?;
    f.write_all(&buffer)?;
    Ok(())
}

pub fn pack(filename: PathBuf, output_filename: PathBuf, key: &mut Vec<u8>) -> anyhow::Result<(), anyhow::Error>
{
    let mut buffer = Vec::new();
    get_file_buffer(filename, &mut buffer)?;
    
    // If i want to use data 'in place'
    // let (head, body, tail) = unsafe { buffer.align_to::<IMAGE_DOS_HEADER>() };
    let mut pe = exe::pe::VecPE::from_disk_data(buffer);

    let dos = pe.get_valid_dos_header()?;
    let dos_hdr = dos.clone();
    if dos_hdr.e_magic.ne(&exe::DOS_SIGNATURE) {
        return Err(anyhow::Error::msg("Invalid DOS signature."));
    }

    let nts = pe.get_valid_nt_headers_64()?;
    let nts_hdr = nts.clone();
    if nts_hdr.signature.ne(&exe::NT_SIGNATURE) {
        return Err(anyhow::Error::msg("Invalid NT signature."));
    }

    println!("Size of PE before 0x{:X}", pe.calculate_disk_size().unwrap());

    let mut entries: Vec<shared::metadata::RuntimeFunction> = Vec::new();

    // Run steps
    encryption::pack(&mut pe, dos_hdr, nts_hdr, key)?; 
    exception::pack(&mut pe, dos_hdr, nts_hdr, &mut entries)?;

    // Write metadata to end of PE.
    shared::metadata::write_data(&mut pe, key, &mut entries)?;

    println!("Size of PE after 0x{:X}", pe.calculate_disk_size().unwrap());

    let writable = pe.get_mut_buffer();

    // Print and write
    println!("Successfully ran all packer steps.");
    write_file_buffer(&writable.to_vec(), output_filename)?;
    Ok(())
}