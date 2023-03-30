//cl#![warn(clippy::all)]

use std::path::PathBuf;
use std::{io::Read, io::Write};
use std::fs;
use exe::{PE, Buffer};
mod encryption;

#[path = "shared/mem.rs"]
mod mem;

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

pub fn pack(filename: PathBuf, output_filename: PathBuf, key: Vec<u8>) -> anyhow::Result<(), anyhow::Error>
{
    let mut buffer = Vec::new();
    get_file_buffer(filename, &mut buffer)?;
    
    // If i want to use data 'in place'
    // let (head, body, tail) = unsafe { buffer.align_to::<IMAGE_DOS_HEADER>() };
    let mut pe = exe::pe::VecPE::from_data(exe::pe::PEType::Disk, buffer);

    let dos = pe.get_valid_dos_header();
    if dos.is_err() {
        return Err(anyhow::Error::msg("Invalid DOS header."));
    }

    let dos_hdr = dos.unwrap().clone();
    
    if dos_hdr.e_magic.ne(&exe::DOS_SIGNATURE) {
        return Err(anyhow::Error::msg("Invalid DOS signature."));
    }

    let nts = pe.get_valid_mut_nt_headers_64();
    if nts.is_err() {
        return Err(anyhow::Error::msg("Invalid NT header."));
    }

    // We don't need mutable.
    let nts_hdr = nts.unwrap().clone();

    if nts_hdr.signature.ne(&exe::NT_SIGNATURE) {
        return Err(anyhow::Error::msg("Invalid NT signature."));
    }

    // Run steps
    encryption::pack(pe.clone(), dos_hdr, nts_hdr, key)?;

    // Add metadata
    // let mut newHdr: ImageSectionHeader;
    // newHdr.set_name(Some(".pack"));
    // pe.append_section(section)

    let writable = pe.get_mut_buffer();

    // Print and write
    println!("Successfully ran all packer steps.");
    write_file_buffer(&writable.to_vec(), output_filename)?;
    Ok(())
}