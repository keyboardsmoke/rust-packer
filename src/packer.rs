//cl#![warn(clippy::all)]

use std::ops::Index;
use std::path::PathBuf;
use std::{io::Read, io::Write};
use std::fs;
use exe::{PE, Buffer, ImageSectionHeader, SectionCharacteristics};
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

    // Append key to the end of the binary, which should be where our section is?...
    for i in 0..0x1000 {
        if i < key.len() {
            let kv = *key.index(i);
            pe.get_mut_buffer().append([kv]);
        } else {
            pe.get_mut_buffer().append([0]);
        }
    }

    // Run steps
    encryption::pack(pe.clone(), dos_hdr, nts_hdr, key)?;

    let chars = SectionCharacteristics::MEM_READ | SectionCharacteristics::ALIGN_4096BYTES | SectionCharacteristics::CNT_INITIALIZED_DATA;

    let new_hdr = ImageSectionHeader { 
        name: [exe::CChar(0x2E), exe::CChar(0x70), exe::CChar(0x61), exe::CChar(0x63), exe::CChar(0x6B), exe::CChar(0x00), exe::CChar(0x00), exe::CChar(0x00)], 
        virtual_size: 0x1000, 
        virtual_address: exe::RVA(0), 
        size_of_raw_data: 0x1000, 
        pointer_to_raw_data: exe::Offset(0), 
        pointer_to_relocations: exe::Offset(0), 
        pointer_to_linenumbers: exe::Offset(0), 
        number_of_relocations: 0, 
        number_of_linenumbers: 0, 
        characteristics: chars
    };

    pe.append_section(&new_hdr)?;

    pe.fix_image_size()?;

    println!("Size of PE after 0x{:X}", pe.calculate_disk_size().unwrap());

    let writable = pe.get_mut_buffer();

    // Print and write
    println!("Successfully ran all packer steps.");
    write_file_buffer(&writable.to_vec(), output_filename)?;
    Ok(())
}