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

fn to_bytes(input: u32) -> anyhow::Result<Vec<u8>, anyhow::Error>
{
    let mut bytes = Vec::with_capacity(std::mem::size_of::<u32>());
    bytes.extend(&input.to_be_bytes());
    return Ok(bytes);
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

    let key_len = key.len();

    // Run steps
    encryption::pack(&mut pe, dos_hdr, nts_hdr, key)?;

    // Append the number of bytes to the stream...
    let key_len_bytes = to_bytes(key_len as u32)?;
    pe.get_mut_buffer().append(key_len_bytes);

    // Append key to the end of the binary, which should be where our section is?...
    for i in 0..key_len {
        let kv = *key.index(i);
        pe.get_mut_buffer().append([kv]);
    }

    // Fill whatever is left
    let remainder = 0x1000 - key.len();
    pe.get_mut_buffer().append((0..remainder).map(|_|0).collect::<Vec<u8>>());


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