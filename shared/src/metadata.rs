use std::{ops::Index};
use exe::{PE, Buffer};
use crate::{section};

#[derive(Clone)]
#[allow(unused)]
pub struct RuntimeFunction
{
    pub begin: u32,
    pub end: u32,
    pub unwind: u32,
    pub key: u32
}

impl RuntimeFunction
{
    #[allow(unused)]
    pub fn get_begin_addr(&self) -> u32
    {
        return self.begin ^ self.key;
    }

    #[allow(unused)]
    pub fn get_end_addr(&self) -> u32
    {
        return self.end ^ self.key;
    }

    #[allow(unused)]
    pub fn get_unwind_addr(&self) -> u32
    {
        return self.unwind ^ self.key;
    }

    #[allow(unused)]
    pub fn set_begin_addr(&mut self, offset: u32)
    {
        self.begin = offset ^ self.key;
    }

    #[allow(unused)]
    pub fn set_end_addr(&mut self, offset: u32)
    {
        self.end = offset ^ self.key;
    }

    #[allow(unused)]
    pub fn set_unwind_addr(&mut self, offset: u32)
    {
        self.unwind = offset ^ self.key;
    }
}

#[allow(unused)]
pub struct FunctionTableCallbackData
{
    pub base: u64,
    pub size: u64,
    pub fns: Vec<RuntimeFunction>
}

pub struct ImportEntry
{
    pub module_name: String,
    pub function_name: Option<String>,
    pub ordinal: Option<u64>
}

#[allow(unused)]
pub struct Metadata
{
    // key data
    pub key: Vec<u8>,

    // 
    pub exception_entries: Vec<RuntimeFunction>,


    //
    // pub import_entries: Vec<ImportEntry>
}

pub struct StreamReader
{
    pub ptr: *mut u8,
    pub index: usize,
}

impl StreamReader
{
    pub fn read<T>(&mut self) -> T
    {
        let dest = unsafe { self.ptr.add(self.index) };
        let res = unsafe { dest.cast::<T>().read() };
        self.index += std::mem::size_of::<T>();
        return res;
    }
}

#[allow(unused)]
pub fn read_data(pe: &mut exe::pe::PtrPE) -> anyhow::Result<Metadata, anyhow::Error>
{
    let pack_section_hdr = pe.get_section_by_name(".pack")?;
    let pack_section_data = pack_section_hdr.read(pe)?;
    let mut pack_section_vec = pack_section_data.to_vec();
    let mut reader = StreamReader { ptr: pack_section_vec.as_mut_ptr(), index: 0 };

    let key_length = reader.read::<u32>();
    println!("Key Length: {}", key_length);

    let exception_entries = reader.read::<u32>();
    println!("Exception Entries: {}", exception_entries);

    let mut key: Vec<u8> = Vec::new();
    for i in 0..key_length as usize {
        let byte = reader.read::<u8>();
        println!("Key byte {} = 0x{:X}", i, byte);
        key.push(byte);
    }

    let mut entries: Vec<RuntimeFunction> = Vec::new();
    for _ in 0..exception_entries as usize {
        let begin = reader.read::<u32>();
        let end = reader.read::<u32>();
        let unwind = reader.read::<u32>();
        let key = reader.read::<u32>();
        if begin == 0 && end == 0 && unwind == 0 && key == 0 {
            println!("All null runtime function entry.");
            continue
        }
        let entry = RuntimeFunction { begin: begin, end: end, unwind: unwind, key: key };
        println!("Metadata Runtime Function [0x{:X}, 0x{:X}, 0x{:X}, 0x{:X}]", entry.get_begin_addr(), entry.get_end_addr(), entry.get_unwind_addr(), entry.key);
        entries.push(entry);
    }

/*
    let mut imps: Vec<ImportEntry> = Vec::new();
    let impres = pe.get_data_directory(exe::ImageDirectoryEntry::Import);
    if impres.is_ok() {
        let impdir = impres.unwrap();
        let number_of_descriptors = impdir.size as usize / std::mem::size_of::<IMAGE_IMPORT_DESCRIPTOR>();
        
        for i in 0..number_of_descriptors {
            let desc = unsafe { *pe.as_mut_ptr().add(i * std::mem::size_of::<IMAGE_IMPORT_DESCRIPTOR>()).cast::<IMAGE_IMPORT_DESCRIPTOR>() };
            let original_first = unsafe { *desc.u.OriginalFirstThunk() };
            if desc.Name == 0 { break } // No more entries.
            let raw_name_offset = mem::virtual_to_raw(pe, desc.Name);
            let raw_original_first_thunk = mem::virtual_to_raw(pe, original_first);
            if raw_name_offset.is_err() || raw_original_first_thunk.is_err() {
                println!("Unable to locate the raw name offset or raw original thunk for import...");
                break
            }
            let raw_offset_value = raw_name_offset.unwrap();
            let module_name = exe::Offset(raw_offset_value).get_cstring(pe, false, None);
            if module_name.is_err() {
                println!("Unable to reference import module function name memory.");
                break
            }
            let othunk = raw_original_first_thunk.unwrap();
            let mut iat = unsafe { pe.as_mut_ptr().add(desc.FirstThunk as usize).cast::<IMAGE_THUNK_DATA64>() };
            let mut int: *mut IMAGE_THUNK_DATA64 = 0 as *mut IMAGE_THUNK_DATA64;
            if othunk != 0 {
                int = unsafe { pe.as_mut_ptr().add(othunk as usize).cast::<IMAGE_THUNK_DATA64>() };
            } else {
                int = iat;
            }

            unsafe {
                println!("Desc [Name: 0x{:X}][Characteristics: 0x{:X}][TimeDateStamp: 0x{:X}][FirstThunk: 0x{:X}][OriginalFirstThunk: 0x{:X}][ForwarderChain: 0x{:X}]", 
                    raw_offset_value, *desc.u.Characteristics(), desc.TimeDateStamp, desc.FirstThunk, *desc.u.OriginalFirstThunk(), desc.ForwarderChain);
            }

            let mut i = 0;
            let mut int_fn = unsafe { *(*int).u1.Function() };
            loop
            {
                let cint = unsafe { int.add(i) };
                let ciat = unsafe { iat.add(i) };

                let rva = desc.FirstThunk + std::mem::size_of::<uintptr_t>() as u32 * i as u32;
                println!("RVA: 0x{:X}", rva);

                let ord = unsafe { *(*cint).u1.Ordinal() };

                int_fn = unsafe { *(*cint).u1.Function() };
                i += 1;
            }
        }
    }

    Ok(Metadata { key: key, exception_entries: entries, import_entries: imps })
*/
    Ok(Metadata { key: key, exception_entries: entries })
}

#[allow(unused)]
pub fn write_data(pe: &mut exe::pe::VecPE, key: &mut Vec<u8>, entries: &mut Vec<RuntimeFunction>) -> anyhow::Result<(), anyhow::Error>
{
    let mut section_buffer: Vec<u8> = Vec::new();

    let mut key_len = (key.len() as u32).to_le_bytes().to_vec();
    let mut entry_count = (entries.len() as u32).to_le_bytes().to_vec();

    section_buffer.append(&mut key_len);
    section_buffer.append(&mut entry_count);

    let old_len = pe.get_buffer().len();

    // Append key to the end of the binary, which should be where our section is?...
    for i in 0..key.len() {
        let kv = *key.index(i);
        section_buffer.append(&mut [kv].to_vec());
    }
    
    for i in 0..entries.len() {
        let entry = entries.index(i);

        // Append the raw (encoded) values into the metadata...
        section_buffer.append(&mut entry.begin.to_le_bytes().to_vec());
        section_buffer.append(&mut entry.end.to_le_bytes().to_vec());
        section_buffer.append(&mut entry.unwind.to_le_bytes().to_vec());
        section_buffer.append(&mut entry.key.to_le_bytes().to_vec());
    }

    let new_len = pe.get_buffer().len();

    section::add_section_with_data(pe, ".pack", section_buffer)?;
    Ok(())
}