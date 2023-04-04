use exe::{ImageDOSHeader, ImageNTHeaders64, PE, Buffer, SectionCharacteristics};
use winapi::um::winnt::RUNTIME_FUNCTION;

pub fn pack(pe: &mut exe::pe::VecPE, _dos: ImageDOSHeader, _nts: ImageNTHeaders64, entries: &mut Vec<shared::metadata::RuntimeFunction>) -> anyhow::Result<(), anyhow::Error>
{
    let data_ptr = pe.get_mut_buffer().as_mut_ptr();
    let pdata = pe.get_mut_section_by_name(".pdata".to_string())?;
    let pdata_ptr = unsafe { data_ptr.add(pdata.pointer_to_raw_data.0 as usize) };
    let mut reader: shared::metadata::StreamReader = shared::metadata::StreamReader { ptr: pdata_ptr, index: 0 };
    let total = pdata.size_of_raw_data as usize / std::mem::size_of::<RUNTIME_FUNCTION>();

    // Start pdata: 000000014001E000
    // Start real entries: 000000014001F800
    // Delta = 1800
    // 1800 / 4 = 600
    // 600 / 3 = 200
    // Should be about 600 null entries...

    for _ in 0..total {
        let offset = reader.index;
        let begin = reader.read::<u32>();
        let end = reader.read::<u32>();
        let unwind = reader.read::<u32>();
        let random_key = rand::random::<u32>();
        if begin == 0 && end == 0 && unwind == 0 {
            continue
        }
        let mut nrt: shared::metadata::RuntimeFunction = shared::metadata::RuntimeFunction { begin: 0, end: 0, unwind: 0, key: random_key };
        nrt.set_begin_addr(begin);
        nrt.set_end_addr(end);
        nrt.set_unwind_addr(unwind);
        println!("Ingest Runtime Function [0x{:X}, 0x{:X}, 0x{:X}, 0x{:X}][Offset: 0x{:X}]", begin, end, unwind, random_key, offset);
        entries.push(nrt);
    }

    // Yeet it.
    unsafe { 
        // pdata.name.fill(exe::CChar(0));
        pdata.characteristics = SectionCharacteristics::MEM_DISCARDABLE;
        pdata_ptr.write_bytes(0, pdata.size_of_raw_data as usize); 
        
        // This is required before RtlInstallFunctionTableCallback will catch pcs from this binary...
        let datadir = pe.get_mut_data_directory(exe::ImageDirectoryEntry::Exception)?;
        datadir.virtual_address = exe::RVA(0);
        datadir.size = 0;
        println!("Set IMAGE_DIRECTORY_ENTRY_EXCEPTION entry to nil.");
    };

    Ok(())
}