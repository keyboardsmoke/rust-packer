use exe::{PE, CCharString};

#[path = "../shared/mem.rs"]
mod mem;

#[path = "../shared/section.rs"]
mod section;

pub fn interpret_pack_section(data: Vec<u8>) -> anyhow::Result<Vec<u8>, anyhow::Error>
{
    // First zero value is the end of the key, i don't really like this because we should know the size of the key... let's just embed it?
    let key_len: [u8; 4] = [ data[0], data[1], data[2], data[3] ];
    let key_len_u32 = u32::from_be_bytes(key_len) as usize;

    let mut key: Vec<u8> = Vec::new();
    print!("Pack key read [");
    for i in 4..key_len_u32+4 {
        let c = data[i];
        print!("{:X}", c);
        key.push(c);
    }
    println!("]");

    return Ok(key.to_vec());
}

pub fn initialize()
{
    // todo!("Nothing here yet.");
}

pub fn run(_base: u64, pe: &mut exe::pe::PtrPE, _peb: u64) -> anyhow::Result<(), anyhow::Error>
{
    let pack_section_hdr = pe.get_section_by_name(".pack")?;
    let pack_section_data = pack_section_hdr.read(pe)?;
    let pack_section_vec = pack_section_data.to_vec();
    let key = interpret_pack_section(pack_section_vec)?;

    let dos = pe.get_valid_dos_header()?;
    let nts = pe.get_valid_nt_headers_64()?;

    section::foreach_section_module(pe, *dos, *nts, |ptr, sec| {
        let sname = sec.name.as_str();
        if sname.is_err() {
            println!("Unable to get section name for section at {}", sec.pointer_to_raw_data.0);
            return;
        }

        let sec_name = sname.ok().unwrap();
        println!("Processing {}", sec_name);

        let good = sec.characteristics.bits() & exe::headers::SectionCharacteristics::MEM_EXECUTE.bits();
        if good != exe::headers::SectionCharacteristics::MEM_EXECUTE.bits() {
            println!("Skipping section {} because it is not marked MEM_EXECUTE.", sec_name);
            return;
        }

        if sec.size_of_raw_data == 0 {
            println!("Skipping section {} because it's raw data is 0.", sec_name);
            return;
        }

        let sec_ptr = unsafe { ptr.add(sec.virtual_address.0 as usize) };

        let q = region::query(sec_ptr);
        if q.is_err() {
            println!("Skipping section {} because we cannot query it's memory region.", sec_name);
            return;
        }

        let query = q.unwrap();
        let prot = query.protection();

        let p = unsafe { region::protect(sec_ptr, query.len(), region::Protection::READ_WRITE_EXECUTE) };
        if p.is_err() {
            println!("Skipping section {} because set it's memory regions to READ_WRITE_EXECUTE.", sec_name);
            return;
        }

        for i in 0 .. sec.size_of_raw_data as usize {
            let kv = key[i.rem_euclid(key.len())];
            unsafe {
                let base: *mut u8 = ptr.add(sec.virtual_address.0 as usize + i);
                *base = *base ^ kv;
            };
        }

        let ps = unsafe { region::protect(sec_ptr, query.len(), prot) };
        if ps.is_err() {
            println!("Warning: Section {} could not restore region protections.", sec_name);
            return;
        }
    });
    Ok(())
}