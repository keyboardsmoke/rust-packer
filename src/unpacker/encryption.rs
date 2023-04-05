use exe::{PE, CCharString};

pub fn attach(_base: u64, _pe: &mut exe::pe::PtrPE) -> anyhow::Result<(), anyhow::Error>
{
    Ok(())
}

pub fn entry(_base: u64, pe: &mut exe::pe::PtrPE, _peb: u64, metadata: &shared::metadata::Metadata) -> anyhow::Result<(), anyhow::Error>
{
    let key = metadata.key.clone();

    let dos = pe.get_valid_dos_header()?;
    let nts = pe.get_valid_nt_headers_64()?;

    shared::section::foreach_section_module(pe, *dos, *nts, |ptr, sec| {
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

pub fn call(_base: u64, _pe: &mut exe::pe::PtrPE) -> anyhow::Result<(), anyhow::Error>
{
    Ok(())
}

pub fn detach(_base: u64, _pe: &mut exe::pe::PtrPE) -> anyhow::Result<(), anyhow::Error>
{
    Ok(())
}