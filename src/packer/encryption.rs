use exe::{ImageDOSHeader, ImageNTHeaders64, CCharString};

pub fn pack(pe: &mut exe::pe::VecPE, dos: ImageDOSHeader, nts: ImageNTHeaders64, key: &mut Vec<u8>) -> anyhow::Result<(), anyhow::Error>
{
    shared::section::foreach_section_buffer(pe, dos, nts, |vpe, sec| {
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

        println!("Packing section {}", sec_name);

        for i in 0 as usize .. sec.size_of_raw_data as usize {
            let kv = key[i.rem_euclid(key.len())];
            unsafe {
                let base = vpe.add(sec.pointer_to_raw_data.0 as usize + i);
                *base = *base ^ kv;
            };
        }
        println!("Packed section {}", sec_name);
    });
    Ok(())
}