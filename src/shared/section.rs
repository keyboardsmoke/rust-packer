use exe::{ImageSectionHeader, ImageNTHeaders64, ImageDOSHeader, Address, PE, Buffer, ImageFileHeader};

#[path = "mem.rs"]
mod mem;

#[allow(unused)]
pub fn foreach_section_buffer<T: FnMut(*mut u8, &&[ImageSectionHeader]) -> bool>(pe: &mut exe::pe::VecPE, dos: ImageDOSHeader, nts: ImageNTHeaders64, mut cb: T) -> bool
{
    let nts_base: usize = dos.e_lfanew.as_offset(pe).unwrap().into();
    let section_base = nts_base as usize + core::mem::size_of::<u32>() + core::mem::size_of::<ImageFileHeader>() + nts.file_header.size_of_optional_header as usize;

    let peb = pe.as_mut_ptr();
    pe.get_section_table().iter().for_each(|sec| {
        cb(peb, sec);
    });
    return false;
}

#[allow(unused)]
pub fn foreach_section_module<T: FnMut(*mut u8, &&[ImageSectionHeader]) -> bool>(pe: &mut exe::pe::PtrPE, dos: ImageDOSHeader, nts: ImageNTHeaders64, mut cb: T) -> bool
{
    let nts_base: usize = dos.e_lfanew.as_offset(pe).unwrap().into();
    let section_base = nts_base as usize + core::mem::size_of::<u32>() + core::mem::size_of::<ImageFileHeader>() + nts.file_header.size_of_optional_header as usize;
    let peb = pe.as_mut_ptr();
    pe.get_section_table().iter().for_each(|sec| {
        cb(peb, sec);
    });
    return false;
}