use winapi::{um::winnt::{IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER, IMAGE_FILE_HEADER}, shared::basetsd::DWORD32};

#[path = "mem.rs"]
mod mem;

#[allow(unused)]
pub fn foreach_section_buffer<T: Fn(&mut Vec<u8>, IMAGE_SECTION_HEADER) -> bool>(buffer: &mut Vec<u8>, dos: IMAGE_DOS_HEADER, nts: IMAGE_NT_HEADERS64, cb: T) -> bool
{
    let section_base = dos.e_lfanew as usize + core::mem::size_of::<DWORD32>() + core::mem::size_of::<IMAGE_FILE_HEADER>() + nts.FileHeader.SizeOfOptionalHeader as usize;
    for i in 0 .. nts.FileHeader.NumberOfSections
    {
        let offset = i as usize * core::mem::size_of::<IMAGE_SECTION_HEADER>();
        let sec = mem::cast_offset_from_vec::<IMAGE_SECTION_HEADER>(buffer, section_base + offset);
        if cb(buffer, sec) { return true; }
    }
    return false;
}

#[allow(unused)]
pub fn foreach_section_module<T: Fn(IMAGE_SECTION_HEADER) -> bool>(module: *mut u8, dos: IMAGE_DOS_HEADER, nts: IMAGE_NT_HEADERS64, cb: T) -> bool
{
    let section_base = dos.e_lfanew as usize + core::mem::size_of::<DWORD32>() + core::mem::size_of::<IMAGE_FILE_HEADER>() + nts.FileHeader.SizeOfOptionalHeader as usize;
    for i in 0 .. nts.FileHeader.NumberOfSections
    {
        let offset = i as usize * core::mem::size_of::<IMAGE_SECTION_HEADER>();
        let sec = mem::cast_offset_from_mod::<IMAGE_SECTION_HEADER>(module, section_base + offset);
        if cb(sec) { return true; }
    }
    return false;
}