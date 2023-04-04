use std::ops::Index;

use exe::PE;

pub fn cast_offset_from_mod<T>(module: *mut u8, offset: usize) -> T
{
    let a = unsafe { module.offset(offset as isize) };
    let r: T = unsafe { std::ptr::read(a as *const _) };
    return r;
}

pub fn cast_offset_from_vec<T>(buffer: &Vec<u8>, offset: usize) -> T
{
    let a = unsafe { buffer.as_ptr().add(offset) };
    let r: T = unsafe { std::ptr::read(a as *const _) };
    return r;
}

pub fn is_power_of_two(num: usize) -> bool
{
	num != 0 && (num & (num - 1)) == 0
}

pub fn align(offset: usize, align: usize) -> usize
{
	debug_assert!(is_power_of_two(align));

	(offset + (align - 1)) & !(align - 1)
}

pub fn page_align(offset: usize) -> usize 
{
	align(offset, page_size::get())
}

pub fn raw_to_virtual(pe: &mut exe::PtrPE, offset: u32) -> anyhow::Result<u32, anyhow::Error>
{
    let secs = pe.get_section_table()?;
    for i in 0..secs.len() {
        let sec = secs.index(i);
        let start = sec.pointer_to_raw_data.0;
        let end = start + sec.size_of_raw_data;
        if offset >= start && offset < end {
            let offset_in_section = offset - start;
            return Ok(sec.virtual_address.0 + offset_in_section);
        }
    }
    Err(anyhow::Error::msg("Unable to locate section with offset."))
}

pub fn virtual_to_raw(pe: &mut exe::PtrPE, offset: u32) -> anyhow::Result<u32, anyhow::Error>
{
    let secs = pe.get_section_table()?;
    for i in 0..secs.len() {
        let sec = secs.index(i);
        let start = sec.virtual_address.0;
        let end = start + sec.virtual_size;
        if offset >= start && offset < end {
            let offset_in_section = offset - start;
            return Ok(sec.pointer_to_raw_data.0 + offset_in_section);
        }
    }
    Err(anyhow::Error::msg("Unable to locate section with offset."))
}