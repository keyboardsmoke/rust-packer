#[allow(unused)]
pub fn cast_offset_from_mod<T>(module: *mut u8, offset: usize) -> T
{
    let a = unsafe { module.offset(offset as isize) };
    let r: T = unsafe { std::ptr::read(a as *const _) };
    return r;
}

#[allow(unused)]
pub fn cast_offset_from_vec<T>(buffer: &Vec<u8>, offset: usize) -> T
{
    let a = unsafe { buffer.as_ptr().add(offset) };
    let r: T = unsafe { std::ptr::read(a as *const _) };
    return r;
}

#[allow(unused)]
pub fn is_power_of_two(num: usize) -> bool
{
	num != 0 && (num & (num - 1)) == 0
}

#[allow(unused)]
pub fn align(offset: usize, align: usize) -> usize
{
	debug_assert!(is_power_of_two(align));

	(offset + (align - 1)) & !(align - 1)
}

#[allow(unused)]
pub fn page_align(offset: usize) -> usize 
{
	align(offset, page_size::get())
}