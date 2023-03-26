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