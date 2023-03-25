use winapi::um::winnt::{IMAGE_NT_HEADERS64, IMAGE_DOS_HEADER};

mod encryption;

fn virtual_to_raw(offset: usize)
{
    
}

pub fn initialize()
{
    encryption::initialize();
}

pub fn run(base: u64, peb: u64)
{
    // Get DOS, NT etc.
    // Pass it.

    encryption::run(base, peb);
}