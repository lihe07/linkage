// __cxa_atexit

#[no_mangle]
extern "C" fn __cxa_atexit() {
    // Do nothing
    println!("Hook: __cxa_atexit called. Doing nothing.");
}

pub fn hook_symbol(name: &str) -> Option<usize> {
    match name {
        "__cxa_atexit" => Some(__cxa_atexit as usize),
        _ => None,
    }
}
