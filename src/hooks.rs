// __cxa_atexit

#[no_mangle]
extern "C" fn hook__cxa_atexit(func: usize, _arg: usize, _dso: usize) {
    // Do nothing
    println!(
        "Hook: __cxa_atexit(func: {:x}, arg: {:x}, dso: {:x})",
        func, _arg, _dso
    );
}

pub fn hook_symbol(name: &str) -> Option<usize> {
    match name {
        "__cxa_atexit" => Some(hook__cxa_atexit as usize),
        _ => None,
    }
}
