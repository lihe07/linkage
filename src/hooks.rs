use log::{info, warn};

// __cxa_atexit
#[no_mangle]
extern "C" fn hook__cxa_atexit(func: usize, _arg: usize, _dso: usize) {
    // Do nothing
    info!(
        "Hook: __cxa_atexit(func: {:x}, arg: {:x}, dso: {:x})",
        func, _arg, _dso
    );
}

// getenv
#[no_mangle]
unsafe extern "C" fn hook_getenv(name: *const libc::c_char) -> *mut libc::c_char {
    let name_cstr = unsafe { std::ffi::CStr::from_ptr(name) };
    info!("Hook: getenv(name: {:?})", name_cstr);
    if name_cstr.to_str().unwrap() == "GC_DONT_GC" {
        warn!("Hook: Setting GC_DONT_GC");
        1 as *mut libc::c_char
    } else {
        libc::getenv(name)
    }
}

pub fn hook_symbol(name: &str) -> Option<usize> {
    match name {
        "__cxa_atexit" => Some(hook__cxa_atexit as usize),
        "getenv" => Some(hook_getenv as usize),
        _ => None,
    }
}
