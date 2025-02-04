use linkage::ElfFile;
use log::*;

fn main() {
    // Init logger

    // Set RUST_LOG=debug to enable debug logs
    unsafe {
        std::env::set_var("RUST_LOG", "trace");
    }
    pretty_env_logger::init();

    let path = std::env::args().nth(1).unwrap();

    let mut elf = ElfFile::parse(&path).unwrap();

    elf.load().unwrap();

    println!("===========================");
    println!("= ELF successfully loaded =");
    println!("===========================");

    // let il2cpp_register_log_callback = elf.get_symbol("il2cpp_register_log_callback").unwrap();
    //
    // let il2cpp_register_log_callback: extern "C" fn(extern "C" fn(*const std::os::raw::c_char)) =
    //     unsafe { std::mem::transmute(il2cpp_register_log_callback) };
    //
    // info!("Registering log callback");
    // il2cpp_register_log_callback(linkage::hooks::my_log_callback);

    let il2cpp_gc_disable = elf.get_symbol("il2cpp_gc_disable").unwrap();
    let il2cpp_gc_disable: extern "C" fn() = unsafe { std::mem::transmute(il2cpp_gc_disable) };

    info!("Disabling GC");
    il2cpp_gc_disable();

    let il2cpp_runtime_unhandled_exception_policy_set = elf
        .get_symbol("il2cpp_runtime_unhandled_exception_policy_set")
        .unwrap();

    let il2cpp_runtime_unhandled_exception_policy_set: extern "C" fn(u32) =
        unsafe { std::mem::transmute(il2cpp_runtime_unhandled_exception_policy_set) };

    info!("Setting unhandled exception policy");
    il2cpp_runtime_unhandled_exception_policy_set(1);

    let il2cpp_init = elf.get_symbol("il2cpp_init").unwrap();
    let il2cpp_init: extern "C" fn(*const u8) -> u64 = unsafe { std::mem::transmute(il2cpp_init) };
    info!("Initializing il2cpp");

    il2cpp_init("IL2CPP Root Domain\0".as_ptr());
}
