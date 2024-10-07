use linkage::ElfFile;

fn main() {
    let path = std::env::args().nth(1).unwrap();

    let mut elf = ElfFile::parse(&path).unwrap();

    elf.load().unwrap();

    println!("===========================");
    println!("= ELF successfully loaded =");
    println!("===========================");

    let il2cpp_init = elf.get_symbol("il2cpp_init").unwrap();

    println!("il2cpp_init: {:x}", il2cpp_init);

    println!("Calling il2cpp_init(\"Hello, world!\")...");

    // jmp(il2cpp_init as usize);
    println!("Jumping to {:x}", il2cpp_init);

    // il2cpp_init takes string as argument
    let il2cpp_init: extern "C" fn(*const u8) -> u64 = unsafe { std::mem::transmute(il2cpp_init) };

    il2cpp_init("Hello, world!\0".as_ptr());

    println!("Function returned");

    println!("===========================");
    println!("=  il2cpp_init returned   =");
    println!("===========================");

    println!("Clearning up...");
}
