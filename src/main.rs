use std::io::Write;

use region::Protection;

fn load_library(name: &str) -> anyhow::Result<libloading::Library> {
    unsafe {
        println!("Loading library: {}", name);
        let library = libloading::Library::new(name)?;
        println!("Library loaded: {}", name);
        Ok(library)
    }
}

#[derive(Debug)]
struct ElfFile {
    libraries: Vec<libloading::Library>,
    object: goblin::elf::Elf<'static>,
    bytes: &'static [u8],
}

fn jmp(addr: usize) {
    // transmute the address to a function pointer
    unsafe {
        let f: fn() = std::mem::transmute(addr);
        f();
    }
}

impl ElfFile {
    fn parse(path: &str) -> anyhow::Result<Self> {
        // Parse elf
        let bytes = std::fs::read(path)?.into_boxed_slice();
        let bytes_leaked = Box::leak(bytes);

        let file = goblin::Object::parse(&*bytes_leaked)?;

        let file = match file {
            goblin::Object::Elf(elf) => elf,
            _ => return Err(anyhow::anyhow!("Not an ELF file")),
        };

        // Parse dynamic section
        let mut libraries = Vec::new();
        for lib in file.libraries.iter() {
            let library = load_library(lib)?;
            libraries.push(library);
        }

        Ok(ElfFile {
            libraries,
            object: file,
            bytes: bytes_leaked,
        })
    }

    /// Load the ELF file into memory
    fn load(&self) -> anyhow::Result<()> {
        // Calculate a good base
        let mut mem_start = u64::MAX;
        let mut mem_end = 0;

        for seg in self.object.program_headers.iter() {
            if seg.p_type == goblin::elf::program_header::PT_LOAD {
                mem_start = std::cmp::min(mem_start, seg.p_vaddr & !0xfff);
                mem_end = std::cmp::max(mem_end, seg.p_vaddr + seg.p_memsz);
            }
        }

        // Allocate memory
        let size = (mem_end - mem_start) as usize & !0xfff;
        println!("Allocating {} bytes", size);

        let mem_map = mmap::MemoryMap::new(size, &[])?;
        // Forget the memory map so it doesn't get unmapped

        let base = mem_map.data() as u64 - mem_start;

        println!("Base address: {:x}", base);
        std::mem::forget(mem_map);

        // mmap the segments
        for seg in self.object.program_headers.iter() {
            if seg.p_type == goblin::elf::program_header::PT_LOAD {
                let addr = base + seg.p_vaddr as u64;
                let aligned_addr = addr & !0xfff; // align to page size

                let size = seg.p_memsz as usize;
                let size_with_align = size + (addr - aligned_addr) as usize;

                let file_size = seg.p_filesz as usize;
                let offset = seg.p_offset as usize;

                let data = &self.bytes[offset..offset + file_size];

                println!(
                    "Mapping segment: addr={:x}, size={}, file_size={}, offset={}",
                    addr, size, file_size, offset
                );

                // Adjust permission
                unsafe {
                    region::protect(
                        aligned_addr as *const u8,
                        size_with_align,
                        Protection::READ | Protection::WRITE | Protection::EXECUTE,
                    )?;
                }

                // Copy data to the mapped memory
                unsafe {
                    println!("Copying data to {:x}", addr);

                    std::ptr::copy(data.as_ptr(), addr as *mut u8, file_size);

                    // Fill the rest with zeros
                    if file_size < size {
                        std::ptr::write_bytes(
                            (addr + file_size as u64) as *mut u8,
                            0,
                            size - file_size,
                        );
                    }
                }
            }
        }

        println!("My pid: {}", std::process::id());

        print!("Press enter to continue...");
        std::io::stdout().flush()?;
        let _ = std::io::stdin().read_line(&mut String::new());

        // Get the address of the entry point
        jmp(base as usize + self.object.entry as usize);

        Ok(())
    }
}

fn main() {
    let path = std::env::args().nth(1).unwrap();

    let elf = ElfFile::parse(&path).unwrap();

    elf.load().unwrap();
}
