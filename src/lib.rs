use region::Protection;

mod hooks;
mod relocs;

use log::*;

fn load_library(name: &str) -> anyhow::Result<libloading::Library> {
    unsafe {
        debug!("Loading library: {}", name);
        let library = libloading::Library::new(name)?;
        debug!("Library loaded: {}", name);
        Ok(library)
    }
}

#[derive(Debug)]
pub struct ElfFile {
    libraries: Vec<libloading::Library>,
    object: goblin::elf::Elf<'static>,
    bytes: &'static [u8],

    base: u64,
}

fn jmp(addr: usize) {
    debug!("Jumping to {:x}", addr);
    // transmute the address to a function pointer
    unsafe {
        let f: fn() = std::mem::transmute(addr);
        f();
    }
}

impl ElfFile {
    pub fn parse(path: &str) -> anyhow::Result<Self> {
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
            base: 0,
        })
    }

    fn find_symbol(&self, name: &str) -> anyhow::Result<u64> {
        // First try hook
        if let Some(func) = hooks::hook_symbol(name) {
            debug!("Hooked symbol: {}", name);
            return Ok(func as u64);
        }

        for lib in self.libraries.iter() {
            unsafe {
                if let Ok(symbol) = lib.get::<*const u8>(name.as_bytes()) {
                    if !symbol.is_null() {
                        return Ok(*symbol as u64);
                    }
                }
            }
        }

        debug!("WARN: Symbol {name} not found in libraries, trying current object");

        // Try to find the symbol in the current object
        for sym in self.object.dynsyms.iter() {
            let sym_name = sym.st_name;
            if let Some(sym_name) = self.object.dynstrtab.get_at(sym_name) {
                // Check if is global or weak and the name matches
                if sym_name == name
                    && (sym.st_bind() == goblin::elf::sym::STB_GLOBAL
                        || sym.st_bind() == goblin::elf::sym::STB_WEAK)
                {
                    return Ok(sym.st_value + self.base);
                }
            }
        }

        Err(anyhow::anyhow!("Symbol not found: {}", name))
    }

    fn relocate(&self) -> anyhow::Result<()> {
        // First, RELA
        for rela in self.object.dynrelas.iter() {
            match rela.r_type {
                goblin::elf::reloc::R_AARCH64_RELATIVE => {
                    let addr = self.base + rela.r_offset as u64;

                    let addend = rela.r_addend.unwrap() as u64;
                    let value = self.base + addend;
                    unsafe {
                        debug!(
                            "Relocating RELA at {:x} ({:x} + {:x}) to {:x} ({:x} + {:x})",
                            addr, self.base, rela.r_offset, value, self.base, addend
                        );
                        let ptr = addr as *mut u64;
                        *ptr = value;
                    }
                }
                goblin::elf::reloc::R_AARCH64_GLOB_DAT => {
                    let addr = self.base + rela.r_offset as u64;
                    let symbol = &self.object.dynsyms.get(rela.r_sym as usize).unwrap();
                    let name = &self.object.dynstrtab[symbol.st_name as usize];

                    if let Ok(symbol) = self.find_symbol(name) {
                        let value = symbol;
                        debug!(
                            "Relocating GLOB_DAT at {:x} ({}) to {:x} ({})",
                            addr, name, value, name
                        );
                        let ptr = addr as *mut u64;
                        unsafe {
                            *ptr = value;
                        }
                    } else {
                        debug!("Symbol not found: {}", name);
                    }
                }
                goblin::elf::reloc::R_AARCH64_ABS64 => {
                    let addr = self.base + rela.r_offset as u64;
                    let symbol = &self.object.dynsyms.get(rela.r_sym as usize).unwrap();
                    let name = &self.object.dynstrtab[symbol.st_name as usize];
                    if let Ok(symbol) = self.find_symbol(name) {
                        let value = symbol;
                        debug!(
                            "Relocating ABS64 at {:x} ({:x} + {:x}) to {:x} ({})",
                            addr, self.base, rela.r_offset, value, name
                        );
                        let ptr = addr as *mut u64;
                        unsafe {
                            *ptr = value;
                        }
                    } else {
                        debug!("Symbol not found: {}", name);
                    }
                }
                _ => {
                    dbg!(rela);
                    debug!("Unknown relocation type: {}", rela.r_type);
                }
            }
        }

        dbg!(self.object.pltrelocs.len());
        // Then JMPREL
        for rel in self.object.pltrelocs.iter() {
            match rel.r_type {
                goblin::elf::reloc::R_AARCH64_JUMP_SLOT => {
                    let addr = self.base + rel.r_offset as u64;
                    let symbol = &self.object.dynsyms.get(rel.r_sym as usize).unwrap();
                    let name = &self.object.dynstrtab[symbol.st_name as usize];

                    if let Ok(symbol) = self.find_symbol(name) {
                        let value = symbol;
                        debug!(
                            "Relocating JMP_SLOT at {:x} ({:x} + {:x}) to {:x} ({})",
                            addr, self.base, rel.r_offset, value, name
                        );
                        let ptr = addr as *mut u64;
                        unsafe {
                            *ptr = value;
                        }
                    } else {
                        debug!("Symbol not found: {}", name);
                    }
                }
                _ => {
                    debug!("Unknown relocation type: {}", rel.r_type);
                }
            }
        }

        Ok(())
    }

    fn relocate_custom(&self) -> anyhow::Result<()> {
        debug!("Custom relocations");

        let relocs = relocs::get_custom_relocs();

        for rel in relocs.iter() {
            match rel.r_type {
                goblin::elf::reloc::R_AARCH64_JUMP_SLOT => {
                    let addr = self.base + rel.r_offset as u64;
                    let symbol = self.find_symbol(&rel.r_sym)?;
                    debug!(
                        "Relocating JMP_SLOT at {:x} to {:x} ({})",
                        addr, symbol, rel.r_sym
                    );
                    let ptr = addr as *mut u64;
                    unsafe {
                        *ptr = symbol;
                    }
                }

                goblin::elf::reloc::R_AARCH64_RELATIVE => {
                    let addr = self.base + rel.r_offset as u64;
                    let addend = rel.r_addend as u64;
                    let old_value = unsafe { *(addr as *const u64) };

                    let value = if addend == 0 {
                        // Auto relative
                        if old_value > relocs::DUMP_BASE {
                            old_value - relocs::DUMP_BASE + self.base
                        } else {
                            old_value + self.base
                        }
                    } else {
                        addend + self.base
                    };

                    debug!(
                        "Relocating RELATIVE at {:x} to {:x} ({:x} + {:x})",
                        rel.r_offset,
                        value,
                        self.base,
                        value - self.base
                    );

                    unsafe {
                        let ptr = addr as *mut u64;
                        *ptr = value;
                    }
                }

                _ => {
                    panic!("Unknown relocation type: {}", rel.r_type);
                }
            }
        }

        Ok(())
    }

    /// Load the ELF file into memory
    pub fn load(&mut self) -> anyhow::Result<()> {
        // Calculate a good base
        let mut mem_start = u64::MAX;
        let mut mem_end = 0;

        let extra_bytes = 5 * 1024 * 1024;

        for seg in self.object.program_headers.iter() {
            if seg.p_type == goblin::elf::program_header::PT_LOAD {
                mem_start = std::cmp::min(mem_start, seg.p_vaddr & !0xfff);
                mem_end = std::cmp::max(mem_end, seg.p_vaddr + seg.p_memsz);
            }
        }

        mem_end += extra_bytes;

        // Allocate memory
        let size = (mem_end - mem_start) as usize & !0xfff;
        debug!("Allocating {} bytes", size);

        let mem_map = mmap::MemoryMap::new(size, &[])?;
        // Forget the memory map so it doesn't get unmapped

        let base = mem_map.data() as u64 - mem_start;

        debug!("Base address: {:x}", base);
        self.base = base;
        std::mem::forget(mem_map);

        // mmap the segments
        for seg in self.object.program_headers.iter() {
            if seg.p_type == goblin::elf::program_header::PT_LOAD {
                let addr = base + seg.p_vaddr as u64;
                let aligned_addr = addr & !0xfff; // align to page size

                let mut size = seg.p_memsz as usize;

                let file_size = seg.p_filesz as usize;
                let offset = seg.p_offset as usize;

                if offset != 0 {
                    // Patch: add three mb
                    size += extra_bytes as usize;
                }

                // Check if offset + file_size is beyond file length.
                let file_size = std::cmp::min(file_size, self.bytes.len() - offset);

                let size_with_align = size + (addr - aligned_addr) as usize;

                let data = &self.bytes[offset..offset + file_size];

                debug!(
                    "Mapping segment: addr={:x}, size={}, file_size={}, offset={}",
                    addr, size, file_size, offset
                );

                let mem_map = mmap::MemoryMap::new(
                    size_with_align,
                    &[
                        mmap::MapOption::MapReadable,
                        mmap::MapOption::MapWritable,
                        mmap::MapOption::MapExecutable,
                        mmap::MapOption::MapOffset(offset as _),
                    ],
                )?;
                std::mem::forget(mem_map);

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
                    debug!("Copying data to {:x}", addr);

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

        // before relocate, first process GOT
        relocs::process_got(base as *mut u8);

        relocs::process_rel_ro(base as *mut u8);
        relocs::process_data(base as *mut u8);

        self.relocate()?;
        self.relocate_custom()?;

        debug!("My pid: {}", std::process::id());

        // Call init_array
        // let dynamic = self.object.dynamic.as_ref().unwrap();
        //
        // let mut init_array_start = 0;
        // let mut init_array_size = 0;
        //
        // for entry in dynamic.dyns.iter() {
        //     if entry.d_tag == goblin::elf::dynamic::DT_INIT_ARRAY {
        //         init_array_start = entry.d_val;
        //     }
        //     if entry.d_tag == goblin::elf::dynamic::DT_INIT_ARRAYSZ {
        //         init_array_size = entry.d_val;
        //     }
        // }

        // Read the init_array
        // let mut init_array = Vec::new();
        // if init_array_start != 0 && init_array_size != 0 {
        //     let start = base + init_array_start as u64;
        //     let size = init_array_size as usize;
        //     let ptr = start as *const u64;
        //     for i in 0..size / 8 {
        //         let val = unsafe { *ptr.add(i) };
        //         init_array.push(val);
        //     }
        // }

        let init_array = vec![
            base + 0x00a6089c, // INIT 0
            base + 0x00a60914, // INIT 1
            base + 0x00a60b48, // INIT 2
            base + 0x00a60bfc, // INIT 3
            base + 0x00a60c3c, // INIT 4
            base + 0x00a60c78, // INIT 5
            base + 0x00a60cb4, // INIT 6
            base + 0x00a60d38, // INIT 7
            base + 0x00a60d9c, // INIT 8
            base + 0x00a60e44, // INIT 9
            base + 0x00a60ec0, // INIT 10
            base + 0x00a60f00, // INIT 11
            base + 0x00a60f40, // INIT 12
            base + 0x00a60ffc, // INIT 13
            base + 0x00a61078, // INIT 14
            base + 0x00a61180, // INIT 15
            base + 0x00a611bc, // INIT 16
            base + 0x00a6122c, // INIT 17
            base + 0x00a61268, // INIT 18
            base + 0x00a612bc, // INIT 19
            base + 0x00a6136c, // INIT 20
            base + 0x00a613a8, // INIT 21
            base + 0x00a613ec, // INIT 22
            base + 0x00a61504, // INIT 23
            base + 0x00a616c8, // INIT 24
            base + 0x00a616ec, // INIT 25
            base + 0x00a61740, // INIT 26
            base + 0x00a61764, // INIT 27
            base + 0x00a617c4, // INIT 28
            base + 0x00a61800, // INIT 29
            base + 0x00a61874, // INIT 30
            base + 0x00a61898, // INIT 31
            base + 0x00a61938, // INIT 32
            base + 0x00a61ad4, // INIT 33
            base + 0x00a619a0, // INIT 34
            base + 0x00a619d8, // INIT 35
            base + 0x00a619fc, // INIT 36
            base + 0x00a61a6c, // INIT 37
            base + 0x00a61aa8, // INIT 38
            base + 0x00a61af0, // INIT 39
            base + 0x00a61b08, // INIT 40
            base + 0x00a61b68, // INIT 41
            base + 0x00a61bb4, // INIT 42
            base + 0x00a61ca8, // INIT 43
        ];

        debug!("init_array has {} functions", init_array.len());

        for &func in init_array.iter() {
            if func != 0 {
                debug!("Calling init_array function at base + {:x}", func - base);

                jmp(func as usize);

                debug!("Function returned");
            }
        }

        // print!("Press enter to continue...");
        // std::io::stdout().flush()?;
        // let _ = std::io::stdin().read_line(&mut String::new());
        //
        // // Get the address of the entry point
        // jmp(base as usize + self.object.entry as usize);

        Ok(())
    }

    pub fn get_symbol(&self, name: &str) -> Option<u64> {
        for sym in self.object.dynsyms.iter() {
            let sym_name = sym.st_name;
            if let Some(sym_name) = self.object.dynstrtab.get_at(sym_name) {
                // Check if is global and the name matches
                if sym_name == name && sym.st_bind() == goblin::elf::sym::STB_GLOBAL {
                    return Some(sym.st_value + self.base);
                }
            }
        }
        None
    }
}
// ABIs: dlopen
//

const MAGIC: u32 = 0x114514;

static mut IL2CPP: Option<ElfFile> = None;

#[no_mangle]
pub unsafe extern "C" fn myopen(filename: *const u8, flags: i32) -> *mut libc::c_void {
    // First try init android logging
    android_logger::init_once(
        android_logger::Config::default()
            .with_tag("linkage")
            .with_max_level(log::LevelFilter::Trace),
    );

    let filename = unsafe { std::ffi::CStr::from_ptr(filename) };
    let filename = filename.to_str().unwrap();
    info!("Hook: dlopen({})", filename);

    // If filename endswith libil2cpp.so
    if filename.ends_with("libil2cpp.so") {
        info!("Found libil2cpp.so, using our loader");

        if let Some(elf) = IL2CPP.as_ref() {
            info!("Already loaded libil2cpp.so");
            return MAGIC as *mut libc::c_void;
        }

        let mut elf = ElfFile::parse(filename).unwrap();
        elf.load().unwrap();

        info!("Loaded libil2cpp.so");

        info!("Let's wait for debugger to attach");

        info!("My PID is {}", std::process::id());

        let mut flag = true;
        while flag {
            std::thread::sleep(std::time::Duration::from_secs(1));
        }

        IL2CPP = Some(elf);

        // Allocate a handle in heap

        MAGIC as *mut libc::c_void
    } else {
        libc::dlopen(filename.as_ptr(), flags)
    }
}

#[no_mangle]
pub unsafe extern "C" fn myclose(handle: *mut libc::c_void) -> libc::c_int {
    info!("Hook: dlclose");

    if handle == MAGIC as *mut libc::c_void {
        info!("Not going to close our handle");
        return 0;
    }

    libc::dlclose(handle)
}

#[no_mangle]
pub unsafe extern "C" fn mysym(handle: *mut libc::c_void, symbol: *const u8) -> *mut libc::c_void {
    let symbol = unsafe { std::ffi::CStr::from_ptr(symbol) };
    let symbol = symbol.to_str().unwrap();
    info!("My dlsym: {:?}", symbol);

    if handle == MAGIC as *mut libc::c_void {
        info!("Using our handle");

        let elf = IL2CPP.as_ref().unwrap();

        if let Some(addr) = elf.get_symbol(symbol) {
            info!("Symbol found: {:x}", addr);
            return addr as *mut libc::c_void;
        }
        warn!("Symbol not found: {}", symbol);
        return std::ptr::null_mut();
    }

    libc::dlsym(handle, symbol.as_ptr())
}
