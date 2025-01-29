use region::Protection;

mod hooks;
mod relocs;

use log::*;

// On Linux 5.17+ PR_SET_VMA_ANON_NAME is available
unsafe fn set_vma_name(start: *mut libc::c_void, len: usize, name: &str) {
    let name = std::ffi::CString::new(name).unwrap();
    libc::prctl(
        libc::PR_SET_VMA,
        libc::PR_SET_VMA_ANON_NAME,
        start,
        len,
        name.as_ptr() as *const libc::c_void,
    );
}

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
    path: String,

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
            path: path.to_string(),
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

        // debug!("WARN: Symbol {name} not found in libraries, trying current object");

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
                        // debug!(
                        //     "Relocating RELA at {:x} ({:x} + {:x}) to {:x} ({:x} + {:x})",
                        //     addr, self.base, rela.r_offset, value, self.base, addend
                        // );
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
                    debug!("Unknown relocation type: {}", rela.r_type);
                }
            }
        }

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
                    // debug!(
                    //     "Relocating JMP_SLOT at {:x} to {:x} ({})",
                    //     addr, symbol, rel.r_sym
                    // );
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

    /// Map segments. Sets self.base
    unsafe fn map_segments(&mut self) -> anyhow::Result<()> {
        let total_size = 0x3323000;

        // 1. Map
        let total_map = libc::mmap(
            std::ptr::null_mut(),
            total_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        if total_map == libc::MAP_FAILED {
            return Err(anyhow::anyhow!("mmap failed"));
        }

        let c_path = std::ffi::CString::new(self.path.clone()).unwrap();
        let fd = libc::open(c_path.as_ptr() as *const libc::c_char, libc::O_RDONLY);
        if fd == -1 {
            return Err(anyhow::anyhow!("open failed"));
        }

        // 2. RX map
        libc::mmap(
            total_map,
            0x2c08000,
            libc::PROT_READ | libc::PROT_EXEC,
            libc::MAP_PRIVATE | libc::MAP_FIXED,
            fd,
            0,
        );

        // 3. GAP
        libc::mmap(
            (total_map as usize + 0x2c08000) as *mut libc::c_void,
            0x10000,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
            -1,
            0,
        );

        //  4. RW map
        libc::mmap(
            (total_map as usize + 0x2c18000) as *mut libc::c_void,
            0x483000,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_FIXED,
            fd,
            0x2c18000,
        );

        // 5. BSS
        let bss_map = libc::mmap(
            (total_map as usize + 0x309B000) as *mut libc::c_void,
            0x288000,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
            -1,
            0,
        );

        set_vma_name(bss_map, 0x288000, ".bss");

        // Close fd
        libc::close(fd);

        self.base = total_map as u64;

        Ok(())
    }

    /// Load the ELF file into memory
    pub fn load(&mut self) -> anyhow::Result<()> {
        // mmap the segments
        debug!("Mapping segments...");
        unsafe {
            self.map_segments()?;
        }
        debug!("Segments mapped. Base = {:x}", self.base);

        let base = self.base;
        // before relocate, first process GOT
        relocs::process_got(base as *mut u8);
        relocs::process_rel_ro(base as *mut u8);
        relocs::process_data(base as *mut u8);

        // self.relocate()?;
        self.relocate_custom()?;

        debug!("My pid: {}", std::process::id());

        // Call init_array
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

        if let Err(e) = elf.load() {
            error!("Error loading libil2cpp.so: {:?}", e);
            return std::ptr::null_mut();
        }

        info!("Loaded libil2cpp.so");

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
        info!("My dlsym: using our handle");

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
