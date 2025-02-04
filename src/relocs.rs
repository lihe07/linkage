use log::{debug, warn};

// Include file ./heap_allocs.txt and ./relative_rels.txt

static HEAP_ALLOCS: &str = include_str!("./heap_allocs.txt");
static RELATIVE_RELS: &str = include_str!("./relative_rels.txt");

#[derive(Debug)]
pub struct MyReloc {
    pub r_offset: u64,
    pub r_addend: u64,
    pub r_sym: String,
    pub r_type: u32,
}

macro_rules! JMP_SLOT {
    ($offset:expr, $sym:expr) => {
        MyReloc {
            r_offset: $offset,
            r_addend: 0,
            r_sym: $sym.to_string(),
            r_type: goblin::elf::reloc::R_AARCH64_JUMP_SLOT,
        }
    };
}

pub const DUMP_BASE: u64 = 0x7af10dc000;

pub fn process_got(base: *mut u8) {
    // .got is at base + 0x2ec0a70

    let got = base.wrapping_add(0x2ec0a70);
    let mut got = got as *mut u64;

    let first = unsafe { *got };

    // First should be 0x2ec0880
    debug!("GOT First: {:#x}", first);

    got = got.wrapping_add(1); // Skip one

    let got_end = base.wrapping_add(0x2f62e20);

    let mut i = 0;
    while got != got_end as *mut u64 {
        let addr = unsafe { *got };

        if addr == 0 {
            // Skipping
            got = got.wrapping_add(1);
            continue;
        }

        if addr < DUMP_BASE || addr > DUMP_BASE + 0x3323000 {
            warn!(
                "Invalid address: {:#x} at BASE + {:#x}",
                addr,
                got as u64 - base as u64
            );
        }

        let addr = addr.wrapping_sub(DUMP_BASE).wrapping_add(base as u64);

        unsafe {
            *got = addr;
        }

        i += 1;
        got = got.wrapping_add(1);
    }

    debug!("Processed {} GOT elements", i);
}

pub fn process_rel_ro(base: *mut u8) {
    let rel_ro = base.wrapping_add(0x2c18188);
    let mut rel_ro = rel_ro as *mut u64;

    let rel_ro_end = base.wrapping_add(0x2ec0880);

    let mut i = 0;
    while rel_ro != rel_ro_end as *mut u64 {
        let addr = unsafe { *rel_ro };

        if addr < DUMP_BASE || addr > DUMP_BASE + 0x3323000 {
            // It's safe to skip them.
            rel_ro = rel_ro.wrapping_add(1);
            continue;
        }

        let addr = addr.wrapping_sub(DUMP_BASE).wrapping_add(base as u64);
        unsafe {
            *rel_ro = addr;
        }
        rel_ro = rel_ro.wrapping_add(1);
        i += 1;
    }
    debug!("Processed {} .data.rel.ro elements", i);
}

pub fn process_data(base: *mut u8) {
    let mut i = 0;

    // For each addr in HEAP_ALLOCS, set it to zero
    for line in HEAP_ALLOCS.lines() {
        // Parse hex offset
        let off = usize::from_str_radix(line, 16).unwrap();
        unsafe {
            *base.wrapping_add(off) = 0;
        }
        i += 1;
    }

    // For each addr in RELATIVE_RELS, compute relative addr
    for line in RELATIVE_RELS.lines() {
        // Parse hex offset
        let off = usize::from_str_radix(line, 16).unwrap();
        // Check if off is aligned with 8
        if off % 8 == 0 {
            let off = base.wrapping_add(off) as *mut u64;
            unsafe {
                let addr = *off;
                let addr = addr.wrapping_sub(DUMP_BASE).wrapping_add(base as u64);
                *off = addr;
            }
        } else {
            // So it is aligned with 4. Read two u32s
            let off = base.wrapping_add(off) as *mut u32;
            unsafe {
                let addr_low = *off;
                let addr_hi = *off.add(1);
                let addr = u64::from(addr_low) | (u64::from(addr_hi) << 32);
                let addr = addr.wrapping_sub(DUMP_BASE).wrapping_add(base as u64);
                let addr_low = addr as u32;
                let addr_hi = (addr >> 32) as u32;
                *off = addr_low;
                *(off.add(1)) = addr_hi;
            }
        }
        i += 1;
    }

    debug!("Processed {} .data elements", i);
}

pub fn get_custom_relocs() -> Vec<MyReloc> {
    vec![
        // ABS64 in GOT
        JMP_SLOT!(0x2ed3288, "__sF"),
        JMP_SLOT!(0x2eedce0, "_ctype_"),
        JMP_SLOT!(0x2f46f48, "pthread_create"),
        JMP_SLOT!(0x2f577e8, "environ"),

        // GOT.PLT
        JMP_SLOT!(0x2f62e40, "strtod"),
        JMP_SLOT!(0x2f62e48, "strlen"),
        JMP_SLOT!(0x2f62e50, "_ZNSt9bad_allocD1Ev"),
        JMP_SLOT!(0x2f62e58, "pthread_cond_timedwait"),
        JMP_SLOT!(0x2f62e60, "_ZNSt8_Rb_treeIPvSt4pairIKS0_lESt10_Select1stIS3_ESt4lessIS0_ESaIS3_EE24_M_get_insert_unique_posERS2_"),
        JMP_SLOT!(0x2f62e68, "_ZNSt8_Rb_treeISsSt4pairIKSsPFvvEESt10_Select1stIS4_ESt4lessISsESaIS4_EE8_M_eraseEPSt13_Rb_tree_nodeIS4_E"),
        JMP_SLOT!(0x2f62e70, "calloc"),
        JMP_SLOT!(0x2f62e78, "wctype"),
        JMP_SLOT!(0x2f62e80, "clock_gettime"),
        JMP_SLOT!(0x2f62e88, "_ZN10__cxxabiv119__foreign_exceptionD1Ev"),
        JMP_SLOT!(0x2f62e90, "poll"),
        JMP_SLOT!(0x2f62e98, "_ZN9__gnu_cxx20recursive_init_errorD1Ev"),
        JMP_SLOT!(0x2f62ea0, "pthread_sigmask"),
        JMP_SLOT!(0x2f62ea8, "_ZNSt8_Rb_treeISsSt4pairIKSsPFvvEESt10_Select1stIS4_ESt4lessISsESaIS4_EE10_M_insert_EPSt18_Rb_tree_node_baseSC_RKS4_"),
        JMP_SLOT!(0x2f62eb0, "sem_getvalue"),
        JMP_SLOT!(0x2f62eb8, "dlopen"),
        JMP_SLOT!(0x2f62ec0, "fclose"),
        JMP_SLOT!(0x2f62ec8, "wcsxfrm"),
        JMP_SLOT!(0x2f62ed0, "_ZNSt16bad_array_lengthD1Ev"),
        JMP_SLOT!(0x2f62ed8, "pthread_rwlock_rdlock"),
        JMP_SLOT!(0x2f62ee0, "powf"),
        JMP_SLOT!(0x2f62ee8, "_Unwind_Resume_or_Rethrow"),
        JMP_SLOT!(0x2f62ef0, "_ZSt9terminatev"),
        JMP_SLOT!(0x2f62ef8, "il2cpp_class_from_type"),
        JMP_SLOT!(0x2f62f00, "stat"),
        JMP_SLOT!(0x2f62f08, "unlink"),
        JMP_SLOT!(0x2f62f10, "il2cpp_string_new"),
        JMP_SLOT!(0x2f62f18, "wcscoll"),
        JMP_SLOT!(0x2f62f20, "__cxa_free_dependent_exception"),
        JMP_SLOT!(0x2f62f28, "free"),
        JMP_SLOT!(0x2f62f30, "getnameinfo"),
        JMP_SLOT!(0x2f62f38, "__register_frame_info_bases"),
        JMP_SLOT!(0x2f62f40, "_ZNSt9exceptionD2Ev"),
        JMP_SLOT!(0x2f62f48, "memchr"),
        JMP_SLOT!(0x2f62f50, "tcflush"),
        JMP_SLOT!(0x2f62f58, "_ZSt14__convert_to_vIfEvPKcRT_RSt12_Ios_IostateRKPi"),
        JMP_SLOT!(0x2f62f60, "dladdr"),
        JMP_SLOT!(0x2f62f68, "pthread_mutex_lock"),
        JMP_SLOT!(0x2f62f70, "isatty"),
        JMP_SLOT!(0x2f62f78, "il2cpp_shutdown"),
        JMP_SLOT!(0x2f62f80, "rmdir"),
        JMP_SLOT!(0x2f62f88, "select"),
        JMP_SLOT!(0x2f62f90, "time"),
        JMP_SLOT!(0x2f62f98, "pthread_rwlock_unlock"),
        JMP_SLOT!(0x2f62fa0, "_ZNSt8_Rb_treeISsSsSt9_IdentityISsESt4lessISsESaISsEE7_M_copyEPKSt13_Rb_tree_nodeISsEPS7_"),
        JMP_SLOT!(0x2f62fa8, "__cxa_atexit"),
        JMP_SLOT!(0x2f62fb0, "CreateZStream"),
        JMP_SLOT!(0x2f62fb8, "difftime"),
        JMP_SLOT!(0x2f62fc0, "_ZSt13get_terminatev"),
        JMP_SLOT!(0x2f62fc8, "strtold"),
        JMP_SLOT!(0x2f62fd0, "_ZNSt8_Rb_treeIPvS0_St9_IdentityIS0_ESt4lessIS0_ESaIS0_EE24_M_get_insert_unique_posERKS0_"),
        JMP_SLOT!(0x2f62fd8, "sched_yield"),
        JMP_SLOT!(0x2f62fe0, "syscall"),
        JMP_SLOT!(0x2f62fe8, "inet_pton"),
        JMP_SLOT!(0x2f62ff0, "_ZNSt6vectorISbItSt11char_traitsItESaItEESaIS3_EE14_M_fill_insertEN9__gnu_cxx17__normal_iteratorIPS3_S5_EEmRKS3_"),
        JMP_SLOT!(0x2f62ff8, "_ZdlPv"),
        JMP_SLOT!(0x2f63000, "pthread_atfork"),
        JMP_SLOT!(0x2f63008, "_ZN10__cxxabiv117__class_type_infoD2Ev"),
        JMP_SLOT!(0x2f63010, "__cxa_guard_acquire"),
        JMP_SLOT!(0x2f63018, "_Unwind_GetRegionStart"),
        JMP_SLOT!(0x2f63020, "recvfrom"),
        JMP_SLOT!(0x2f63028, "_ZNKSbItSt11char_traitsItESaItEE7compareEPKt"),
        JMP_SLOT!(0x2f63030, "_Unwind_SetGR"),
        JMP_SLOT!(0x2f63038, "readdir"),
        JMP_SLOT!(0x2f63040, "_ZNSt15__exception_ptreqERKNS_13exception_ptrES2_"),
        JMP_SLOT!(0x2f63048, "__errno"),
        JMP_SLOT!(0x2f63050, "_ZSt15get_new_handlerv"),
        JMP_SLOT!(0x2f63058, "memmove"),
        JMP_SLOT!(0x2f63060, "fmod"),
        JMP_SLOT!(0x2f63068, "_ZNSt15__exception_ptr13exception_ptrC1Ev"),
        JMP_SLOT!(0x2f63070, "_Unwind_Find_FDE"),
        JMP_SLOT!(0x2f63078, "localtime"),
        JMP_SLOT!(0x2f63080, "_ZNSt8_Rb_treeIPvSt4pairIKS0_lESt10_Select1stIS3_ESt4lessIS0_ESaIS3_EE17_M_insert_unique_ESt23_Rb_tree_const_iteratorIS3_ERKS3_"),
        JMP_SLOT!(0x2f63088, "mmap"),
        JMP_SLOT!(0x2f63090, "send"),
        JMP_SLOT!(0x2f63098, "accept"),
        JMP_SLOT!(0x2f630a0, "il2cpp_method_get_object"),
        JMP_SLOT!(0x2f630a8, "__google_potentially_blocking_region_end"),
        JMP_SLOT!(0x2f630b0, "__cxa_allocate_exception"),
        JMP_SLOT!(0x2f630b8, "pthread_attr_init"),
        JMP_SLOT!(0x2f630c0, "open"),
        JMP_SLOT!(0x2f630c8, "bsearch"),
        JMP_SLOT!(0x2f630d0, "dup2"),
        JMP_SLOT!(0x2f630d8, "_ZNSt6vectorISsSaISsEEaSERKS1_"),
        JMP_SLOT!(0x2f630e0, "_ZN10__cxxabiv117__class_type_infoD1Ev"),
        JMP_SLOT!(0x2f630e8, "gettimeofday"),
        JMP_SLOT!(0x2f630f0, "modf"),
        JMP_SLOT!(0x2f630f8, "ReadZStream"),
        JMP_SLOT!(0x2f63100, "strlcpy"),
        JMP_SLOT!(0x2f63108, "_ZdaPv"),
        JMP_SLOT!(0x2f63110, "towlower"),
        JMP_SLOT!(0x2f63118, "atol"),
        JMP_SLOT!(0x2f63120, "fmodf"),
        JMP_SLOT!(0x2f63128, "mktime"),
        JMP_SLOT!(0x2f63130, "strftime"),
        JMP_SLOT!(0x2f63138, "gethostname"),
        JMP_SLOT!(0x2f63140, "__cxa_guard_abort"),
        JMP_SLOT!(0x2f63148, "_ZNSbItSt11char_traitsItESaItEEC2ERKS2_"),
        JMP_SLOT!(0x2f63150, "unsetenv"),
        JMP_SLOT!(0x2f63158, "ldexp"),
        JMP_SLOT!(0x2f63160, "memalign"),
        JMP_SLOT!(0x2f63168, "log10"),
        JMP_SLOT!(0x2f63170, "vsnprintf"),
        JMP_SLOT!(0x2f63178, "_ZNSt15__exception_ptr13exception_ptr10_M_releaseEv"),
        JMP_SLOT!(0x2f63180, "opendir"),
        JMP_SLOT!(0x2f63188, "pthread_cond_wait"),
        JMP_SLOT!(0x2f63190, "connect"),
        JMP_SLOT!(0x2f63198, "sysconf"),
        JMP_SLOT!(0x2f631a0, "sigaddset"),
        JMP_SLOT!(0x2f631a8, "il2cpp_array_new"),
        JMP_SLOT!(0x2f631b0, "_ZNSt8_Rb_treeIPvSt4pairIKS0_lESt10_Select1stIS3_ESt4lessIS0_ESaIS3_EE29_M_get_insert_hint_unique_posESt23_Rb_tree_const_iteratorIS3_ERS2_"),
        JMP_SLOT!(0x2f631b8, "pthread_condattr_init"),
        JMP_SLOT!(0x2f631c0, "pthread_self"),
        JMP_SLOT!(0x2f631c8, "tcgetattr"),
        JMP_SLOT!(0x2f631d0, "__gttf2"),
        JMP_SLOT!(0x2f631d8, "_ZSt10unexpectedv"),
        JMP_SLOT!(0x2f631e0, "_Unwind_DeleteException"),
        JMP_SLOT!(0x2f631e8, "_ZNK10__cxxabiv117__class_type_info11__do_upcastEPKS0_PKvRNS0_15__upcast_resultE"),
        JMP_SLOT!(0x2f631f0, "_ZNSt8_Rb_treeISsSt4pairIKSsPFvvEESt10_Select1stIS4_ESt4lessISsESaIS4_EE24_M_get_insert_unique_posERS1_"),
        JMP_SLOT!(0x2f631f8, "iswctype"),
        JMP_SLOT!(0x2f63200, "__register_frame_info"),
        JMP_SLOT!(0x2f63208, "_ZNSt8_Rb_treeIPFvvES1_St9_IdentityIS1_ESt4lessIS1_ESaIS1_EE16_M_insert_uniqueERKS1_"),
        JMP_SLOT!(0x2f63210, "pthread_mutexattr_init"),
        JMP_SLOT!(0x2f63218, "atan2"),
        JMP_SLOT!(0x2f63220, "wcrtomb"),
        JMP_SLOT!(0x2f63228, "__cxa_demangle"),
        JMP_SLOT!(0x2f63230, "pthread_rwlock_wrlock"),
        JMP_SLOT!(0x2f63238, "isalpha"),
        JMP_SLOT!(0x2f63240, "__cxa_finalize"),
        JMP_SLOT!(0x2f63248, "pthread_rwlock_destroy"),
        JMP_SLOT!(0x2f63250, "acos"),
        JMP_SLOT!(0x2f63258, "_ZNSt8_Rb_treeISsSsSt9_IdentityISsESt4lessISsESaISsEE8_M_eraseEPSt13_Rb_tree_nodeISsE"),
        JMP_SLOT!(0x2f63260, "_ZNSt6vectorIiSaIiEEaSERKS1_"),
        JMP_SLOT!(0x2f63268, "gmtime"),
        JMP_SLOT!(0x2f63270, "_ZNSbItSt11char_traitsItESaItEE4_Rep8_M_cloneERKS1_m"),
        JMP_SLOT!(0x2f63278, "sin"),
        JMP_SLOT!(0x2f63280, "__deregister_frame_info_bases"),
        JMP_SLOT!(0x2f63288, "readlink"),
        JMP_SLOT!(0x2f63290, "_ZSt14get_unexpectedv"),
        JMP_SLOT!(0x2f63298, "wcslen"),
        JMP_SLOT!(0x2f632a0, "pthread_detach"),
        JMP_SLOT!(0x2f632a8, "__cxa_rethrow"),
        JMP_SLOT!(0x2f632b0, "_ZNSbItSt11char_traitsItESaItEE4_Rep9_S_createEmmRKS1_"),
        JMP_SLOT!(0x2f632b8, "il2cpp_array_element_size"),
        JMP_SLOT!(0x2f632c0, "btowc"),
        JMP_SLOT!(0x2f632c8, "sem_post"),
        JMP_SLOT!(0x2f632d0, "fileno"),
        JMP_SLOT!(0x2f632d8, "uname"),
        JMP_SLOT!(0x2f632e0, "_ZNSt8bad_castD1Ev"),
        JMP_SLOT!(0x2f632e8, "pthread_getattr_np"),
        JMP_SLOT!(0x2f632f0, "log10f"),
        JMP_SLOT!(0x2f632f8, "__cxa_allocate_dependent_exception"),
        JMP_SLOT!(0x2f63300, "_ZNSt6vectorImSaImEE14_M_fill_insertEN9__gnu_cxx17__normal_iteratorIPmS1_EEmRKm"),
        JMP_SLOT!(0x2f63308, "bind"),
        JMP_SLOT!(0x2f63310, "_ZNSt15__exception_ptr13exception_ptrC1EPv"),
        JMP_SLOT!(0x2f63318, "strerror"),
        JMP_SLOT!(0x2f63320, "ftruncate"),
        JMP_SLOT!(0x2f63328, "usleep"),
        JMP_SLOT!(0x2f63330, "Flush"),
        JMP_SLOT!(0x2f63338, "_ZNSt8_Rb_treeISsSt4pairIKSsPFvvEESt10_Select1stIS4_ESt4lessISsESaIS4_EE17_M_insert_unique_ESt23_Rb_tree_const_iteratorIS4_ERKS4_"),
        JMP_SLOT!(0x2f63340, "il2cpp_object_unbox"),
        JMP_SLOT!(0x2f63348, "_ZNKSt15__exception_ptr13exception_ptr6_M_getEv"),
        JMP_SLOT!(0x2f63350, "_Unwind_Resume"),
        JMP_SLOT!(0x2f63358, "pow"),
        JMP_SLOT!(0x2f63360, "exit"),
        JMP_SLOT!(0x2f63368, "pthread_getspecific"),
        JMP_SLOT!(0x2f63370, "pthread_cond_broadcast"),
        JMP_SLOT!(0x2f63378, "_ZNSbItSt11char_traitsItESaItEE6assignERKS2_"),
        JMP_SLOT!(0x2f63380, "fputs"),
        JMP_SLOT!(0x2f63388, "_Unwind_GetIPInfo"),
        JMP_SLOT!(0x2f63390, "_ZNSt6vectorIiSaIiEE13_M_insert_auxEN9__gnu_cxx17__normal_iteratorIPiS1_EERKi"),
        JMP_SLOT!(0x2f63398, "recvmsg"),
        JMP_SLOT!(0x2f633a0, "memcpy"),
        JMP_SLOT!(0x2f633a8, "pthread_attr_getstack"),
        JMP_SLOT!(0x2f633b0, "_ZNSt8_Rb_treeIPFvvES1_St9_IdentityIS1_ESt4lessIS1_ESaIS1_EE24_M_get_insert_unique_posERKS1_"),
        JMP_SLOT!(0x2f633b8, "access"),
        JMP_SLOT!(0x2f633c0, "il2cpp_array_length"),
        JMP_SLOT!(0x2f633c8, "_Unwind_GetLanguageSpecificData"),
        JMP_SLOT!(0x2f633d0, "__google_potentially_blocking_region_begin"),
        JMP_SLOT!(0x2f633d8, "__cxa_end_catch"),
        JMP_SLOT!(0x2f633e0, "strstr"),
        JMP_SLOT!(0x2f633e8, "pthread_mutex_unlock"),
        JMP_SLOT!(0x2f633f0, "_ZNSbItSt11char_traitsItESaItEE15_M_replace_safeEmmPKtm"),
        JMP_SLOT!(0x2f633f8, "div"),
        JMP_SLOT!(0x2f63400, "sqrt"),
        JMP_SLOT!(0x2f63408, "_ZNSbItSt11char_traitsItESaItEE6assignEPKtm"),
        JMP_SLOT!(0x2f63410, "il2cpp_monitor_exit"),
        JMP_SLOT!(0x2f63418, "wctob"),
        JMP_SLOT!(0x2f63420, "pthread_condattr_destroy"),
        JMP_SLOT!(0x2f63428, "__divdc3"),
        JMP_SLOT!(0x2f63430, "_ZN10__cxxabiv115__forced_unwindD1Ev"),
        JMP_SLOT!(0x2f63438, "_ZNSt20bad_array_new_lengthD1Ev"),
        JMP_SLOT!(0x2f63440, "strcoll"),
        JMP_SLOT!(0x2f63448, "_Unwind_GetTextRelBase"),
        JMP_SLOT!(0x2f63450, "atan"),
        JMP_SLOT!(0x2f63458, "_ZNSt13bad_exceptionD1Ev"),
        JMP_SLOT!(0x2f63460, "getcwd"),
        JMP_SLOT!(0x2f63468, "dlclose"),
        JMP_SLOT!(0x2f63470, "sigfillset"),
        JMP_SLOT!(0x2f63478, "__register_frame_info_table"),
        JMP_SLOT!(0x2f63480, "pthread_cond_destroy"),
        JMP_SLOT!(0x2f63488, "_ZNSt8_Rb_treeISsSt4pairIKSsPFvvEESt10_Select1stIS4_ESt4lessISsESaIS4_EE29_M_get_insert_hint_unique_posESt23_Rb_tree_const_iteratorIS4_ERS1_"),
        JMP_SLOT!(0x2f63490, "strcmp"),
        JMP_SLOT!(0x2f63498, "sigemptyset"),
        JMP_SLOT!(0x2f634a0, "_ZNSt6vectorImSaImEE13_M_insert_auxEN9__gnu_cxx17__normal_iteratorIPmS1_EERKm"),
        JMP_SLOT!(0x2f634a8, "_ZNSt8_Rb_treeISsSsSt9_IdentityISsESt4lessISsESaISsEE10_M_insert_EPSt18_Rb_tree_node_baseS7_RKSs"),
        JMP_SLOT!(0x2f634b0, "_ZNSt15__exception_ptr13exception_ptrC1ERKS0_"),
        JMP_SLOT!(0x2f634b8, "realloc"),
        JMP_SLOT!(0x2f634c0, "pthread_key_create"),
        JMP_SLOT!(0x2f634c8, "cos"),
        JMP_SLOT!(0x2f634d0, "__cxa_call_unexpected"),
        JMP_SLOT!(0x2f634d8, "__cxa_bad_cast"),
        JMP_SLOT!(0x2f634e0, "_ZNSt8_Rb_treeIPvSt4pairIKS0_lESt10_Select1stIS3_ESt4lessIS0_ESaIS3_EE8_M_eraseEPSt13_Rb_tree_nodeIS3_E"),
        JMP_SLOT!(0x2f634e8, "nanosleep"),
        JMP_SLOT!(0x2f634f0, "__android_log_print"),
        JMP_SLOT!(0x2f634f8, "_ZNSbItSt11char_traitsItESaItEE9_M_mutateEmmm"),
        JMP_SLOT!(0x2f63500, "tcsetattr"),
        JMP_SLOT!(0x2f63508, "pthread_once"),
        JMP_SLOT!(0x2f63510, "memset"),
        JMP_SLOT!(0x2f63518, "setlocale"),
        JMP_SLOT!(0x2f63520, "clock"),
        JMP_SLOT!(0x2f63528, "pipe"),
        JMP_SLOT!(0x2f63530, "_ZN10__cxxabiv120__si_class_type_infoD1Ev"),
        JMP_SLOT!(0x2f63538, "tolower"),
        JMP_SLOT!(0x2f63540, "setsockopt"),
        JMP_SLOT!(0x2f63548, "_Unwind_Backtrace"),
        JMP_SLOT!(0x2f63550, "socket"),
        JMP_SLOT!(0x2f63558, "pthread_mutex_destroy"),
        JMP_SLOT!(0x2f63560, "dup"),
        JMP_SLOT!(0x2f63568, "_ZNSt8_Rb_treeISsSt4pairIKSsPFvvEESt10_Select1stIS4_ESt4lessISsESaIS4_EE4findERS1_"),
        JMP_SLOT!(0x2f63570, "_Znwm"),
        JMP_SLOT!(0x2f63578, "clock_getres"),
        JMP_SLOT!(0x2f63580, "_ZNSt9bad_allocD2Ev"),
        JMP_SLOT!(0x2f63588, "wmemchr"),
        JMP_SLOT!(0x2f63590, "getpid"),
        JMP_SLOT!(0x2f63598, "strncpy"),
        JMP_SLOT!(0x2f635a0, "__register_frame_info_table_bases"),
        JMP_SLOT!(0x2f635a8, "strcpy"),
        JMP_SLOT!(0x2f635b0, "getenv"),
        JMP_SLOT!(0x2f635b8, "__deregister_frame_info"),
        JMP_SLOT!(0x2f635c0, "sendmsg"),
        JMP_SLOT!(0x2f635c8, "_ZNSt9exceptionD1Ev"),
        JMP_SLOT!(0x2f635d0, "strtol"),
        JMP_SLOT!(0x2f635d8, "_ZNSbItSt11char_traitsItESaItEE6appendEPKtm"),
        JMP_SLOT!(0x2f635e0, "exp2f"),
        JMP_SLOT!(0x2f635e8, "CloseZStream"),
        JMP_SLOT!(0x2f635f0, "_Unwind_SetIP"),
        JMP_SLOT!(0x2f635f8, "il2cpp_bounded_array_class_get"),
        JMP_SLOT!(0x2f63600, "ioctl"),
        JMP_SLOT!(0x2f63608, "_ZNSs12_S_constructIN9__gnu_cxx17__normal_iteratorIPKcSsEEEEPcT_S6_RKSaIcESt20forward_iterator_tag"),
        JMP_SLOT!(0x2f63610, "_Unwind_GetDataRelBase"),
        JMP_SLOT!(0x2f63618, "__cxa_free_exception"),
        JMP_SLOT!(0x2f63620, "_Unwind_RaiseException"),
        JMP_SLOT!(0x2f63628, "exp2"),
        JMP_SLOT!(0x2f63630, "abort"),
        JMP_SLOT!(0x2f63638, "close"),
        JMP_SLOT!(0x2f63640, "__cxa_get_globals_fast"),
        JMP_SLOT!(0x2f63648, "_ZNSt8_Rb_treeIPvS0_St9_IdentityIS0_ESt4lessIS0_ESaIS0_EE10_M_insert_EPSt18_Rb_tree_node_baseS8_RKS0_"),
        JMP_SLOT!(0x2f63650, "WriteZStream"),
        JMP_SLOT!(0x2f63658, "atan2f"),
        JMP_SLOT!(0x2f63660, "mkdir"),
        JMP_SLOT!(0x2f63668, "_Znam"),
        JMP_SLOT!(0x2f63670, "fputc"),
        JMP_SLOT!(0x2f63678, "il2cpp_array_new_specific"),
        JMP_SLOT!(0x2f63680, "read"),
        JMP_SLOT!(0x2f63688, "__cxa_throw"),
        JMP_SLOT!(0x2f63690, "pthread_setspecific"),
        JMP_SLOT!(0x2f63698, "strchr"),
        JMP_SLOT!(0x2f636a0, "_ZNSt8_Rb_treeIPFvvES1_St9_IdentityIS1_ESt4lessIS1_ESaIS1_EE10_M_insert_EPSt18_Rb_tree_node_baseS9_RKS1_"),
        JMP_SLOT!(0x2f636a8, "pthread_rwlock_init"),
        JMP_SLOT!(0x2f636b0, "_ZNSt6vectorISsSaISsEE13_M_insert_auxEN9__gnu_cxx17__normal_iteratorIPSsS1_EERKSs"),
        JMP_SLOT!(0x2f636b8, "getaddrinfo"),
        JMP_SLOT!(0x2f636c0, "asin"),
        JMP_SLOT!(0x2f636c8, "_Unwind_GetCFA"),
        JMP_SLOT!(0x2f636d0, "lstat"),
        JMP_SLOT!(0x2f636d8, "_ZN10__cxxabiv111__terminateEPFvvE"),
        JMP_SLOT!(0x2f636e0, "_ZNSt15__exception_ptr13exception_ptr4swapERS0_"),
        JMP_SLOT!(0x2f636e8, "_ZNSbItSt11char_traitsItESaItEE7reserveEm"),
        JMP_SLOT!(0x2f636f0, "_ZNSs12_S_constructIN9__gnu_cxx17__normal_iteratorIPcSt6vectorIcSaIcEEEEEES2_T_S7_RKS4_St20forward_iterator_tag"),
        JMP_SLOT!(0x2f636f8, "acosf"),
        JMP_SLOT!(0x2f63700, "fopen"),
        JMP_SLOT!(0x2f63708, "dlsym"),
        JMP_SLOT!(0x2f63710, "getsockname"),
        JMP_SLOT!(0x2f63718, "listen"),
        JMP_SLOT!(0x2f63720, "writev"),
        JMP_SLOT!(0x2f63728, "_ZNSt10bad_typeidD1Ev"),
        JMP_SLOT!(0x2f63730, "il2cpp_class_from_il2cpp_type"),
        JMP_SLOT!(0x2f63738, "pthread_cond_init"),
        JMP_SLOT!(0x2f63740, "_ZSt14__convert_to_vIdEvPKcRT_RSt12_Ios_IostateRKPi"),
        JMP_SLOT!(0x2f63748, "memcmp"),
        JMP_SLOT!(0x2f63750, "signal"),
        JMP_SLOT!(0x2f63758, "_ZNSt8_Rb_treeIPvSt4pairIKS0_lESt10_Select1stIS3_ESt4lessIS0_ESaIS3_EE10_M_insert_EPSt18_Rb_tree_node_baseSB_RKS3_"),
        JMP_SLOT!(0x2f63760, "sem_init"),
        JMP_SLOT!(0x2f63768, "strtof"),
        JMP_SLOT!(0x2f63770, "strxfrm"),
        JMP_SLOT!(0x2f63778, "__cxa_begin_catch"),
        JMP_SLOT!(0x2f63780, "atoi"),
        JMP_SLOT!(0x2f63788, "mprotect"),
        JMP_SLOT!(0x2f63790, "wcsftime"),
        JMP_SLOT!(0x2f63798, "pthread_create"),
        JMP_SLOT!(0x2f637a0, "wmemmove"),
        JMP_SLOT!(0x2f637a8, "__system_property_get"),
        JMP_SLOT!(0x2f637b0, "_ZNSt8_Rb_treeISsSsSt9_IdentityISsESt4lessISsESaISsEE24_M_get_insert_unique_posERKSs"),
        JMP_SLOT!(0x2f637b8, "__sfp_handle_exceptions"),
        JMP_SLOT!(0x2f637c0, "malloc"),
        JMP_SLOT!(0x2f637c8, "munmap"),
        JMP_SLOT!(0x2f637d0, "il2cpp_raise_exception"),
        JMP_SLOT!(0x2f637d8, "wmemcpy"),
        JMP_SLOT!(0x2f637e0, "_ZN10__cxxabiv112__unexpectedEPFvvE"),
        JMP_SLOT!(0x2f637e8, "sigsuspend"),
        JMP_SLOT!(0x2f637f0, "isspace"),
        JMP_SLOT!(0x2f637f8, "mbrtowc"),
        JMP_SLOT!(0x2f63800, "fstat"),
        JMP_SLOT!(0x2f63808, "pthread_key_delete"),
        JMP_SLOT!(0x2f63810, "lseek"),
        JMP_SLOT!(0x2f63818, "strncmp"),
        JMP_SLOT!(0x2f63820, "sinf"),
        JMP_SLOT!(0x2f63828, "_ZSt14__convert_to_vIeEvPKcRT_RSt12_Ios_IostateRKPi"),
        JMP_SLOT!(0x2f63830, "vsprintf"),
        JMP_SLOT!(0x2f63838, "freeaddrinfo"),
        JMP_SLOT!(0x2f63840, "pthread_attr_destroy"),
        JMP_SLOT!(0x2f63848, "pthread_mutexattr_settype"),
        JMP_SLOT!(0x2f63850, "_Unwind_GetIP"),
        JMP_SLOT!(0x2f63858, "sigaction"),
        JMP_SLOT!(0x2f63860, "strtoul"),
        JMP_SLOT!(0x2f63868, "dl_iterate_phdr"),
        JMP_SLOT!(0x2f63870, "fwrite"),
        JMP_SLOT!(0x2f63878, "getsockopt"),
        JMP_SLOT!(0x2f63880, "__lttf2"),
        JMP_SLOT!(0x2f63888, "fcntl"),
        JMP_SLOT!(0x2f63890, "il2cpp_object_new"),
        JMP_SLOT!(0x2f63898, "sem_wait"),
        JMP_SLOT!(0x2f638a0, "setjmp"),
        JMP_SLOT!(0x2f638a8, "_ZN10__cxxabiv121__vmi_class_type_infoD1Ev"),
        JMP_SLOT!(0x2f638b0, "_ZNSt8_Rb_treeIPvS0_St9_IdentityIS0_ESt4lessIS0_ESaIS0_EE8_M_eraseEPSt13_Rb_tree_nodeIS0_E"),
        JMP_SLOT!(0x2f638b8, "_ZNSt8_Rb_treeIPvS0_St9_IdentityIS0_ESt4lessIS0_ESaIS0_EE16_M_insert_uniqueERKS0_"),
        JMP_SLOT!(0x2f638c0, "inet_ntop"),
        JMP_SLOT!(0x2f638c8, "il2cpp_monitor_enter"),
        JMP_SLOT!(0x2f638d0, "atanf"),
        JMP_SLOT!(0x2f638d8, "__cxa_get_globals"),
        JMP_SLOT!(0x2f638e0, "pthread_kill"),
        JMP_SLOT!(0x2f638e8, "sprintf"),
        JMP_SLOT!(0x2f638f0, "sigdelset"),
        JMP_SLOT!(0x2f638f8, "write"),
        JMP_SLOT!(0x2f63900, "pthread_cond_signal"),
        JMP_SLOT!(0x2f63908, "__cxa_current_exception_type"),
        JMP_SLOT!(0x2f63910, "_ZNSt15__exception_ptr13exception_ptrD1Ev"),
        JMP_SLOT!(0x2f63918, "setenv"),
        JMP_SLOT!(0x2f63920, "il2cpp_array_class_get"),
        JMP_SLOT!(0x2f63928, "sqrtf"),
        JMP_SLOT!(0x2f63930, "pthread_condattr_setclock"),
        JMP_SLOT!(0x2f63938, "wmemset"),
        JMP_SLOT!(0x2f63940, "__ctype_get_mb_cur_max"),
        JMP_SLOT!(0x2f63948, "_ZNSt15__exception_ptr13exception_ptr9_M_addrefEv"),
        JMP_SLOT!(0x2f63950, "_ZSt18uncaught_exceptionv"),
        JMP_SLOT!(0x2f63958, "__dynamic_cast"),
        JMP_SLOT!(0x2f63960, "__cxa_guard_release"),
        JMP_SLOT!(0x2f63968, "shutdown"),
        JMP_SLOT!(0x2f63970, "pthread_mutex_init"),
        JMP_SLOT!(0x2f63978, "il2cpp_gc_wbarrier_set_field"),
        JMP_SLOT!(0x2f63980, "strrchr"),
        JMP_SLOT!(0x2f63988, "towupper"),
        JMP_SLOT!(0x2f63990, "cosf"),
        JMP_SLOT!(0x2f63998, "log"),
        JMP_SLOT!(0x2f639a0, "pthread_mutexattr_destroy"),
        JMP_SLOT!(0x2f639a8, "closedir"),

        // Floating
        JMP_SLOT!(0x2f64068, "malloc"),
        JMP_SLOT!(0x2f64078, "free"),
        JMP_SLOT!(0x2f64088, "calloc"),
        JMP_SLOT!(0x2f64090, "realloc"),
    ]
}
