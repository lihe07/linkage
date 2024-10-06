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

macro_rules! RELATIVE {
    ($offset:expr, $addend:expr) => {
        MyReloc {
            r_offset: $offset,
            r_addend: $addend,
            r_sym: "".to_string(),
            r_type: goblin::elf::reloc::R_AARCH64_RELATIVE,
        }
    };
}

const DUMP_BASE: u64 = 0x7af10dc000;

pub fn process_got(base: *mut u8) {
    // .got is at base + 0x2ec0a70

    let got = base.wrapping_add(0x2ec0a70);
    let mut got = got as *mut u64;

    let first = unsafe { *got };

    // First should be 0x2ec0880
    println!("First: {:#x}", first);

    let got_end = base.wrapping_add(0x2f62e20);

    while got != got_end as *mut u64 {
        let addr = unsafe { *got };
        if addr == 0 {
            println!("Warning: NULL entry at {:#x}", got as u64);
            got = got.wrapping_add(1);
            continue;
        }

        let addr = addr.wrapping_sub(DUMP_BASE).wrapping_add(base as u64);

        unsafe {
            *got = addr;
        }

        got = got.wrapping_add(1);
    }

    unsafe {
        let elem = *(base.wrapping_add(0x2ecc440) as *const u64);
        dbg!(elem);
        println!("elem: {:#x}", elem);
    }
}

pub fn get_custom_relocs() -> Vec<MyReloc> {
    vec![
        JMP_SLOT!(0x2f63570, "_Znwm"),  // operator new
        JMP_SLOT!(0x2f62ff8, "_ZdlPv"), // operator delete
        JMP_SLOT!(0x2f63210, "pthread_mutexattr_init"),
        JMP_SLOT!(0x2f63848, "pthread_mutexattr_settype"),
        JMP_SLOT!(0x2f63970, "pthread_mutex_init"),
        JMP_SLOT!(0x2f639a0, "pthread_mutexattr_destroy"),
        JMP_SLOT!(0x2f636a8, "pthread_rwlock_init"),
        JMP_SLOT!(0x2f634c0, "pthread_key_create"),
        JMP_SLOT!(0x2f63690, "pthread_setspecific"),
        JMP_SLOT!(0x2f63368, "pthread_getspecific"),
        JMP_SLOT!(0x2f631b8, "pthread_condattr_init"),
        JMP_SLOT!(0x2f63930, "pthread_condattr_setclock"),
        JMP_SLOT!(0x2f63738, "pthread_cond_init"),
        JMP_SLOT!(0x2f63420, "pthread_condattr_destroy"),
        JMP_SLOT!(0x2f62f68, "pthread_mutex_lock"),
        JMP_SLOT!(0x2f63558, "pthread_mutex_destroy"),
        JMP_SLOT!(0x2f63480, "pthread_cond_destroy"),
        JMP_SLOT!(0x2f633e8, "pthread_mutex_unlock"),
        JMP_SLOT!(0x2f63350, "_Unwind_Resume"),
        JMP_SLOT!(0x2f62e48, "strlen"),
        JMP_SLOT!(0x2f633a0, "memcpy"),
        JMP_SLOT!(0x2f63358, "pow"),
        JMP_SLOT!(0x2f63360, "exit"),
        JMP_SLOT!(0x2f63370, "pthread_cond_broadcast"),
        JMP_SLOT!(0x2f63380, "fputs"),
        JMP_SLOT!(0x2f63388, "_Unwind_GetIPInfo"),
        JMP_SLOT!(0x2f63398, "recvmsg"),
        JMP_SLOT!(0x2f633a8, "pthread_attr_getstack"),
        JMP_SLOT!(0x2f633b8, "access"),
        JMP_SLOT!(0x2f633e0, "strstr"),
        JMP_SLOT!(0x2f633f8, "div"),
        JMP_SLOT!(0x2f63400, "sqrt"),
        JMP_SLOT!(0x2f63518, "setlocale"),
        // C++ Hell
        // std::_Rb_tree<void (*)(), void (*)(), std::_Identity<void (*)()>, std::less<void (*)()>, std::allocator<void (*)()> >::_M_insert_unique
        RELATIVE!(0x2f63208, 0x00ae4648),
        // std::_Rb_tree<void (*)(), void (*)(), std::_Identity<void (*)()>, std::less<void (*)()>, std::allocator<void (*)()> >::_M_get_insert_unique_pos
        RELATIVE!(0x2f633b0, 0x00ae4698),
        // std::_Rb_tree<void (*)(), void (*)(), std::_Identity<void (*)()>, std::less<void (*)()>, std::allocator<void (*)()> >::_M_insert_
        RELATIVE!(0x2f636a0, 0x00ae472c),
    ]
}
