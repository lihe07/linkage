fn patch(base: u64, offset: u64, patch: &[u8]) {
    let addr = base + offset;
    unsafe {
        let addr = addr as *mut u8;
        let patch_ptr = patch.as_ptr();
        std::ptr::copy_nonoverlapping(patch_ptr, addr, patch.len());
    }
}

pub fn apply_patches(base: u64) {
    let i64_neg1 = &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
    let i64_0 = &[0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0];
    let i64_1 = &[0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0];

    patch(base, 0x2f63fd0, i64_neg1);
    patch(base, 0x2f63fe8, i64_neg1);
    patch(base, 0x2f63ff0, i64_0);
    patch(base, 0x2f63ff8, i64_neg1);
    patch(base, 0x2f64000, i64_0);
    patch(base, 0x2f64020, i64_neg1);

    patch(base, 0x2f64050, i64_neg1);
    patch(base, 0x2f64058, i64_1);

    patch(base, 0x2f640a8, i64_neg1);
    patch(base, 0x2f640b0, &[0xFF, 0xFF, 0xFF, 0xFF]);
}
