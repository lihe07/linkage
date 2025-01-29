## linkage

A custom dynamic linker that attempts to load some specific memory dumps.

## Pre-requisites

Android NDK: r27 or later

Rust: nightly with target aarch64-linux-android

## Testing

With qiling framework:

```sh
make qiling
```

## Produce the bundle APK

1. Patch `libunity.so` to add a NEEDED entry for `liblinkage.so`

2. Patch `libunity.so` to replace dlopen, dlclose, dlsym with myopen, myclose, mysym in the dynamic symbol table

3. Add `liblinkage.so` to the APK

## Progress

- Resolved relocations: `.got.plt`

- Resolved `.init_array` functions (43/43)

- Resolved RELATIVE relocations: `.got`, `.data.rel.ro`, `.data`

- WIP: Resolved some JMP & ABS64 relocation outside of `.got.plt` section

## Contribute

Currently, some `ABS64` relocations in `.data.rel.ro` and `.data` sections need to be resolved.

To figure them out, you need to setup a native debugging environment. For example:

- `gdbserver` on Android + `gdb` on host
- IDA Debug Server on Android + IDA Pro

After starting debug server, connect to phone with ADB, then use this command to view the log:

```bash
adb logcat "*:S,linkage:D"
```

Launch the app, and it will automatically pause to wait for debuggers. Attach the debugger, then modify the regs to break out the `while` loop.

When you encounter an segfault, look at the backtrace and try to guess the appropriate relocation type.

Always refer to `./3.7_relocs_data.txt` and `./3.7_relocs_data_rel_ro.txt` to match the relocation type & symbol name.
