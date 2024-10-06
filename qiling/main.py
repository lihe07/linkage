from qiling import *
from qiling.const import *
from qiling.os.const import *

import os

os.system("cp ./linkage ./arm64_android6.0/linkage")

OVERRIDES = {"mmap_address": 0x68000000}

env = {"ANDROID_DATA": r"/data", "ANDROID_ROOT": r"/system", "LD_DEBUG": "all"}

q = Qiling(
    ["./arm64_android6.0/linkage", "/libil2cpp.so"],
    "./arm64_android6.0/",
    env=env,
    profile={"OS64": OVERRIDES},
    multithread=True,
    verbose=QL_VERBOSE.DISABLED,
)

# hook write syscall


def my_syscall_write(ql: Qiling, fd: int, buf: int, count: int) -> int:
    try:
        # read data from emulated memory
        data = ql.mem.read(buf, count)

        # select the emulated file object that corresponds to the requested
        # file descriptor
        fobj = ql.os.fd[fd]

        # write the data into the file object, if it supports write operations
        if hasattr(fobj, "write"):
            fobj.write(data)

        if data.startswith(b"Jumping to"):
            print("=====")
            ql.verbose = QL_VERBOSE.DEBUG
        if data.startswith(b"Function returned"):
            ql.verbose = QL_VERBOSE.DISABLED
    except:
        ret = -1
    else:
        ret = count

    # return a value to the caller
    return ret


q.os.set_syscall("write", my_syscall_write, QL_INTERCEPT.CALL)


def LibraryNamePrefixAndSuffix(ql: Qiling, *args) -> None:
    # get the three arguments
    arg0 = ql.arch.regs.x0
    arg1 = ql.arch.regs.x1
    arg2 = ql.arch.regs.x2
    print("==============")
    print(f"arg0: {arg0}")
    print(f"arg1: '{ql.mem.string(arg1)}'")
    print(f"arg2: '{ql.mem.string(arg2)}'")

    addr = BASE + 0x2ECC440

    # print the u64 value at the address
    print(f"u64 at {addr}: {hex(ql.mem.read_ptr(addr, 8))}")


BASE = 0x6BB52000

q.hook_address(LibraryNamePrefixAndSuffix, BASE + 0x00AC5844)

q.run()
