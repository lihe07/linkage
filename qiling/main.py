from collections import defaultdict
from qiling import *
from qiling.const import *
from qiling.os.const import *

import os

os.system("cp ./linkage ./arm64_android6.0/linkage")


stack_size = 0x100000 * 100
stack_address = 0x008000009DE000

OVERRIDES = {
    "mmap_address": 0x68000000,
}

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

        if data.startswith(b"Jumping to 6c5f34b4"):
            print("=====")
            ql.verbose = QL_VERBOSE.DEFAULT
        if data.startswith(b"Function returned"):
            ql.verbose = QL_VERBOSE.DISABLED
    except:
        ret = -1
    else:
        ret = count

    # return a value to the caller
    return ret


q.os.set_syscall("write", my_syscall_write, QL_INTERCEPT.CALL)


# openat(fd = 0xffffff9c, path = 0x6814d258, flags = 0x0, mode = 0x0) = -0x1 (EPERM)


def my_syscall_openat(ql: Qiling, fd: int, path: int, flags: int, mode: int):
    print(f"openat: {ql.mem.string(path)}")

    pathstr = ql.mem.string(path)

    if pathstr == "/Metadata/global-metadata.dat":
        # redirect to /global-metadata.dat
        print("Hook: Redirecting to /global-metadata.dat... For debugging")
        ql.mem.string(path, "/global-metadata.dat")
        return None, [fd, path, flags, mode]
    return None


q.os.set_syscall("openat", my_syscall_openat, QL_INTERCEPT.ENTER)


from qiling.os.mapper import QlFsMappedObject
from qiling.os.posix import syscall


class Fake_maps(QlFsMappedObject):
    def __init__(self, ql: Qiling):
        self.ql = ql

    def read(self, size):
        return "".join(
            f"{lbound:x}-{ubound:x} {perms}p {label}\n"
            for lbound, ubound, perms, label, _ in self.ql.mem.get_mapinfo()
        ).encode()

    def fstat(self):
        return defaultdict(int)

    def close(self):
        return 0


q.add_fs_mapper("/proc/self/maps", Fake_maps(q))


class Fake_stat(QlFsMappedObject):
    def __init__(self, ql: Qiling):
        self.ql = ql

    def read(self, size):
        arr = "28651 (cat) R 14107 28651 14107 34822 28651 4194304 103 0 0 0 0 0 0 0 20 0 1 0 3065310 10186752 1373 18446744073709551615 108380401893376 108380401909889 140734720709296 0 0 0 0 0 0 0 0 0 17 6 0 0 0 0 0 108380401924720 108380401926248 108380841504768 140734720714845 140734720714865 140734720714865 140734720716779 0"
        arr = arr.split(" ")
        arr[27] = str(stack_address)
        return " ".join(arr).encode() + b"\n"

    def fstat(self):
        return defaultdict(int)

    def close(self):
        return 0


# q.add_fs_mapper("/proc/self/stat", Fake_stat(q))


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
