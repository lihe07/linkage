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
            # save snapshot to ./before_il2cpp_init

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


q.add_fs_mapper("/proc/self/task/2000/maps", Fake_maps(q))


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


def hook_il2cpp_init(ql: Qiling, *args) -> None:
    print("Il2cpp init called")
    # ql.verbose = QL_VERBOSE.DISASM


q.hook_address(hook_il2cpp_init, 0x6C5F34B4)

call_stack = []


def print_call_stack():
    for addr in call_stack:
        if addr > BASE:
            print(f"libil2cpp + {hex(addr - BASE)}", end=" -> ")
        else:
            region = None
            region_start = None
            for start, end, _, _, name in q.mem.get_mapinfo():
                if start <= addr < end:
                    region = name
                    region_start = start
                    break

            if region is not None:
                print(f"{region} + {hex(addr - region_start)}", end=" -> ")
            else:
                print(f"{hex(addr)}", end=" -> ")
    print()


def rec_func_calls(ql: Qiling, address: int, size: int, md) -> None:
    buf = ql.mem.read(address, size)

    for insn in md.disasm(buf, address):
        if "bl" in insn.mnemonic:
            addr = int(insn.op_str.strip("#").strip("0x"), 16)

            if "blr" in insn.mnemonic:
                addr = ql.arch.regs.__getattr__(insn.op_str)

            call_stack.append(addr)
        if "ret" in insn.mnemonic:
            call_stack.pop()


def start_trace_stack(ql: Qiling) -> None:
    print("Starting stack trace")
    ql.hook_code(rec_func_calls, user_data=q.arch.disassembler)


def hook_object_new(ql: Qiling, *args) -> None:
    clazz = ql.arch.regs.x0

    ptr_to_class_name = ql.mem.read_ptr(clazz + 16, 8)

    class_name = ql.mem.string(ptr_to_class_name)

    print(f"Object::New({class_name})")

    unwind_stack(ql)
    ql.stop()


def unwind_stack(ql: Qiling) -> None:
    fp = ql.arch.regs.x29
    link = ql.arch.regs.arch_pc

    links = []

    links.append(link)

    while True:
        # Trace back one frame
        # Last fp and link is stored at the current fp
        link = ql.mem.read_ptr(fp + 8, 8)
        fp = ql.mem.read_ptr(fp, 8)

        links.append(link)

        if fp == 0:
            break

    # reverse the list
    links = links[::-1]

    for link in links:
        if link > BASE:
            print(f"libil2cpp + {hex(link - BASE)}", end=" -> ")
        else:
            region = None
            region_start = None
            for start, end, _, _, name in q.mem.get_mapinfo():
                if start <= link < end:
                    region = name
                    region_start = start
                    break
            if region is not None:
                print(f"{region} + {hex(link - region_start)}", end=" -> ")
            else:
                print(f"{hex(link)}", end=" -> ")

    print()


q.hook_address(hook_object_new, BASE + 0xABB9EC)


q.hook_address(lambda _: print("Before Runtime::ClassInit"), BASE + 0xABBAA4)
q.hook_address(lambda _: print("Object New Ret"), BASE + 0xABBAB4)


def hook_runtime_invoke(ql: Qiling, *args) -> None:
    print("Before Runtime::Invoke")
    method = ql.arch.regs.x0
    ptr_to_method_name = ql.mem.read_ptr(method + 16, 8)
    method_name = ql.mem.string(ptr_to_method_name)

    method_addr = ql.mem.read_ptr(method, 8)
    invoker_addr = ql.mem.read_ptr(method + 8, 8)

    print(
        f"Runtime::Invoke({method_name}, Invoker {hex(invoker_addr - BASE)}, Method {hex(method_addr - BASE)})"
    )

    # start_trace_stack(ql)


q.hook_address(hook_runtime_invoke, BASE + 0xA8FA24)
q.hook_address(lambda _: print("After Runtime::Invoke"), BASE + 0xA8FA9C)

# 72c6b4db9c


def hook_gc_malloc(ql: Qiling, *args) -> None:
    size = ql.arch.regs.x0
    print(f"GC::Malloc({size})")


q.hook_address(hook_gc_malloc, BASE + 0xAD84D0)


def hook_getenv(ql: Qiling, *args) -> None:
    print("getenv called")
    arg = ql.arch.regs.x0
    print(f"arg: {ql.mem.string(arg)}")

    if ql.mem.string(arg) == "GC_PRINT_VERBOSE_STATS":
        print("Returning 1")
        res = ql.mem.map_anywhere(len("1\0"))
        ql.mem.string(res, "1\0")
        ql.arch.regs.x0 = res

        # get the return address from x30
        ret = ql.arch.regs.x30
        # set the return address to the next instruction (aarch64)
        ret += 4
        ql.arch.regs.arch_pc = ret


q.hook_address(hook_getenv, BASE + 0x00A60050)

q.run()
