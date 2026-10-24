
import ctypes
import sys
from ctypes import wintypes


PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400

MEM_COMMIT = 0x1000

PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_GUARD = 0x100


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("PartitionId", wintypes.WORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

kernel32.OpenProcess.argtypes = [
    wintypes.DWORD,
    wintypes.BOOL,
    wintypes.DWORD,
]
kernel32.OpenProcess.restype = wintypes.HANDLE

kernel32.VirtualQueryEx.argtypes = [
    wintypes.HANDLE,
    ctypes.c_void_p,
    ctypes.POINTER(MEMORY_BASIC_INFORMATION),
    ctypes.c_size_t,
]
kernel32.VirtualQueryEx.restype = ctypes.c_size_t

kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL


def main():
    if sys.platform != "win32":
        raise SystemExit("Run with Windows Python.")

    if len(sys.argv) != 2:
        raise SystemExit(
            "Usage: inspect_memory.py <PID>"
        )

    pid = int(sys.argv[1])

    handle = kernel32.OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        False,
        pid,
    )

    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())

    readable_protections = {
        PAGE_READONLY,
        PAGE_READWRITE,
        PAGE_WRITECOPY,
        PAGE_EXECUTE_READ,
        PAGE_EXECUTE_READWRITE,
        PAGE_EXECUTE_WRITECOPY,
    }

    regions = 0
    readable_regions = 0
    readable_bytes = 0

    try:
        address = 0
        info = MEMORY_BASIC_INFORMATION()

        while True:
            result = kernel32.VirtualQueryEx(
                handle,
                ctypes.c_void_p(address),
                ctypes.byref(info),
                ctypes.sizeof(info),
            )

            if not result:
                break

            regions += 1

            protection = info.Protect & 0xFF

            if (
                info.State == MEM_COMMIT
                and protection in readable_protections
                and not (info.Protect & PAGE_GUARD)
            ):
                readable_regions += 1
                readable_bytes += info.RegionSize

            next_address = (
                (info.BaseAddress or 0) + info.RegionSize
            )

            if next_address <= address:
                break

            address = next_address

    finally:
        kernel32.CloseHandle(handle)

    print(f"Process PID: {pid}")
    print(f"Memory regions: {regions:,}")
    print(f"Readable regions: {readable_regions:,}")
    print(
        f"Total readable memory: "
        f"{readable_bytes / (1024 ** 2):,.1f} MiB"
    )
    print("No memory contents were read or exported.")


if __name__ == "__main__":
    main()
