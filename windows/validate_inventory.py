
import argparse
import ctypes
import struct
import sys
from ctypes import wintypes


PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400

MEM_COMMIT = 0x1000
PAGE_GUARD = 0x100

READABLE = {
    0x02, 0x04, 0x08,
    0x20, 0x40, 0x80,
}

CHUNK_SIZE = 1024 * 1024
OVERLAP = 15

REFERENCE_CARDS = {
    75446: ("Charmed Stray (ANB)", 4),
    93726: ("Fleeting Flight (FDN)", 1),
    93855: ("Healer's Hawk (FDN)", 2),
    67692: ("Ajani's Welcome (M19)", 0),
}

if sys.platform != "win32":
    raise SystemExit("Run with Windows Python.")

if ctypes.sizeof(ctypes.c_void_p) != 8:
    raise SystemExit("64-bit Windows Python required.")


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

kernel32.ReadProcessMemory.argtypes = [
    wintypes.HANDLE,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
kernel32.ReadProcessMemory.restype = wintypes.BOOL

kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL


def readable_regions(handle):
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

        base = info.BaseAddress or 0
        size = info.RegionSize

        if (
            info.State == MEM_COMMIT
            and (info.Protect & 0xFF) in READABLE
            and not (info.Protect & PAGE_GUARD)
        ):
            yield base, size

        next_address = base + size

        if next_address <= address:
            break

        address = next_address


def read_memory(handle, address, size):
    buffer = ctypes.create_string_buffer(size)
    bytes_read = ctypes.c_size_t()

    success = kernel32.ReadProcessMemory(
        handle,
        ctypes.c_void_p(address),
        buffer,
        size,
        ctypes.byref(bytes_read),
    )

    if not success and bytes_read.value == 0:
        return b""

    return buffer.raw[:bytes_read.value]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("pid", type=int)
    args = parser.parse_args()

    handle = kernel32.OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        False,
        args.pid,
    )

    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())

    prefixes = {
        card_id: struct.pack(
            "<III",
            card_id,
            0xFFFFFFFF,
            card_id,
        )
        for card_id in REFERENCE_CARDS
    }

    matches = {card_id: [] for card_id in REFERENCE_CARDS}

    try:
        for base, size in readable_regions(handle):
            offset = 0
            previous = b""

            while offset < size:
                read_size = min(CHUNK_SIZE, size - offset)
                chunk = read_memory(handle, base + offset, read_size)

                if not chunk:
                    previous = b""
                    offset += read_size
                    continue

                data = previous + chunk
                data_base = base + offset - len(previous)

                for card_id, prefix in prefixes.items():
                    start = 0

                    while True:
                        pos = data.find(prefix, start)

                        if pos == -1:
                            break

                        if pos + 16 <= len(data):
                            quantity = struct.unpack_from(
                                "<I", data, pos + 12
                            )[0]

                            matches[card_id].append(
                                (data_base + pos, quantity)
                            )

                        start = pos + 1

                previous = data[-OVERLAP:]
                offset += read_size

    finally:
        kernel32.CloseHandle(handle)

    print("\nInventory pattern validation")
    print("=" * 50)

    for card_id, (name, expected) in REFERENCE_CARDS.items():
        print(f"\n{name}")
        print(f"  Arena ID: {card_id}")
        print(f"  Expected: {expected}")
        print(f"  Matches: {len(matches[card_id])}")

        for address, quantity in matches[card_id][:10]:
            result = (
                "MATCH"
                if quantity == expected
                else "DIFFERENT"
            )

            print(
                f"  0x{address:X} "
                f"quantity={quantity} [{result}]"
            )


if __name__ == "__main__":
    main()
