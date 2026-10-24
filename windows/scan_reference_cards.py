
import argparse
import ctypes
import struct
import sys
from collections import Counter
from ctypes import wintypes


PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400

MEM_COMMIT = 0x1000
PAGE_GUARD = 0x100
PAGE_NOACCESS = 0x01

READABLE = {
    0x02,  # PAGE_READONLY
    0x04,  # PAGE_READWRITE
    0x08,  # PAGE_WRITECOPY
    0x20,  # PAGE_EXECUTE_READ
    0x40,  # PAGE_EXECUTE_READWRITE
    0x80,  # PAGE_EXECUTE_WRITECOPY
}

CARD_IDS = {
    69459: "Charmed Stray (WAR)",
    75446: "Charmed Stray (ANB)",
    93726: "Fleeting Flight (FDN)",
    68475: "Healer's Hawk (GRN)",
    72169: "Healer's Hawk (JMP)",
    93855: "Healer's Hawk (FDN)",
}

CHUNK_SIZE = 1024 * 1024
OVERLAP = 16

if sys.platform != "win32":
    raise SystemExit("Run using Windows Python.")

if ctypes.sizeof(ctypes.c_void_p) != 8:
    raise SystemExit("64-bit Windows Python is required.")


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
        protection = info.Protect & 0xFF

        if (
            info.State == MEM_COMMIT
            and protection in READABLE
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


def scan_chunk(data, base_address, patterns, results, max_matches):
    for card_id, pattern in patterns.items():
        start = 0

        while True:
            offset = data.find(pattern, start)

            if offset == -1:
                break

            address = base_address + offset

            nearby = {}

            for relative_offset in (-8, -4, 4, 8):
                position = offset + relative_offset

                if 0 <= position <= len(data) - 4:
                    nearby[relative_offset] = struct.unpack_from(
                        "<I", data, position
                    )[0]

            results.append({
                "card_id": card_id,
                "address": address,
                "nearby": nearby,
            })

            if len(results) >= max_matches:
                return True

            start = offset + 1

    return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("pid", type=int)
    parser.add_argument("--max-matches", type=int, default=500)
    args = parser.parse_args()

    if args.max_matches < 1:
        parser.error("--max-matches must be positive")

    handle = kernel32.OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        False,
        args.pid,
    )

    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())

    patterns = {
        card_id: struct.pack("<I", card_id)
        for card_id in CARD_IDS
    }

    results = []
    regions_scanned = 0
    bytes_scanned = 0
    stopped_early = False

    try:
        for base, size in readable_regions(handle):
            regions_scanned += 1
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
                data_address = base + offset - len(previous)

                stopped_early = scan_chunk(
                    data,
                    data_address,
                    patterns,
                    results,
                    args.max_matches,
                )

                if stopped_early:
                    break

                previous = data[-OVERLAP:]
                bytes_scanned += len(chunk)
                offset += read_size

            if stopped_early:
                break

    finally:
        kernel32.CloseHandle(handle)

    print(f"\nRegions visited: {regions_scanned:,}")
    print(f"Memory read: {bytes_scanned / (1024 ** 2):,.1f} MiB")
    print(f"Matches: {len(results):,}")
    print(f"Stopped early: {stopped_early}")

    counts = Counter(item["card_id"] for item in results)

    print("\nMatches by card:")

    for card_id, name in CARD_IDS.items():
        print(f"  {name}: {counts[card_id]}")

    print("\nCandidate matches (first 30):")

    for item in results[:30]:
        print(
            f"  {CARD_IDS[item['card_id']]} "
            f"@ 0x{item['address']:X} "
            f"nearby={item['nearby']}"
        )

    print("\nNo memory contents were saved to disk.")


if __name__ == "__main__":
    main()
