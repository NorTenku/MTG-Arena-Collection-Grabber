
import argparse
import ctypes
import struct
from ctypes import wintypes

from find_arena import find_arena_pid


# Windows process permissions: read and query only.
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400

MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000
MEM_MAPPED = 0x40000
MEM_IMAGE = 0x1000000

PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100
PAGE_READABLE = {
    0x02,  # PAGE_READONLY
    0x04,  # PAGE_READWRITE
    0x08,  # PAGE_WRITECOPY
    0x20,  # PAGE_EXECUTE_READ
    0x40,  # PAGE_EXECUTE_READWRITE
    0x80,  # PAGE_EXECUTE_WRITECOPY
}

# Keep individual reads reasonably small.
CHUNK_SIZE = 1024 * 1024

# Windows 64-bit user address-space upper bound.
MAX_ADDRESS = 0x00007FFFFFFFFFFF


# Reference cards used to locate candidate inventory structures.
# Quantities are deliberately excluded from discovery.
REFERENCES = {
    "Charmed Stray": 75446,
    "Fleeting Flight": 93726,
    "Healer's Hawk": 93855,
}

RECORD = struct.Struct("<IIII")
MARKER = 0xFFFFFFFF

# Match the first 12 bytes:
# card_id | 0xFFFFFFFF | card_id
#
# The final four bytes contain the quantity, which is
# inspected separately.
SIGNATURES = {
    name: struct.pack(
        "<III",
        card_id,
        MARKER,
        card_id,
    )
    for name, card_id in REFERENCES.items()
}



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


kernel32 = ctypes.WinDLL(
    "kernel32",
    use_last_error=True,
)

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

kernel32.CloseHandle.argtypes = [
    wintypes.HANDLE,
]
kernel32.CloseHandle.restype = wintypes.BOOL


def open_process(pid):
    handle = kernel32.OpenProcess(
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        False,
        pid,
    )

    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())

    return handle


def readable_region(info):
    protection = info.Protect

    if info.State != MEM_COMMIT:
        return False

    if protection & PAGE_GUARD:
        return False

    if protection & PAGE_NOACCESS:
        return False

    return (protection & 0xFF) in PAGE_READABLE


def iter_regions(handle):
    address = 0
    info = MEMORY_BASIC_INFORMATION()

    while address < MAX_ADDRESS:
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

        if size == 0:
            break

        if readable_region(info):
            yield base, size

        next_address = base + size

        if next_address <= address:
            break

        address = next_address


def read_chunk(handle, address, size):
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



def scan_region(handle, base, size):
    matches = {
        name: []
        for name in SIGNATURES
    }

    offset = 0
    tail = b""

    # Preserve enough bytes to detect records crossing
    # chunk boundaries.
    overlap = RECORD.size - 1

    while offset < size:
        length = min(CHUNK_SIZE, size - offset)
        address = base + offset

        data = read_chunk(handle, address, length)

        if not data:
            tail = b""
            offset += length
            continue

        combined = tail + data
        combined_base = address - len(tail)

        for name, signature in SIGNATURES.items():
            search_from = 0

            while True:
                position = combined.find(
                    signature,
                    search_from,
                )

                if position == -1:
                    break

                record_end = position + RECORD.size

                if record_end <= len(combined):
                    match_address = combined_base + position

                    if match_address % 4 == 0:
                        quantity = struct.unpack_from(
                            "<I",
                            combined,
                            position + 12,
                        )[0]

                        if 1 <= quantity <= 4:
                            matches[name].append({
                                "address": match_address,
                                "quantity": quantity,
                            })

                search_from = position + 1

        tail = combined[-overlap:]
        offset += length

    return matches



def discover_inventory_anchors(pid):
    """
    Discover all memory addresses containing the expected
    reference-card signatures.
    """
    handle = open_process(pid)
    candidates = []

    try:
        for base, size in iter_regions(handle):
            matches = scan_region(handle, base, size)

            if all(matches[name] for name in SIGNATURES):
                candidates.extend(
                    match["address"]
                    for match in matches["Charmed Stray"]
                )

    finally:
        kernel32.CloseHandle(handle)

    candidates = sorted(set(candidates))

    if not candidates:
        raise RuntimeError(
            "No validated inventory anchors found. "
            "Make sure Arena is fully loaded and the "
            "reference quantities are unchanged."
        )

    return candidates


def discover_inventory_anchor(pid):
    """
    Compatibility wrapper for callers expecting one anchor.
    """
    candidates = discover_inventory_anchors(pid)

    if len(candidates) != 1:
        raise RuntimeError(
            "Multiple inventory anchors found: "
            + ", ".join(f"0x{address:X}" for address in candidates)
            + ". Candidate classification is required."
        )

    return candidates[0]


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Discover candidate MTG Arena inventory "
            "addresses using known card signatures."
        )
    )

    parser.add_argument(
        "--pid",
        type=int,
        help="MTG Arena PID (auto-detected if omitted)",
    )

    args = parser.parse_args()

    pid = args.pid if args.pid is not None else find_arena_pid()

    print(f"MTG Arena PID: {pid}")
    print("Scanning readable process memory...")
    print()

    handle = open_process(pid)

    regions_scanned = 0
    bytes_scanned = 0
    candidate_regions = []

    try:
        for base, size in iter_regions(handle):
            regions_scanned += 1
            bytes_scanned += size

            matches = scan_region(handle, base, size)

            found = {
                name: addresses
                for name, addresses in matches.items()
                if addresses
            }

            if not found:
                continue

            candidate_regions.append({
                "base": base,
                "size": size,
                "matches": matches,
            })

    finally:
        kernel32.CloseHandle(handle)

    print(f"Readable regions: {regions_scanned:,}")
    print(
        f"Readable memory examined: "
        f"{bytes_scanned / (1024 * 1024):,.1f} MiB"
    )
    print(
        f"Regions containing reference signatures: "
        f"{len(candidate_regions):,}"
    )

    print("\nCandidate regions:")

    for candidate in candidate_regions:
        base = candidate["base"]
        size = candidate["size"]
        matches = candidate["matches"]

        matched_count = sum(
            bool(addresses)
            for addresses in matches.values()
        )

        print(
            f"\nRegion: 0x{base:X} "
            f"({size:,} bytes)"
        )
        print(
            f"Reference signatures matched: "
            f"{matched_count}/{len(SIGNATURES)}"
        )

        for name, addresses in matches.items():
            if addresses:
                formatted = ", ".join(
                    f"0x{match['address']:X} "
                    f"(quantity={match['quantity']})"
                    for match in addresses[:5]
                )

                print(f"  {name}: {formatted}")

    validated = [
        candidate
        for candidate in candidate_regions
        if all(
            candidate["matches"][name]
            for name in SIGNATURES
        )
    ]

    print(
        f"\nRegions matching all three references: "
        f"{len(validated)}"
    )

    if validated:
        print("\nSuggested extraction anchors:")

        for candidate in validated:
            anchor = candidate["matches"]["Charmed Stray"][0]["address"]
            print(f"  0x{anchor:X}")

    else:
        print(
            "\nNo single region contained all three "
            "reference signatures."
        )
        print(
            "This may mean the inventory is split "
            "across regions or the reference "
            "quantities have changed."
        )


if __name__ == "__main__":
    main()
