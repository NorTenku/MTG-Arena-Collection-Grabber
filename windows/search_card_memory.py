"""Read-only MTGA process-memory search for a suspected missing Arena card ID.

Run with Windows 64-bit Python. Searches committed, readable memory in chunks.
No process writes, injection, or game-file modifications are performed.
"""
import argparse
import ctypes
import struct
import sys
from ctypes import wintypes

if sys.platform != "win32":
    raise SystemExit("Run with 64-bit Windows Python (py.exe -3), not WSL Python.")
if ctypes.sizeof(ctypes.c_void_p) != 8:
    raise SystemExit("64-bit Windows Python required.")

from find_arena import find_arena_pid

PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
MEM_COMMIT = 0x1000
PAGE_GUARD = 0x100
PAGE_NOACCESS = 0x01
READABLE = {0x02, 0x04, 0x08, 0x20, 0x40, 0x80}
CHUNK = 1024 * 1024
OVERLAP = 64  # enough for 16-byte pattern and +/- 24-byte context
MAX_ADDRESS = 0x7FFFFFFFFFFF

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
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.VirtualQueryEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t]
kernel32.VirtualQueryEx.restype = ctypes.c_size_t
kernel32.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
kernel32.ReadProcessMemory.restype = wintypes.BOOL
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL


def read_bytes(handle, address, size):
    buf = ctypes.create_string_buffer(size)
    count = ctypes.c_size_t()
    ok = kernel32.ReadProcessMemory(handle, ctypes.c_void_p(address), buf, size, ctypes.byref(count))
    return buf.raw[:count.value] if ok or count.value else b""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("card_id", type=int, nargs="?", default=103481)
    parser.add_argument("--pid", type=int, help="MTGA.exe PID (otherwise autodetect)")
    parser.add_argument("--max-raw", type=int, default=40, help="Maximum raw-only matches to print")
    args = parser.parse_args()
    if not 0 < args.card_id <= 0xFFFFFFFF:
        parser.error("card_id must be a positive uint32")
    if args.max_raw < 0:
        parser.error("--max-raw must be nonnegative")

    pid = args.pid if args.pid is not None else find_arena_pid()
    if not pid:
        raise SystemExit("MTGA.exe not found. Open Arena or pass --pid.")
    handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())

    raw = struct.pack("<I", args.card_id)
    prefix = struct.pack("<III", args.card_id, 0xFFFFFFFF, args.card_id)
    full = prefix + struct.pack("<I", 1)
    totals = {"full": 0, "prefix_other": 0, "raw_only": 0}
    regions = 0
    unreadable_chunks = 0
    raw_printed = 0
    print(f"PID: {pid} | Arena ID: {args.card_id} (0x{args.card_id:08X})")
    print("Looking for: full record (quantity 1), prefix (any quantity), raw uint32")
    print("Addresses and context are hexadecimal. Raw-only output is capped.\n")

    try:
        cursor = 0
        while cursor < MAX_ADDRESS:
            mbi = MEMORY_BASIC_INFORMATION()
            n = kernel32.VirtualQueryEx(handle, ctypes.c_void_p(cursor), ctypes.byref(mbi), ctypes.sizeof(mbi))
            if not n:
                break
            base = int(mbi.BaseAddress or 0)
            size = int(mbi.RegionSize)
            end = base + size
            if end <= cursor:
                break
            cursor = end
            if not (mbi.State == MEM_COMMIT and (mbi.Protect & 0xFF) in READABLE and not (mbi.Protect & PAGE_GUARD)):
                continue
            regions += 1
            pos = base
            while pos < end:
                # Overlap avoids losing records crossing chunk boundaries.
                request = min(CHUNK + OVERLAP, end - pos)
                data = read_bytes(handle, pos, request)
                if not data:
                    unreadable_chunks += 1
                    pos += CHUNK
                    continue
                primary_len = min(CHUNK, end - pos)
                search_end = min(primary_len, len(data))
                offset = data.find(raw)
                while offset != -1 and offset < search_end:
                    address = pos + offset
                    if data[offset:offset + 16] == full:
                        kind = "full"
                    elif data[offset:offset + 12] == prefix:
                        kind = "prefix_other"
                    else:
                        kind = "raw_only"
                    totals[kind] += 1
                    if kind != "raw_only" or raw_printed < args.max_raw:
                        start = max(0, offset - 24)
                        stop = min(len(data), offset + 40)
                        context = data[start:stop].hex(" ")
                        extra = ""
                        if kind != "raw_only" and len(data) >= offset + 16:
                            extra = f" | quantity_field={struct.unpack_from('<I', data, offset + 12)[0]}"
                        print(f"{kind:12} address=0x{address:X} region=0x{base:X} +0x{address-base:X}{extra}")
                        print(f"  context [0x{pos+start:X}]: {context}")
                        if kind == "raw_only":
                            raw_printed += 1
                    offset = data.find(raw, offset + 1)
                pos += CHUNK
    finally:
        kernel32.CloseHandle(handle)

    print("\nSummary")
    print(f"  Readable regions visited: {regions}")
    print(f"  Unreadable chunks skipped: {unreadable_chunks}")
    print(f"  Full records (quantity 1): {totals['full']}")
    print(f"  Prefix matches (other quantity): {totals['prefix_other']}")
    print(f"  Raw-only ID occurrences: {totals['raw_only']}")
    if totals['raw_only'] > raw_printed:
        print(f"  Raw-only occurrences omitted: {totals['raw_only'] - raw_printed}")
    print("Note: A raw ID occurrence is not evidence of ownership.")

if __name__ == "__main__":
    main()
