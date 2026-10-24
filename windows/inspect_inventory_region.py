
import argparse
import ctypes
import struct
import sys
from ctypes import wintypes


PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400

RECORD = struct.Struct("<IIII")
MARKER = 0xFFFFFFFF

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

kernel32.OpenProcess.argtypes = [
    wintypes.DWORD,
    wintypes.BOOL,
    wintypes.DWORD,
]
kernel32.OpenProcess.restype = wintypes.HANDLE

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


def main():
    if sys.platform != "win32":
        raise SystemExit("Run with Windows Python.")

    parser = argparse.ArgumentParser()
    parser.add_argument("pid", type=int)
    parser.add_argument("address", type=lambda x: int(x, 0))
    parser.add_argument("--radius", type=int, default=4096)
    args = parser.parse_args()

    if args.radius < 0 or args.radius > 1024 * 1024:
        parser.error("Radius must be between 0 and 1 MiB.")

    start = max(0, args.address - args.radius)
    size = args.radius * 2 + RECORD.size

    handle = kernel32.OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        False,
        args.pid,
    )

    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())

    buffer = ctypes.create_string_buffer(size)
    bytes_read = ctypes.c_size_t()

    try:
        success = kernel32.ReadProcessMemory(
            handle,
            ctypes.c_void_p(start),
            buffer,
            size,
            ctypes.byref(bytes_read),
        )

        if not success:
            raise ctypes.WinError(ctypes.get_last_error())

    finally:
        kernel32.CloseHandle(handle)

    data = buffer.raw[:bytes_read.value]

    print(f"Read {len(data):,} bytes")
    print("Candidate inventory records:")
    print("-" * 65)

    matches = []

    for offset in range(0, len(data) - RECORD.size + 1, 4):
        card_id, marker, repeated_id, quantity = (
            RECORD.unpack_from(data, offset)
        )

        if (
            card_id == repeated_id
            and marker == MARKER
            and 0 <= quantity <= 4
        ):
            matches.append(
                (start + offset, card_id, quantity)
            )

    for address, card_id, quantity in matches:
        print(
            f"0x{address:X} "
            f"card_id={card_id} "
            f"quantity={quantity}"
        )

    print(f"\nCandidate records found: {len(matches)}")


if __name__ == "__main__":
    main()
