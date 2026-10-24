
import ctypes
import sys
from ctypes import wintypes


PROCESS_VM_READ = 0x0010
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

PROCESS_ACCESS = (
    PROCESS_VM_READ
    | PROCESS_QUERY_LIMITED_INFORMATION
)

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

kernel32.OpenProcess.argtypes = [
    wintypes.DWORD,
    wintypes.BOOL,
    wintypes.DWORD,
]
kernel32.OpenProcess.restype = wintypes.HANDLE

kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL


def open_read_only(pid):
    handle = kernel32.OpenProcess(
        PROCESS_ACCESS,
        False,
        pid,
    )

    if not handle:
        error = ctypes.get_last_error()
        raise ctypes.WinError(error)

    return handle


def main():
    if sys.platform != "win32":
        raise SystemExit(
            "Run this script using Windows Python, not WSL Python."
        )

    if len(sys.argv) != 2:
        raise SystemExit(
            "Usage: python inspect_process.py <MTGA_PID>"
        )

    pid = int(sys.argv[1])

    print(f"Target process PID: {pid}")
    print("Requesting read-only access...")

    handle = open_read_only(pid)

    try:
        print("Success: read-only process handle acquired.")
        print("No memory was modified or exported.")
    finally:
        kernel32.CloseHandle(handle)
        print("Process handle closed.")


if __name__ == "__main__":
    main()
