
import ctypes
from ctypes import wintypes
from pathlib import Path
import sys


TH32CS_SNAPPROCESS = 0x00000002
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),
    ]


kernel32.CreateToolhelp32Snapshot.argtypes = [
    wintypes.DWORD,
    wintypes.DWORD,
]
kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE

kernel32.Process32FirstW.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(PROCESSENTRY32W),
]
kernel32.Process32FirstW.restype = wintypes.BOOL

kernel32.Process32NextW.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(PROCESSENTRY32W),
]
kernel32.Process32NextW.restype = wintypes.BOOL

kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL


def find_arena_processes():
    snapshot = kernel32.CreateToolhelp32Snapshot(
        TH32CS_SNAPPROCESS, 0
    )

    if snapshot == INVALID_HANDLE_VALUE:
        raise ctypes.WinError(ctypes.get_last_error())

    processes = []

    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)

        if not kernel32.Process32FirstW(
            snapshot, ctypes.byref(entry)
        ):
            raise ctypes.WinError(ctypes.get_last_error())

        while True:
            name = entry.szExeFile.lower()

            if name in {"mtga.exe", "mtga"}:
                processes.append({
                    "pid": entry.th32ProcessID,
                    "name": entry.szExeFile,
                })

            if not kernel32.Process32NextW(
                snapshot, ctypes.byref(entry)
            ):
                break
    finally:
        kernel32.CloseHandle(snapshot)

    return processes


def find_arena_pid():
    processes = find_arena_processes()

    if not processes:
        raise RuntimeError(
            "MTG Arena is not running. "
            "Launch Arena and try again."
        )

    if len(processes) > 1:
        raise RuntimeError(
            "Multiple MTG Arena processes found: "
            + ", ".join(str(p["pid"]) for p in processes)
        )

    return processes[0]["pid"]


if __name__ == "__main__":
    try:
        pid = find_arena_pid()
        print(f"MTG Arena PID: {pid}")
    except RuntimeError as error:
        print(f"Error: {error}", file=sys.stderr)
        sys.exit(1)
