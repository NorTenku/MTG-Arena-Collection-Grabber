
import argparse
import ctypes
import json
import struct
import sys
from discover_collection import (
    discover_inventory_anchor,
    discover_inventory_anchors,
)
from find_arena import find_arena_pid
from datetime import datetime, timezone
from pathlib import Path
from ctypes import wintypes
from collection_classifier import (
    classify_candidate,
    load_baseline,
    records_from_flat_list,
)

PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400

MEM_COMMIT = 0x1000
PAGE_GUARD = 0x100

READABLE = {0x02, 0x04, 0x08, 0x20, 0x40, 0x80}

RECORD = struct.Struct("<IIII")
MARKER = 0xFFFFFFFF

MAX_SCAN_BYTES = 8 * 1024 * 1024

REFERENCE_CARDS = {
    75446: ("Charmed Stray", 4),
    93726: ("Fleeting Flight", 1),
    93855: ("Healer's Hawk", 2),
    67692: ("Ajani's Welcome", 0),
}

ANCHOR_ID = 75446

if sys.platform != "win32":
    raise SystemExit("Use Windows Python.")

if ctypes.sizeof(ctypes.c_void_p) != 8:
    raise SystemExit("64-bit Python required.")


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


def open_process(pid):
    handle = kernel32.OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        False,
        pid,
    )

    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())

    return handle


def get_region(handle, address):
    info = MEMORY_BASIC_INFORMATION()

    result = kernel32.VirtualQueryEx(
        handle,
        ctypes.c_void_p(address),
        ctypes.byref(info),
        ctypes.sizeof(info),
    )

    if not result:
        raise ctypes.WinError(ctypes.get_last_error())

    if (
        info.State != MEM_COMMIT
        or (info.Protect & 0xFF) not in READABLE
        or (info.Protect & PAGE_GUARD)
    ):
        raise RuntimeError("Anchor is not in readable memory.")

    return info.BaseAddress, info.RegionSize


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

    if not success or bytes_read.value != size:
        raise ctypes.WinError(ctypes.get_last_error())

    return buffer.raw


def find_records(data, base):
    records = []

    for offset in range(0, len(data) - RECORD.size + 1, 4):
        card_id, marker, repeated_id, quantity = (
            RECORD.unpack_from(data, offset)
        )

        if (
            card_id > 0
            and card_id == repeated_id
            and marker == MARKER
            and 1 <= quantity <= 4
        ):
            records.append({
                "address": base + offset,
                "card_id": card_id,
                "quantity": quantity,
            })

    return records


def group_runs(records):
    runs = []
    current = []

    for record in records:
        if (
            current
            and record["address"] != current[-1]["address"] + 16
        ):
            runs.append(current)
            current = []

        current.append(record)

    if current:
        runs.append(current)

    return runs


def validate(records):
    lookup = {}

    for record in records:
        card_id = record["card_id"]
        lookup.setdefault(card_id, set()).add(
            record["quantity"]
        )

    results = {}

    for card_id, (name, expected) in REFERENCE_CARDS.items():
        observed = sorted(lookup.get(card_id, set()))

        if observed:
            status = (
                "match"
                if observed == [expected]
                else "mismatch"
            )
        else:
            status = (
                "absent_as_expected"
                if expected == 0
                else "missing"
            )

        results[str(card_id)] = {
            "name": name,
            "expected": expected,
            "observed": observed,
            "status": status,
        }

    return results


def extract_candidate(handle, anchor):
    region_base, region_size = get_region(handle, anchor)

    data = read_memory(
        handle,
        region_base,
        region_size,
    )

    records = find_records(data, region_base)

    return {
        "anchor": anchor,
        "region_base": region_base,
        "region_size": region_size,
        "records": records,
        "runs": group_runs(records),
        "validation": validate(records),
    }


def main():
    parser = argparse.ArgumentParser(
        description="Extract provisional MTG Arena collection records."
    )

    parser.add_argument(
        "--pid",
        type=int,
        default=None,
        help="MTG Arena PID (automatically detected if omitted)",
    )

    parser.add_argument(
        "--anchor",
        type=lambda value: int(value, 0),
        default=None,
        help="Override automatic inventory anchor discovery",
    )

    parser.add_argument(
        "--list-anchors",
        action="store_true",
        help="Discover and print all candidate inventory anchors",
    )

    parser.add_argument(
        "--baseline",
        type=Path,
        help="Provisional collection snapshot used to classify candidates",
    )

    parser.add_argument(
        "--list-candidates",
        action="store_true",
        help="Discover, extract, and classify all candidate regions",
    )

    parser.add_argument(
        "--output", 
        type=Path
    )

    args = parser.parse_args()

    pid = args.pid if args.pid is not None else find_arena_pid()
    print(f"Using MTG Arena PID: {pid}")

    if args.list_anchors:
        anchors = discover_inventory_anchors(pid)

        print(f"Discovered {len(anchors)} inventory anchor(s):")

        for anchor in anchors:
            print(f"  0x{anchor:X}")

        return

    
    if args.list_candidates:
        if args.baseline is None:
            parser.error(
                "--baseline is required with --list-candidates"
            )

        baseline = load_baseline(args.baseline)
        anchors = discover_inventory_anchors(pid)

        print(
            f"Discovered {len(anchors)} candidate anchor(s)"
        )
        print(
            f"Baseline contains {len(baseline):,} unique IDs"
        )

        handle = open_process(pid)

        try:
            candidates = []

            for anchor in anchors:
                extracted = extract_candidate(handle, anchor)

                candidate_records = records_from_flat_list(
                    extracted["records"]
                )

                classification = classify_candidate(
                    baseline,
                    candidate_records,
                )

                candidates.append({
                    "anchor": anchor,
                    "extracted": extracted,
                    "classification": classification,
                })

        finally:
            kernel32.CloseHandle(handle)

        for index, candidate in enumerate(candidates, 1):
            result = candidate["classification"]
            extracted = candidate["extracted"]

            print(f"\nCandidate {index}")
            print("-" * 50)
            print(f"Anchor: 0x{candidate['anchor']:X}")
            print(
                f"Region size: "
                f"{extracted['region_size']:,} bytes"
            )
            print(
                f"Unique IDs: "
                f"{result['candidate_count']:,}"
            )
            print(
                f"Baseline coverage: "
                f"{result['coverage']:.2%}"
            )
            print(
                f"Baseline precision: "
                f"{result['precision']:.2%}"
            )
            print(
                f"Quantity agreement: "
                f"{result['quantity_agreement']:.2%}"
            )
            print(
                f"Quantity mismatches: "
                f"{result['quantity_mismatches']}"
            )
            print(
                f"Internal conflicts: "
                f"{result['conflicts']}"
            )

            print("Reference validation:")

            for reference in extracted["validation"].values():
                print(
                    f"  {reference['name']}: "
                    f"{reference['status']}"
                )

        return


    if args.output is None and not args.list_candidates:
        parser.error(
            "--output is required unless --list-anchors "
            "or --list-candidates is specified"
        )

    if args.list_candidates:
        if args.baseline is None:
            parser.error(
                "--baseline is required with --list-candidates"
            )

    # Discover every candidate anchor.
    # Read each candidate's memory region.
    # Extract records from each region.
    # Compare records against the baseline.
    # Print classification results.
    # Return without exporting.

    if args.anchor is not None:
        anchor = args.anchor
        print(f"Using supplied anchor: 0x{anchor:X}")
    else:
        print("Discovering inventory anchor...")
        anchor = discover_inventory_anchor(pid)
        print(f"Discovered inventory anchor: 0x{anchor:X}")

    handle = open_process(pid)


    try:
        region_base, region_size = get_region(
            handle,
            anchor,
        )

        region_end = region_base + region_size

        start = region_base
        end = region_end

        # Preserve 4-byte alignment relative to the region.
        start -= (start - region_base) % 4

        print(f"Region base: 0x{region_base:X}")
        print(f"Region size: {region_size:,} bytes")
        print(f"Scan start: 0x{start:X}")
        print(f"Scan size: {end - start:,} bytes")

        data = read_memory(
            handle,
            start,
            end - start,
        )

    finally:
        kernel32.CloseHandle(handle)

    records = find_records(data, start)
    runs = group_runs(records)

    print(f"Candidate records: {len(records):,}")
    print(f"Contiguous runs: {len(runs):,}")

    anchor_runs = [
        run for run in runs
        if any(
            item["address"] == anchor
            and item["card_id"] == ANCHOR_ID
            and item["quantity"] == 4
            for item in run
        )
    ]

    if len(anchor_runs) != 1:
        raise RuntimeError(
            "Expected exactly one matching anchor run; "
            f"found {len(anchor_runs)}."
        )

    selected = anchor_runs[0]
    validation = validate(records)

    print(f"Anchor run length: {len(selected):,}")

    for item in validation.values():
        print(
            f"{item['name']}: "
            f"{item['status']} "
            f"(observed={item['observed']})"
        )

    # Export all candidate records in the bounded window,
    # preserving their run membership for later validation.
    export_runs = []

    for index, run in enumerate(runs):
        export_runs.append({
            "run_id": index,
            "start_address": hex(run[0]["address"]),
            "record_count": len(run),
            "records": [
                {
                    "card_id": item["card_id"],
                    "quantity": item["quantity"],
                }
                for item in run
            ],
        })

    output = {
        "status": "provisional",
        "source": "mtga_process_memory",
        "extracted_at": datetime.now(timezone.utc).isoformat(),
        "pid": pid,
        "anchor_address": hex(anchor),
        "scan_start": hex(start),
        "scan_bytes": len(data),
        "anchor_run_length": len(selected),
        "reference_validation": validation,
        "runs": export_runs,
    }

    args.output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with args.output.open("w", encoding="utf-8") as file:
        json.dump(output, file, indent=2)

    print(f"\nSaved provisional export: {args.output}")


if __name__ == "__main__":
    main()
