
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
    93726: ("Fleeting Flight", 2),
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


def group_candidates(candidates):
    """
    Group extracted candidates by their complete
    card-ID and quantity mappings.

    Each candidate must contain:
      - anchor
      - extracted
      - classification (optional)
    """
    groups = {}

    for candidate in candidates:
        records = records_from_flat_list(
            candidate["extracted"]["records"]
        )

        # Include every observed quantity for each ID.
        # This ensures conflicting quantities are not
        # silently discarded.
        signature = tuple(
            sorted(
                (
                    card_id,
                    tuple(sorted(quantities)),
                )
                for card_id, quantities in records.items()
            )
        )

        groups.setdefault(signature, []).append(candidate)

    return list(groups.values())



def load_ownership_checks(path):
    with path.open("r", encoding="utf-8") as file:
        data = json.load(file)

    checks = {}

    for card_id, entry in data.items():
        quantity = int(entry["quantity"])

        if not 0 <= quantity <= 4:
            raise ValueError(
                f"Invalid quantity for card {card_id}: {quantity}"
            )

        checks[int(card_id)] = {
            "name": entry["name"],
            "quantity": quantity,
        }

    if not checks:
        raise ValueError("Ownership checks file is empty.")

    return checks


def check_candidate_ownership(records, checks):
    """
    Compare a candidate's observed quantities against
    independently verified ownership checks.
    """
    observed = records_from_flat_list(records)

    results = {}
    valid = True

    for card_id, check in checks.items():
        quantities = observed.get(card_id, set())
        expected = check["quantity"]

        if expected == 0:
            passed = not quantities
        else:
            passed = quantities == {expected}

        if not passed:
            valid = False

        results[str(card_id)] = {
            "name": check["name"],
            "expected": expected,
            "observed": sorted(quantities),
            "passed": passed,
        }

    return valid, results


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
        "--group-candidates",
        action="store_true",
        help="Group candidate regions by identical card IDs and quantities",
    )

    parser.add_argument(
        "--auto-select",
        action="store_true",
        help="Select a collection candidate using verified ownership checks",
    )

    parser.add_argument(
        "--ownership-checks",
        type=Path,
        help="JSON file containing independently verified card quantities",
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

    
    if args.group_candidates:
        anchors = discover_inventory_anchors(pid)

        print(
            f"Discovered {len(anchors)} candidate anchor(s)"
        )

        handle = open_process(pid)

        try:
            candidates = []

            for anchor in anchors:
                extracted = extract_candidate(handle, anchor)

                candidates.append({
                    "anchor": anchor,
                    "extracted": extracted,
                })

        finally:
            kernel32.CloseHandle(handle)

        groups = group_candidates(candidates)

        print(
            f"Distinct candidate datasets: {len(groups)}"
        )

        for index, group in enumerate(groups, 1):
            representative = group[0]["extracted"]

            records = records_from_flat_list(
                representative["records"]
            )

            conflicts = sum(
                len(quantities) > 1
                for quantities in records.values()
            )

            print(f"\nGroup {index}")
            print("-" * 50)

            print(f"Matching candidates: {len(group)}")
            print(f"Unique IDs: {len(records):,}")
            print(f"Quantity conflicts: {conflicts}")

            print("Anchors:")

            for candidate in group:
                print(
                    f"  0x{candidate['anchor']:X}"
                )

            print("Reference validation:")

            for reference in representative["validation"].values():
                print(
                    f"  {reference['name']}: "
                    f"{reference['status']} "
                    f"(observed={reference['observed']})"
                )

        return

        
    if args.output is None:
        parser.error("--output is required for collection extraction")

    selected_extraction = None

    if args.auto_select:
        if args.anchor is not None:
            parser.error(
                "--auto-select cannot be combined with --anchor"
            )

        if args.ownership_checks is None:
            parser.error(
                "--ownership-checks is required with --auto-select"
            )

        if args.output is None:
            parser.error(
                "--output is required with --auto-select"
            )

        checks = load_ownership_checks(args.ownership_checks)
        anchors = discover_inventory_anchors(pid)

        print(f"Discovered {len(anchors)} candidate anchor(s)")

        handle = open_process(pid)

        try:
            candidates = []

            for anchor in anchors:
                extracted = extract_candidate(handle, anchor)

                candidates.append({
                    "anchor": anchor,
                    "extracted": extracted,
                })

        finally:
            kernel32.CloseHandle(handle)

        groups = group_candidates(candidates)
        passing_groups = []

        for index, group in enumerate(groups, 1):
            representative = group[0]["extracted"]

            passed, results = check_candidate_ownership(
                representative["records"],
                checks,
            )

            print(
                f"Group {index}: "
                f"{len(group)} matching candidate(s), "
                f"{len(records_from_flat_list(representative['records'])):,} IDs"
            )

            for result in results.values():
                status = "PASS" if result["passed"] else "FAIL"

                print(
                    f"  {result['name']}: {status} "
                    f"(expected={result['expected']}, "
                    f"observed={result['observed']})"
                )

            if passed:
                passing_groups.append(group)

        if len(passing_groups) != 1:
            raise RuntimeError(
                "Automatic selection requires exactly one "
                "candidate group passing all ownership checks; "
                f"found {len(passing_groups)}."
            )

        selected_group = passing_groups[0]

        # Prefer the smallest readable region among
        # equivalent candidate datasets.
        selected_candidate = min(
            selected_group,
            key=lambda candidate: (
                candidate["extracted"]["region_size"],
                candidate["anchor"],
            ),
        )

        anchor = selected_candidate["anchor"]

        selected_extraction = selected_candidate["extracted"]

        print(f"Selected anchor: 0x{anchor:X}")

    else:
        if args.output is None:
            parser.error(
                "--output is required for collection extraction"
            )

        if args.anchor is not None:
            anchor = args.anchor
            print(f"Using supplied anchor: 0x{anchor:X}")
        else:
            print("Discovering inventory anchor...")
            anchor = discover_inventory_anchor(pid)
            print(f"Discovered inventory anchor: 0x{anchor:X}")

    # Reuse the validated snapshot in auto-select mode.
    # Manual extraction still reads the selected region once.
    if selected_extraction is not None:
        extracted = selected_extraction
    else:
        handle = open_process(pid)
        try:
            extracted = extract_candidate(handle, anchor)
        finally:
            kernel32.CloseHandle(handle)

    start = extracted["region_base"]
    region_size = extracted["region_size"]
    scan_bytes = region_size
    records = extracted["records"]
    runs = extracted["runs"]
    validation = extracted["validation"]

    print(f"Region base: 0x{start:X}")
    print(f"Region size: {region_size:,} bytes")
    print(f"Scan start: 0x{start:X}")
    print(f"Scan size: {scan_bytes:,} bytes")

    print(f"Candidate records: {len(records):,}")
    print(f"Contiguous runs: {len(runs):,}")

    anchor_runs = [
        run for run in runs
        if any(
            item["address"] == anchor
            and item["card_id"] == ANCHOR_ID
            and 1 <= item["quantity"] <= 4
            for item in run
        )
    ]

    if len(anchor_runs) != 1:
        raise RuntimeError(
            "Expected exactly one matching anchor run; "
            f"found {len(anchor_runs)}."
        )

    selected = anchor_runs[0]
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
        "scan_bytes": scan_bytes,
        "anchor_run_length": len(selected),
        "reference_validation": validation,
        "runs": export_runs,
        "selection_method": (
            "ownership_checks"
            if args.auto_select
            else "manual_or_single_anchor"
        ),
        "selection_group_anchors": (
            [hex(candidate["anchor"]) for candidate in selected_group]
            if args.auto_select
            else [hex(anchor)]
        ),
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
