"""Read-only comparison of MTG Arena card-ID representations in process memory.

Place beside search_card_memory.py and find_arena.py. Run with 64-bit Windows Python.
Reports matching repeated-ID records and aligned ID/value pairs, grouped by region.
Neither representation is automatically treated as proof of ownership.
"""
import argparse
import ctypes
import json
import struct
import sys
from collections import Counter, defaultdict
from pathlib import Path

if sys.platform != "win32":
    raise SystemExit("Use 64-bit Windows Python (py.exe -3).")
if ctypes.sizeof(ctypes.c_void_p) != 8:
    raise SystemExit("64-bit Windows Python required.")

from find_arena import find_arena_pid
from search_card_memory import (
    CHUNK, MAX_ADDRESS, MEM_COMMIT, PAGE_GUARD, PROCESS_QUERY_INFORMATION,
    PROCESS_VM_READ, READABLE, MEMORY_BASIC_INFORMATION, kernel32, read_bytes,
)

DEFAULT_CARDS = [
    (75446, "Charmed Stray", 4),
    (93726, "Fleeting Flight", 2),
    (93855, "Healer's Hawk", 2),
    (103481, "Last Light of Durin's Day", 1),
    (76519, "Devouring Tendrils", 0),
]
# Need 16 bytes after a hit and context around it, even at a chunk boundary.
OVERLAP = 64


def inspect_hit(data, offset, address, card_id):
    """Interpret a hit without assigning any ownership semantics."""
    tail = data[offset:offset + 16]
    if len(tail) >= 16:
        marker, repeated, qty = struct.unpack_from("<III", tail, 4)
        if marker == 0xFFFFFFFF and repeated == card_id:
            return "repeated_id", qty
    # Candidate ID/value pair only when the address is 4-byte aligned.
    # The value is not necessarily a quantity; it could be metadata.
    if address % 4 == 0 and len(tail) >= 8:
        return "id_value", struct.unpack_from("<I", tail, 4)[0]
    return "unaligned_raw", None


def scan(handle, cards, max_examples):
    patterns = {card_id: struct.pack("<I", card_id) for card_id, _, _ in cards}
    counts = defaultdict(Counter)
    values = defaultdict(Counter)
    examples = defaultdict(list)
    regions = 0
    unreadable = 0
    cursor = 0

    while cursor < MAX_ADDRESS:
        mbi = MEMORY_BASIC_INFORMATION()
        n = kernel32.VirtualQueryEx(
            handle, ctypes.c_void_p(cursor), ctypes.byref(mbi), ctypes.sizeof(mbi)
        )
        if not n:
            break
        base = int(mbi.BaseAddress or 0)
        end = base + int(mbi.RegionSize)
        if end <= cursor:
            break
        cursor = end
        if not (mbi.State == MEM_COMMIT and
                (mbi.Protect & 0xFF) in READABLE and
                not (mbi.Protect & PAGE_GUARD)):
            continue
        regions += 1
        pos = base
        while pos < end:
            primary = min(CHUNK, end - pos)
            data = read_bytes(handle, pos, min(primary + OVERLAP, end - pos))
            if len(data) < primary:
                unreadable += 1
            # Count hits only within the primary portion, never twice in overlap.
            limit = min(primary, len(data))
            for card_id, pattern in patterns.items():
                offset = data.find(pattern)
                while offset >= 0 and offset < limit:
                    address = pos + offset
                    kind, value = inspect_hit(data, offset, address, card_id)
                    key = (card_id, base, kind)
                    counts[key]["hits"] += 1
                    if value is not None:
                        values[key][value] += 1
                    if len(examples[key]) < max_examples:
                        start = max(0, offset - 16)
                        stop = min(len(data), offset + 32)
                        examples[key].append({
                            "address": f"0x{address:X}",
                            "value": value,
                            "context_address": f"0x{pos + start:X}",
                            "context_hex": data[start:stop].hex(" "),
                        })
                    offset = data.find(pattern, offset + 1)
            pos += CHUNK
    return counts, values, examples, regions, unreadable


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, help="Arena PID; auto-detected by default")
    parser.add_argument("--max-examples", type=int, default=2,
                        help="Examples shown per card, region and match type (default 2)")
    parser.add_argument("--output", type=Path, help="Optional JSON diagnostic report")
    args = parser.parse_args()
    if args.max_examples < 0:
        parser.error("--max-examples must be >= 0")

    pid = args.pid or find_arena_pid()
    if not pid:
        raise SystemExit("MTGA.exe not found.")
    handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    print(f"MTGA PID: {pid} | scanning readable memory for {len(DEFAULT_CARDS)} IDs")
    print("All values below are raw memory values, NOT confirmed ownership.\n", flush=True)
    try:
        counts, values, examples, regions, unreadable = scan(
            handle, DEFAULT_CARDS, args.max_examples
        )
    finally:
        kernel32.CloseHandle(handle)

    report = {"pid": pid, "readable_regions": regions,
              "short_or_unreadable_chunks": unreadable, "cards": []}
    for card_id, name, expected in DEFAULT_CARDS:
        print(f"\n{name} | ID {card_id} | Arena UI expected x{expected}")
        print("-" * 72)
        card_report = {"card_id": card_id, "name": name,
                       "expected_ui_quantity": expected, "regions": []}
        matching = sorted((key for key in counts if key[0] == card_id),
                          key=lambda key: (key[1], key[2]))
        if not matching:
            print("  No occurrences found in successfully scanned memory")
        totals = Counter()
        for key in matching:
            _, base, kind = key
            count = counts[key]["hits"]
            totals[kind] += count
            value_counts = dict(sorted(values[key].items()))
            print(f"  region=0x{base:X} | {kind} | hits={count} | values={value_counts}")
            for item in examples[key]:
                print(f"    {item['address']} value={item['value']}")
                print(f"      context [{item['context_address']}]: {item['context_hex']}")
            card_report["regions"].append({
                "base": f"0x{base:X}", "kind": kind, "hits": count,
                "value_counts": {str(k): v for k, v in value_counts.items()},
                "examples": examples[key],
            })
        print(f"  TOTAL: {dict(totals)}")
        report["cards"].append(card_report)
    print(f"\nScanned readable regions: {regions}; short/unreadable chunks: {unreadable}")
    print("repeated_id = [ID, FFFFFFFF, ID, value]; id_value = aligned [ID, value].")
    print("Note: id_value matches may overlap repeated_id records at their repeated ID.")
    print("A positive value is not by itself evidence of card ownership.")
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"Saved diagnostic report: {args.output}")


if __name__ == "__main__":
    main()
