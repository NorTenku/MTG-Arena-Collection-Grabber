"""Read-only MTGA inspection of 16-byte records neighbouring Last Light.

Run with 64-bit Windows Python, alongside find_arena.py and search_card_memory.py.
All values are unverified memory fields, NOT established ownership counts.
"""

import argparse
import ctypes
import gzip
import json
import struct
import sys
from pathlib import Path

if sys.platform != "win32" or ctypes.sizeof(ctypes.c_void_p) != 8:
    raise SystemExit("Run with 64-bit Windows Python (py.exe -3).")

from find_arena import find_arena_pid
from search_card_memory import (
    MEM_COMMIT, PAGE_GUARD, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    READABLE, MEMORY_BASIC_INFORMATION, kernel32, read_bytes,
)

RECORD = struct.Struct("<IIII")
LAST_LIGHT = 103481
# These addresses were confirmed in PID 6660; revalidate before using.
DEFAULT_ADDRESSES = [0x2457595F490, 0x24547C93490]


def inspect_window(handle, anchor, neighbours):
    mbi = MEMORY_BASIC_INFORMATION()
    if not kernel32.VirtualQueryEx(
        handle, ctypes.c_void_p(anchor), ctypes.byref(mbi), ctypes.sizeof(mbi)
    ):
        return {"anchor": hex(anchor), "error": "VirtualQueryEx failed"}
    base = int(mbi.BaseAddress or 0)
    end = base + int(mbi.RegionSize)
    result = {"anchor": hex(anchor), "region_base": hex(base),
              "region_size": int(mbi.RegionSize), "records": []}
    if not (mbi.State == MEM_COMMIT and
            (mbi.Protect & 0xFF) in READABLE and
            not (mbi.Protect & PAGE_GUARD)):
        result["error"] = "Memory region is no longer readable"
        return result
    start = anchor - neighbours * RECORD.size
    size = (2 * neighbours + 1) * RECORD.size
    if start < base or start + size > end:
        result["error"] = "Requested window crosses readable region boundary"
        return result
    data = read_bytes(handle, start, size)
    if len(data) != size:
        result["error"] = f"Short read: requested {size} bytes, received {len(data)}"
        return result

    a, b, c, d = RECORD.unpack_from(data, neighbours * RECORD.size)
    if (a, c) != (LAST_LIGHT, LAST_LIGHT) or b == 0xFFFFFFFF:
        result["error"] = (
            f"Anchor changed: found [{a}, {b}, {c}, {d}] instead of "
            f"a non-FFFFFFFF repeated-ID record for {LAST_LIGHT}"
        )
        return result

    for i in range(2 * neighbours + 1):
        cid, field_a, repeated_cid, field_b = RECORD.unpack_from(data, i * RECORD.size)
        row = {"offset": i - neighbours, "address": hex(start + i * RECORD.size),
               "card_id": cid, "field_a": field_a,
               "repeated_card_id": repeated_cid, "field_b": field_b,
               "repeated_id": cid == repeated_cid,
               "format": ("sentinel" if field_a == 0xFFFFFFFF else "non_sentinel")
                         if cid == repeated_cid else "other"}
        result["records"].append(row)
    return result


def load_scryfall(path, ids):
    """Look up only nearby Arena IDs, streaming Scryfall JSONL (optionally gzip)."""
    resolved = {cid: [] for cid in ids}
    op = gzip.open if path.name.lower().endswith(".gz") else open
    with op(path, "rt", encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid Scryfall JSONL at line {line_number}: {exc}") from exc
            if not isinstance(obj, dict):
                continue
            cid = obj.get("arena_id")
            if cid in resolved:
                resolved[cid].append({key: obj.get(key) for key in
                    ("name", "set", "collector_number", "artist", "type_line")})
    return resolved


def load_collection_ids(path):
    """Read IDs from the existing provisional export, without changing it."""
    payload = json.loads(path.read_text(encoding="utf-8"))
    runs = payload.get("runs", [])
    ids = set()
    for run in runs:
        for item in run.get("records", []):
            if int(item.get("quantity", 0)) > 0:
                ids.add(int(item["card_id"]))
    return ids


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, help="Arena process ID (default: auto-detect)")
    parser.add_argument("--address", action="append", type=lambda v: int(v, 0),
                        help="Use a custom Last Light record address (repeatable)")
    parser.add_argument("--neighbours", type=int, default=12,
                        help="Number of records either side of anchor (default 12)")
    parser.add_argument("--scryfall", type=Path,
                        help="Optional Scryfall default_cards JSONL or JSONL.gz for names")
    parser.add_argument("--collection", type=Path,
                        help="Optional existing provisional collection.json for cross-check")
    parser.add_argument("--output", type=Path, help="Save structured JSON report")
    args = parser.parse_args()
    if not 1 <= args.neighbours <= 100:
        parser.error("--neighbours must be between 1 and 100")
    for file_arg in (args.scryfall, args.collection):
        if file_arg is not None and not file_arg.is_file():
            parser.error(f"File not found: {file_arg}")
    pid = args.pid if args.pid is not None else find_arena_pid()
    if not pid:
        raise SystemExit("MTGA.exe not found. Keep Arena running, or specify --pid.")
    handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        windows = [inspect_window(handle, addr, args.neighbours)
                   for addr in (args.address or DEFAULT_ADDRESSES)]
    finally:
        kernel32.CloseHandle(handle)

    valid = [w for w in windows if "error" not in w]
    ids = {row["card_id"] for w in valid for row in w["records"]
           if row["repeated_id"]}
    names = load_scryfall(args.scryfall, ids) if args.scryfall and ids else {}
    collection_ids = load_collection_ids(args.collection) if args.collection else None
    for w in valid:
        for row in w["records"]:
            card = names.get(row["card_id"], []) if row["repeated_id"] else []
            row["scryfall"] = card
            row["in_provisional_export"] = (
                row["card_id"] in collection_ids if collection_ids is not None else None
            )

    report = {
        "pid": pid,
        "warning": "Raw fields only: no ownership interpretation",
        "scryfall_file": str(args.scryfall) if args.scryfall else None,
        "collection_file": str(args.collection) if args.collection else None,
        "windows": windows,
    }
    print(f"MTGA PID {pid} | Last Light neighbouring records | read-only")
    print("Field A and Field B are raw values; neither is confirmed to mean ownership.")
    for i, w in enumerate(windows, 1):
        print(f"\nWINDOW {i}: anchor={w['anchor']} region={w.get('region_base', '?')}")
        if "error" in w:
            print(f"  WARNING: {w['error']}")
            continue
        print("  offset  card_id  field_A  field_B  format        export  card (Scryfall)")
        for row in w["records"]:
            matches = row.get("scryfall", [])
            label = (" / ".join(f"{m['name']} [{str(m['set']).upper()} "
                              f"#{m['collector_number']}]" for m in matches[:2])
                     if matches else "(unresolved)")
            if row["format"] == "other":
                label = f"MISMATCH: repeated ID is {row['repeated_card_id']}"
            present = row["in_provisional_export"]
            export = ("yes" if present else "no") if present is not None else "?"
            a_value = "-1" if row["field_a"] == 0xFFFFFFFF else str(row["field_a"])
            print(f"  {row['offset']:+5d} {row['card_id']:>8} {a_value:>8} "
                  f"{row['field_b']:>8}  {row['format']:<12}  {export:>5}  {label}")

    if len(valid) >= 2:
        baseline = valid[0]["records"]
        print("\nCROSS-WINDOW COMPARISON")
        for second in valid[1:]:
            mismatches = [a["offset"] for a, b in zip(baseline, second["records"])
                          if (a["card_id"], a["field_a"], a["repeated_card_id"], a["field_b"])
                          != (b["card_id"], b["field_a"], b["repeated_card_id"], b["field_b"])]
            print(f"  {valid[0]['anchor']} vs {second['anchor']}: "
                  f"{len(baseline) - len(mismatches)}/{len(baseline)} records identical "
                  f"at matching relative offsets")
            if mismatches:
                print(f"  Mismatched offsets: {mismatches}")

    if valid:
        candidate_rows = [r for r in valid[0]["records"]
                          if r["offset"] != 0 and r["format"] == "non_sentinel" and
                          r["field_b"] == 1]
        if collection_ids is not None:
            candidate_rows.sort(key=lambda r: r["in_provisional_export"])
        print("\nPOTENTIAL ARENA UI CHECKS (not assumed owned; verify exact printings)")
        for row in candidate_rows[:8]:
            cards = row.get("scryfall", [])
            name = (f"{cards[0]['name']} [{cards[0]['set'].upper()} "
                    f"#{cards[0]['collector_number']}]" if cards else "unresolved")
            print(f"  {row['card_id']} | A={row['field_a']} B={row['field_b']} | "
                  f"{name} | in provisional export={row['in_provisional_export']}")
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\nSaved {args.output}")


if __name__ == "__main__":
    main()
