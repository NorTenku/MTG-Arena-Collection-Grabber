"""Export a *candidate*, read-only MTG Arena collection from two matching mixed-format runs.

Requires the existing inspect_mixed_collection.py, search_card_memory.py, and
find_arena.py alongside this file in windows/. Run with 64-bit Windows Python.

This is a controlled follow-up to the October 2026 mixed-record investigation.
It is NOT a general-purpose authoritative Arena collection reader. Two copies
of the same in-memory dataset may share the same underlying error.

No process writes. Refuses to change existing collection.json or to overwrite
any existing output, and refuses to export unless every check succeeds.
"""

import argparse
from collections import Counter
from datetime import datetime, timezone
import ctypes
import hashlib
import json
from pathlib import Path
import struct
import sys

from inspect_mixed_collection import (
    DEFAULT_ANCHORS,
    RECORD,
    SEED_ID,
    SENTINEL,
    analyze_window,
    compare_seed_runs,
    load_collection,
    read_window,
)

# UI quantities independently checked in Arena. Zero is an unowned control;
# absence from the *selected run* is required. A zero record elsewhere in
# process memory is not evidence of ownership or non-ownership.
UI_CHECKS = {
    75446: ("Charmed Stray", 4),
    93726: ("Fleeting Flight", 2),
    93855: ("Healer's Hawk", 2),
    103481: ("Last Light of Durin's Day", 1),
    103497: ("Beorn, Reluctant Host", 1),
    103429: ("Sound the Trumpets", 1),
    103461: ("Stony-Voiced Goblins", 2),
    103533: ("Duskwatch Hunter", 3),
    103529: ("Bolg's Company", 1),
    93784: ("Stab [FDN #71]", 4),
    93831: ("Dreadwing Scavenger [FDN #118]", 4),
    93905: ("Burst Lightning [FDN #192]", 4),
    103373: ("Bofur, Reliable Guardian [HOB #6]", 4),
    103377: ("Dwarven Provisioner [HOB #9]", 4),
    76519: ("Devouring Tendrils", 0),
    76644: ("Spirit Summoning", 0),
    67692: ("Ajani's Welcome", 0),
}

PROTECTED_NAMES = {
    "collection.json", "ownership_checks.json", "resolved_cards.json",
    "card_index.json", "decks.json", "scryfall_default_cards.jsonl.gz",
}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def validate_windows(windows, baseline, expected_records):
    """Pure validation; returns accepted records and a detailed audit."""
    require(len(windows) == 2, "Exactly two independently addressed runs are required")
    require(len(baseline) > 0, "Baseline is empty")

    anchor_addresses = [int(w["anchor"], 16) for w in windows]
    require(len(set(anchor_addresses)) == 2, "Anchors must be at distinct addresses")

    for idx, w in enumerate(windows, 1):
        s = w["seed_run_summary"]
        rows = w["seed_records"]
        require(not w["read_notes"], f"Copy {idx}: memory read notes: {w['read_notes']}")
        require(not w["seed_run_clipped_left"] and not w["seed_run_clipped_right"],
                f"Copy {idx}: the record sequence is clipped at a scan boundary")
        require(s["record_count"] == expected_records,
                f"Copy {idx}: expected {expected_records:,} records, found {s['record_count']:,}")
        require(s["unique_ids"] == expected_records,
                f"Copy {idx}: duplicate IDs in contiguous run")
        require(not s["quantity_conflicts"], f"Copy {idx}: conflicting quantities")
        require(not s["export_quantity_mismatches"],
                f"Copy {idx}: some quantities disagree with the baseline")
        require(len(rows) == expected_records, f"Copy {idx}: record count disagreement")
        require(sum(r["card_id"] == SEED_ID for r in rows) == 1,
                f"Copy {idx}: seed ID missing or duplicated")
        for pos, r in enumerate(rows):
            require(r["field_b"] in (1, 2, 3, 4),
                    f"Copy {idx}: bad quantity at record {pos}")
            require(r["format"] in ("sentinel", "non_sentinel"),
                    f"Copy {idx}: unknown format at record {pos}")
            if r["format"] == "sentinel":
                require(r["field_a"] == -1,
                        f"Copy {idx}: inconsistent sentinel format at record {pos}")
            else:
                require(r["field_a"] != -1,
                        f"Copy {idx}: inconsistent non-sentinel format at record {pos}")

    comparison = compare_seed_runs(windows[0], windows[1])
    require(comparison["same_complete_run"] and
            comparison["compared_offsets"] == expected_records and
            comparison["identical_offsets"] == expected_records,
            "Two memory copies do not contain the same complete, aligned run")

    records = windows[0]["seed_records"]
    by_id = {r["card_id"]: r for r in records}
    require(len(by_id) == len(records), "Duplicate card IDs in selected run")

    # Crucial: the old collection must equal the sentinel subset, with exactly
    # the same quantities. This detects other formats introduced by Arena or
    # changes that invalidate our earlier interpretation.
    sentinel = {r["card_id"]: r["field_b"] for r in records
                if r["format"] == "sentinel"}
    baseline_single = {}
    for cid, quantities in baseline.items():
        require(len(quantities) == 1,
                f"Old export has conflicting quantities for card ID {cid}")
        baseline_single[cid] = next(iter(quantities))
    require(sentinel == baseline_single,
            "Sentinel subset differs from existing collection.json; refusing export")

    non_sentinel = {r["card_id"]: r["field_b"] for r in records
                    if r["format"] == "non_sentinel"}
    require(not (non_sentinel.keys() & baseline_single.keys()),
            "A non-sentinel record overlaps with the baseline")
    require(len(non_sentinel) > 0, "No new non-sentinel records found")

    validations = {}
    for cid, (name, expected) in UI_CHECKS.items():
        observed = by_id[cid]["field_b"] if cid in by_id else None
        passed = (observed == expected) if expected else observed is None
        validations[str(cid)] = {
            "name": name, "expected": expected,
            "observed": observed, "passed": passed,
        }
    failed = [f"{card_id} ({c['name']}): expected={c['expected']} observed={c['observed']}"
              for card_id, c in validations.items() if not c["passed"]]
    require(not failed, "Independent UI ownership checks failed: " + "; ".join(failed))

    # An ordered signature is more informative than a map. Exclude addresses,
    # which naturally differ across copies; include both fields and order.
    signature = [[r["card_id"], r["field_a"], r["field_b"]] for r in records]
    digest = hashlib.sha256(json.dumps(signature, separators=(",", ":")).encode()).hexdigest()
    return records, {
        "old_export_unique_ids": len(baseline_single),
        "candidate_unique_ids": len(by_id),
        "new_non_sentinel_ids": len(non_sentinel),
        "format_counts": dict(Counter(r["format"] for r in records)),
        "copy_comparison": comparison,
        "ui_checks": validations,
        "record_signature_sha256": digest,
    }


def make_payload(pid, windows, rows, audit, collection_path):
    start = int(rows[0]["address"], 16)
    stop = int(rows[-1]["address"], 16) + RECORD.size
    return {
        "status": "candidate_unconfirmed",
        "source": "mtga_process_memory_read_only_mixed_format",
        "extracted_at": datetime.now(timezone.utc).isoformat(),
        "pid": pid,
        "anchor_address": windows[0]["anchor"],
        "scan_start": hex(start),
        "scan_bytes": stop - start,
        "anchor_run_length": len(rows),
        "selection_method": "two_matching_contiguous_mixed_format_runs_with_ui_checks",
        "selection_group_anchors": [w["anchor"] for w in windows],
        "baseline_source": str(collection_path),
        "reference_validation": audit["ui_checks"],
        "mixed_format_audit": {
            key: val for key, val in audit.items() if key != "ui_checks"
        },
        # Keep familiar 'runs' schema for existing downstream tools. Extra
        # fields preserve evidence without altering card_id/quantity semantics.
        "runs": [{
            "run_id": 0,
            "start_address": hex(start),
            "record_count": len(rows),
            "records": [{
                "card_id": r["card_id"],
                "quantity": r["field_b"],
                "field_a": r["field_a"],
                "record_format": r["format"],
            } for r in rows],
        }],
        "caution": ("Provisional candidate, not proof of complete ownership. "
                    "Card ID quantities must not be multiplied for card styles/appearances."),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, help="Arena PID; auto-detected by default")
    parser.add_argument("--anchor", action="append", type=lambda s: int(s, 0),
                        help="Confirmed Last Light record address; specify twice for two copies")
    parser.add_argument("--collection", type=Path, required=True,
                        help="Original collection.json (read-only baseline)")
    parser.add_argument("--output", type=Path, required=True,
                        help="New candidate JSON; must not exist already")
    parser.add_argument("--expected-records", type=int, default=1660,
                        help="Required sequence length (default: 1660, from validated diagnostic)")
    parser.add_argument("--window-kb", type=int, default=256,
                        help="Read this many KB on EACH side of each anchor (default: 256)")
    args = parser.parse_args()

    if args.expected_records < 100:
        parser.error("--expected-records must be >= 100")
    if not 64 <= args.window_kb <= 4096 or args.window_kb % 4:
        parser.error("--window-kb must be a multiple of 4 from 64 to 4096")
    if not args.collection.is_file():
        parser.error("Baseline collection file does not exist")
    if args.output.name.lower() in PROTECTED_NAMES:
        parser.error("Refusing to use a protected production filename")
    if args.output.resolve() == args.collection.resolve():
        parser.error("Refusing to overwrite the existing collection")
    if args.output.exists():
        parser.error("Output already exists; choose another filename rather than overwrite")
    if sys.platform != "win32" or ctypes.sizeof(ctypes.c_void_p) != 8:
        parser.error("Run with 64-bit Windows Python (py.exe -3), not WSL Python")

    anchors = args.anchor or list(DEFAULT_ANCHORS)
    if len(anchors) != 2 or len(set(anchors)) != 2:
        parser.error("Exactly two DISTINCT anchors are required")

    from find_arena import find_arena_pid
    from search_card_memory import (
        MEM_COMMIT, PAGE_GUARD, READABLE, MEMORY_BASIC_INFORMATION,
        PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, kernel32, read_bytes,
    )

    baseline = load_collection(args.collection)
    pid = args.pid if args.pid is not None else find_arena_pid()
    if not pid:
        raise SystemExit("Arena process not found")
    handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())

    print(f"MTGA PID: {pid} | strict mixed-format candidate export (READ-ONLY)")
    windows = []
    try:
        for index, anchor in enumerate(anchors, 1):
            print(f"Scanning copy {index}/2 at {anchor:#x}...")
            window = read_window(handle, anchor, args.window_kb * 1024,
                                 kernel32, MEMORY_BASIC_INFORMATION, read_bytes,
                                 READABLE, MEM_COMMIT, PAGE_GUARD)
            analyzed = analyze_window(window, anchor, baseline, min_run=8)
            summary = analyzed["seed_run_summary"]
            print(f"  Found {summary['record_count']:,} records; "
                  f"sentinel={summary['sentinel_records']:,}, "
                  f"non-sentinel={summary['non_sentinel_records']:,}")
            windows.append(analyzed)
    finally:
        kernel32.CloseHandle(handle)

    rows, audit = validate_windows(windows, baseline, args.expected_records)
    payload = make_payload(pid, windows, rows, audit, args.collection)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    # Exclusive creation also guards against output appearing during the scan.
    with args.output.open("x", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
        f.write("\n")

    print("\nPASS: all checks succeeded")
    print(f"  Identical copies: {audit['copy_comparison']['identical_offsets']:,} / "
          f"{audit['copy_comparison']['compared_offsets']:,}")
    print(f"  Old export matched: {audit['old_export_unique_ids']:,} sentinel records")
    print(f"  Additional candidates: {audit['new_non_sentinel_ids']:,} non-sentinel records")
    print(f"  Candidate total: {audit['candidate_unique_ids']:,} IDs")
    print(f"  Independent ownership controls: {len(audit['ui_checks'])} / "
          f"{len(audit['ui_checks'])} passed")
    print(f"  Signature SHA-256: {audit['record_signature_sha256']}")
    print(f"Saved: {args.output}")
    print("Existing collection.json and extract_collection.py were NOT modified.")
    print("Status remains CANDIDATE until further checks establish completeness.")


if __name__ == "__main__":
    main()
