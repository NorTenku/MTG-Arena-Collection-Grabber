"""Read-only investigation of contiguous mixed-format MTG Arena card records.

Looks for adjacent 16-byte records [card_id, field_A, card_id, field_B]
near the two validated Last Light of Durin's Day memory locations.

IMPORTANT: Field B is *not* presumed to be ownership. No collection is
exported or modified. Output is diagnostic evidence only.

Requires 64-bit Windows Python and the existing find_arena.py and
search_card_memory.py modules in the same windows/ directory.
"""

import argparse
from collections import Counter, defaultdict
import ctypes
import gzip
import json
from pathlib import Path
import struct
import sys

RECORD = struct.Struct('<IIII')
SENTINEL = 0xFFFFFFFF
SEED_ID = 103481
SEED_FIELD_A = 490
SEED_FIELD_B = 1
DEFAULT_ANCHORS = (0x2457595F490, 0x24547C93490)
CHUNK_BYTES = 64 * 1024

# Independently confirmed against the Arena UI. Expected 0 means unowned.
UI_CONTROLS = {
    75446: ('Charmed Stray', 4),
    93726: ('Fleeting Flight', 2),
    93855: ("Healer's Hawk", 2),
    103481: ("Last Light of Durin's Day", 1),
    103497: ('Beorn, Reluctant Host', 1),
    103429: ('Sound the Trumpets', 1),
    103461: ('Stony-Voiced Goblins', 2),
    103533: ('Duskwatch Hunter', 3),
    103529: ("Bolg's Company", 1),
    76519: ('Devouring Tendrils', 0),
    76644: ('Spirit Summoning', 0),
    67692: ("Ajani's Welcome", 0),
}


def parse_records(raw, start_address, min_card_id=1, max_card_id=500000):
    """Find aligned, adjacent runs of plausible positive-value repeated-ID records.

    start_address is aligned to the known 16-byte record boundary.
    Does NOT confer ownership meaning on anything it finds.
    """
    if start_address % RECORD.size:
        raise ValueError('Scan origin must align to 16-byte records')
    runs = []
    active = []
    usable_len = len(raw) - len(raw) % RECORD.size
    for offset in range(0, usable_len, RECORD.size):
        cid, meta, repeated, value = RECORD.unpack_from(raw, offset)
        if min_card_id <= cid <= max_card_id and repeated == cid and 1 <= value <= 4:
            active.append({
                'address': hex(start_address + offset),
                'card_id': cid,
                'field_a': -1 if meta == SENTINEL else meta,
                'field_b': value,
                'format': 'sentinel' if meta == SENTINEL else 'non_sentinel',
            })
        elif active:
            runs.append(active)
            active = []
    if active:
        runs.append(active)
    return runs


def load_collection(path):
    if path is None:
        return None
    payload = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(payload, dict) or not isinstance(payload.get('runs'), list):
        raise ValueError('Expected collection.json with a runs list')
    quantities = defaultdict(set)
    for run in payload['runs']:
        for item in run.get('records', []):
            cid, qty = int(item['card_id']), int(item['quantity'])
            if qty > 0:
                quantities[cid].add(qty)
    return dict(quantities)


def load_scryfall(path, ids):
    if path is None or not ids:
        return {}
    names = {}
    opener = gzip.open if path.name.lower().endswith('.gz') else open
    with opener(path, 'rt', encoding='utf-8') as stream:
        for line in stream:
            if not line.strip():
                continue
            card = json.loads(line)
            cid = card.get('arena_id')
            if cid in ids and cid not in names:
                names[cid] = {
                    'name': card.get('name'), 'set': card.get('set'),
                    'collector_number': card.get('collector_number'),
                    'artist': card.get('artist'),
                }
    return names


def read_window(handle, anchor, side_budget, kernel32, mbi_class, read_bytes, readable, mem_commit, guard):
    """Read outward from an anchor across *readable* VirtualQueryEx boundaries.

    Stops at any inaccessible region or short read; never skips a gap.
    Returned data remains aligned to 16-byte records.
    """
    def region_at(address):
        mbi = mbi_class()
        result = kernel32.VirtualQueryEx(
            handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi))
        if not result:
            return None, 'VirtualQueryEx failed at ' + hex(address)
        base = int(mbi.BaseAddress or 0)
        end = base + int(mbi.RegionSize)
        if not (mbi.State == mem_commit and
                (mbi.Protect & 0xFF) in readable and not (mbi.Protect & guard)):
            return None, 'Unreadable region at ' + hex(address)
        return (base, end), None

    seed = read_bytes(handle, anchor, RECORD.size)
    if len(seed) != RECORD.size:
        raise RuntimeError(f'Cannot read seed record at {anchor:#x}')
    if RECORD.unpack(seed) != (SEED_ID, SEED_FIELD_A, SEED_ID, SEED_FIELD_B):
        raise RuntimeError(
            f'Seed changed at {anchor:#x}: got {RECORD.unpack(seed)}, '
            f'expected {(SEED_ID, SEED_FIELD_A, SEED_ID, SEED_FIELD_B)}. '
            'Arena may have reallocated memory. Do not use stale addresses.')

    notes = []
    left_blocks, right_blocks = [], []
    left_cursor, right_cursor = anchor, anchor + RECORD.size
    left_count = right_count = 0

    while left_count < side_budget:
        if left_cursor == 0:
            notes.append('Left scan reached address zero')
            break
        region, error = region_at(left_cursor - 1)
        if error:
            notes.append('Left: ' + error)
            break
        base, _ = region
        n = min(CHUNK_BYTES, side_budget - left_count, left_cursor - base)
        n -= n % RECORD.size
        if n == 0:
            notes.append('Left: region boundary not aligned to 16-byte record')
            break
        data = read_bytes(handle, left_cursor - n, n)
        if len(data) != n:
            notes.append(f'Left: short read at {left_cursor - n:#x}: {len(data)}/{n}')
            break
        left_blocks.append(data)
        left_cursor -= n
        left_count += n

    while right_count < side_budget:
        region, error = region_at(right_cursor)
        if error:
            notes.append('Right: ' + error)
            break
        _, end = region
        n = min(CHUNK_BYTES, side_budget - right_count, end - right_cursor)
        n -= n % RECORD.size
        if n == 0:
            notes.append('Right: region boundary not aligned to 16-byte record')
            break
        data = read_bytes(handle, right_cursor, n)
        if len(data) != n:
            notes.append(f'Right: short read at {right_cursor:#x}: {len(data)}/{n}')
            break
        right_blocks.append(data)
        right_cursor += n
        right_count += n

    raw = b''.join(reversed(left_blocks)) + seed + b''.join(right_blocks)
    return {
        'start': left_cursor,
        'end': right_cursor,
        'data': raw,
        'seed_offset': anchor - left_cursor,
        'left_bytes': left_count,
        'right_bytes': right_count,
        'notes': notes,
    }


def characterize(records, export):
    vals = defaultdict(set)
    for row in records:
        vals[row['card_id']].add(row['field_b'])
    conflicts = {str(cid): sorted(qs) for cid, qs in vals.items() if len(qs) > 1}
    format_counts = Counter(row['format'] for row in records)
    novel = sorted(cid for cid in vals if export is not None and cid not in export)
    overlap_mismatches = {
        str(cid): {'observed': sorted(qs), 'export': sorted(export[cid])}
        for cid, qs in vals.items() if export is not None and cid in export and qs != export[cid]
    }
    controls = {}
    for cid, (name, expected) in UI_CONTROLS.items():
        observed = sorted(vals.get(cid, set()))
        passed = (not observed if expected == 0 else observed == [expected])
        controls[str(cid)] = {'name': name, 'expected': expected,
                              'observed': observed, 'passed': passed}
    return {
        'record_count': len(records), 'unique_ids': len(vals),
        'sentinel_records': format_counts['sentinel'],
        'non_sentinel_records': format_counts['non_sentinel'],
        'quantity_conflicts': conflicts,
        'new_ids_not_in_export': len(novel) if export is not None else None,
        'novel_ids': novel,
        'export_quantity_mismatches': overlap_mismatches,
        'controls': controls,
    }


def analyze_window(window, anchor, export, min_run):
    runs = parse_records(window['data'], window['start'])
    picked = [run for run in runs if any(int(row['address'], 16) == anchor for row in run)]
    if len(picked) != 1:
        raise RuntimeError(f'Expected exactly one seed-containing run at {anchor:#x}; found {len(picked)}')
    seed_run = picked[0]
    seed_summary = characterize(seed_run, export)
    all_rows = [row for run in runs for row in run]
    scanned_summary = characterize(all_rows, export)
    retained_runs = [run for run in runs if len(run) >= min_run or run is seed_run]
    beginning, ending = int(seed_run[0]['address'], 16), int(seed_run[-1]['address'], 16) + 16
    return {
        'anchor': hex(anchor),
        'window_start': hex(window['start']),
        'window_end': hex(window['end']),
        'scanned_bytes': len(window['data']),
        'side_bytes_left': window['left_bytes'],
        'side_bytes_right': window['right_bytes'],
        'read_notes': window['notes'],
        'seed_run_clipped_left': beginning == window['start'],
        'seed_run_clipped_right': ending == window['end'],
        'seed_run_summary': seed_summary,
        'entire_window_summary': scanned_summary,
        'runs_found_total': len(runs),
        'runs_retained': len(retained_runs),
        'runs': [{
            'start': run[0]['address'],
            'end_exclusive': hex(int(run[-1]['address'], 16) + 16),
            'record_count': len(run),
            'contains_seed': run is seed_run,
            'records': run,
        } for run in retained_runs],
        'seed_records': seed_run,
    }


def compare_seed_runs(a, b):
    def relative(run, anchor):
        return {
            (int(rec['address'], 16) - anchor) // RECORD.size:
            (rec['card_id'], rec['field_a'], rec['field_b'])
            for rec in run
        }
    ar = relative(a['seed_records'], int(a['anchor'], 16))
    br = relative(b['seed_records'], int(b['anchor'], 16))
    shared = ar.keys() & br.keys()
    mismatches = sorted(offset for offset in shared if ar[offset] != br[offset])
    return {'compared_offsets': len(shared), 'identical_offsets': len(shared) - len(mismatches),
            'mismatch_offsets': mismatches[:25],
            'same_complete_run': ar == br and not (
                a['seed_run_clipped_left'] or a['seed_run_clipped_right'] or
                b['seed_run_clipped_left'] or b['seed_run_clipped_right'])}


def label(cid, names):
    n = names.get(cid)
    if not n:
        return '(unresolved by local Scryfall)'
    return f"{n['name']} [{str(n['set']).upper()} #{n['collector_number']}]"


def print_report(results, names, export):
    for idx, w in enumerate(results, 1):
        s = w['seed_run_summary']
        whole = w['entire_window_summary']
        print(f'\nWINDOW {idx}: seed={w["anchor"]} range={w["window_start"]}..{w["window_end"]}')
        print(f'  Read {w["scanned_bytes"]:,} bytes across VirtualQueryEx boundaries; notes={w["read_notes"] or "none"}')
        print(f'  Found {w["runs_found_total"]:,} plausible positive-value runs; '
              f'{w["runs_retained"]:,} runs at least the retention threshold (plus seed run)')
        print(f'  Seed-containing run: {s["record_count"]:,} records, {s["unique_ids"]:,} distinct IDs')
        print(f'    sentinel={s["sentinel_records"]:,}  non-sentinel={s["non_sentinel_records"]:,}')
        print(f'    clipped at scan edge: left={w["seed_run_clipped_left"]} right={w["seed_run_clipped_right"]}')
        print(f'    within-seed-run quantity conflicts: {len(s["quantity_conflicts"])}')
        if export is not None:
            print(f'    IDs absent from provisional export: {s["new_ids_not_in_export"]:,}')
            print(f'    export quantity mismatches: {len(s["export_quantity_mismatches"])}')
        print(f'  All detected runs in this WINDOW (not automatically ownership): '
              f'{whole["record_count"]:,} records, {whole["unique_ids"]:,} IDs')
        print('  INDEPENDENT UI CONTROLS within seed run ("absent" on positive controls is not proof of error):')
        for cid, c in s['controls'].items():
            if c['observed'] or int(cid) == SEED_ID:
                status = 'PASS' if c['passed'] else 'FAIL'
                print(f'    {status:<4} {c["name"]:<30} expected={c["expected"]} observed={c["observed"]}')
        for cid, c in whole['controls'].items():
            if c['expected'] == 0 and c['observed']:
                print(f'  WARNING: unowned control appears POSITIVE elsewhere in window: '
                      f'{c["name"]} ({cid}) values={c["observed"]}')
        print('  Longest candidate runs in entire window:')
        biggest = sorted(w['runs'], key=lambda r: r['record_count'], reverse=True)
        for run in biggest[:6]:
            print(f'    {run["start"]} size={run["record_count"]:,} '
                  f'seed={run["contains_seed"]}')

        rows = [r for r in w['seed_records'] if r['format'] == 'non_sentinel' and
                (export is None or r['card_id'] not in export)]
        unique = {r['card_id']: r for r in rows}
        # Emphasise quantities >1: best for independent UI validation.
        picks = sorted(unique.values(), key=lambda r: (-r['field_b'], r['card_id']))[:15]
        print('  UI CHECK CANDIDATES from seed run (never assumed owned):')
        for r in picks:
            print(f'    {r["card_id"]} | A={r["field_a"]} B={r["field_b"]} | '
                  f'{label(r["card_id"], names)}')
        if s['quantity_conflicts']:
            print('  Conflicting ID values (first 10):', list(s['quantity_conflicts'].items())[:10])
        if s['export_quantity_mismatches']:
            print('  Export mismatches (first 10):', list(s['export_quantity_mismatches'].items())[:10])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid', type=int, help='PID; default auto-detect')
    parser.add_argument('--anchor', action='append', type=lambda s: int(s, 0),
                        help='Last Light record address (repeatable); defaults to two known addresses')
    parser.add_argument('--window-kb', type=int, default=256,
                        help='KB read on EACH side of each anchor (default: 256; max: 4096)')
    parser.add_argument('--min-run', type=int, default=8,
                        help='Keep other runs of this length or longer in JSON (default: 8)')
    parser.add_argument('--collection', type=Path,
                        help='Existing provisional collection.json (read-only)')
    parser.add_argument('--scryfall', type=Path,
                        help='Local Scryfall JSONL.gz file (read-only)')
    parser.add_argument('--output', type=Path, required=True,
                        help='New diagnostic JSON report path; collection.json is protected')
    args = parser.parse_args()
    if not 4 <= args.window_kb <= 4096 or args.window_kb % 4:
        parser.error('--window-kb must be a multiple of 4 between 4 and 4096')
    if not 1 <= args.min_run <= 1000:
        parser.error('--min-run must be between 1 and 1000')
    if any(not path.is_file() for path in (args.collection, args.scryfall) if path is not None):
        parser.error('The --collection and/or --scryfall file does not exist')
    for protected in (args.collection, args.scryfall):
        if protected is not None and args.output.resolve() == protected.resolve():
            parser.error('Diagnostic output must not overwrite input files')
    if args.output.name.lower() in {'collection.json', 'resolved_cards.json', 'ownership_checks.json'}:
        parser.error('Refusing to overwrite a production data file')
    if sys.platform != 'win32' or ctypes.sizeof(ctypes.c_void_p) != 8:
        parser.error('Use 64-bit Windows Python (py.exe -3), not WSL Python')

    from find_arena import find_arena_pid
    from search_card_memory import (MEM_COMMIT, PAGE_GUARD, READABLE,
        MEMORY_BASIC_INFORMATION, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
        kernel32, read_bytes)

    pid = args.pid if args.pid is not None else find_arena_pid()
    if not pid:
        raise SystemExit('MTGA.exe not found')
    handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())

    export = load_collection(args.collection)
    print(f'MTGA PID {pid} | mixed-format card record investigation (READ-ONLY)')
    print('CAUTION: Field B and other fields are raw observations, NOT proven ownership counts.')
    anchors = args.anchor or list(DEFAULT_ANCHORS)
    results = []
    try:
        for anchor in anchors:
            window = read_window(handle, anchor, args.window_kb * 1024,
                                 kernel32, MEMORY_BASIC_INFORMATION, read_bytes,
                                 READABLE, MEM_COMMIT, PAGE_GUARD)
            results.append(analyze_window(window, anchor, export, args.min_run))
    finally:
        kernel32.CloseHandle(handle)

    ids = {r['card_id'] for w in results for r in w['seed_records']}
    names = load_scryfall(args.scryfall, ids)
    print_report(results, names, export)
    comparisons = []
    if len(results) >= 2:
        for other in results[1:]:
            c = compare_seed_runs(results[0], other)
            comparisons.append(c)
            print('\nCROSS-WINDOW SEED-RUN COMPARISON: '
                  f'{c["identical_offsets"]}/{c["compared_offsets"]} shared offsets identical; '
                  f'complete runs same={c["same_complete_run"]}')
            if c['mismatch_offsets']:
                print('  First different relative record positions:', c['mismatch_offsets'])

    report = {
        'pid': pid, 'status': 'diagnostic_only',
        'caution': 'No field proves ownership; false positives exist in some memory datasets.',
        'collection_source': str(args.collection) if args.collection else None,
        'export_unique_ids': len(export) if export is not None else None,
        'scan_window_kb_each_side': args.window_kb,
        'scryfall_source': str(args.scryfall) if args.scryfall else None,
        'scryfall_card_names': {str(k): v for k, v in names.items()},
        'cross_window_comparisons': comparisons,
        'windows': results,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(f'\nSaved diagnostic JSON: {args.output}')
    print('No changes made to Arena or to the provisional collection export.')


if __name__ == '__main__':
    main()
