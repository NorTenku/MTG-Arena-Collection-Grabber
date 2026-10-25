#!/usr/bin/env python3
"""Read-only, auto-discovering mixed-format MTG Arena collection candidate exporter.

Standalone companion to extract_collection.py: does not modify the legacy extractor.
Windows 64-bit Python is required for live process inspection; --self-test also
works on Linux/WSL using the saved reference JSON.

Strategy:
  1. Scan readable MTGA.exe memory for known repeated-ID anchors (no addresses).
  2. Expand around each hit across *adjacent readable* VirtualQueryEx regions.
  3. Keep only complete, contiguous 16-byte mixed-format card sequences.
  4. Require two distinct memory copies with identical ordered triples.
  5. Cross-check reference overlap, quantities, and independently observed UI
     positive and unowned controls. Fail closed if any condition fails.
  6. Optionally export one new, non-overwriting candidate JSON file.

This is a candidate extractor, NOT a proof that every owned card was discovered.
No writes, injection, or MTGA game-file modifications occur.
"""

import argparse
from collections import Counter, defaultdict
import ctypes
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct
import sys

from inspect_mixed_collection import RECORD, SENTINEL, analyze_window

# Only stable ID/record-structure signatures are used, never prior heap addresses.
SENTINEL_ANCHOR = 75446  # Charmed Stray [id, FFFFFFFF, id, quantity]
MIXED_ANCHOR = 103481   # Last Light [id, any other metadata, id, quantity]
MAX_ARENA_ID = 500000
SCAN_CHUNK = 1024 * 1024
SCAN_OVERLAP = 16
READ_CHUNK = 64 * 1024
MIN_RUN_RECORDS = 300
MIN_REFERENCE_COVERAGE = 0.90
MIN_QUANTITY_AGREEMENT = 0.95
MIN_REFERENCE_SIZE_RATIO = 0.75
MAX_REFERENCE_SIZE_RATIO = 1.50
PROTECTED_NAMES = {
    'collection.json', 'collection_candidate.json', 'ownership_checks.json',
    'resolved_cards.json', 'card_index.json', 'decks.json',
    'scryfall_default_cards.jsonl.gz',
}


def require(test, reason):
    if not test:
        raise RuntimeError(reason)


def load_reference(path):
    data = json.loads(path.read_text(encoding='utf-8'))
    require(isinstance(data, dict) and isinstance(data.get('runs'), list),
            'Reference must be an exported collection JSON containing runs')
    records = [r for run in data['runs'] for r in run.get('records', [])]
    require(len(records) >= MIN_RUN_RECORDS, 'Reference is unexpectedly small')
    ids = [r['card_id'] for r in records]
    require(len(ids) == len(set(ids)), 'Duplicate card IDs in reference')
    quantities = {}
    for r in records:
        cid, qty = r['card_id'], r['quantity']
        require(type(cid) is int and 1 <= cid <= MAX_ARENA_ID and
                type(qty) is int and 1 <= qty <= 4,
                f'Invalid reference record {r!r}')
        quantities[cid] = qty
    controls = data.get('reference_validation')
    require(isinstance(controls, dict) and len(controls) >= 10,
            'Reference lacks the previously independently verified UI controls')
    require(sum(c['expected'] == 0 for c in controls.values()) >= 2,
            'Reference lacks unowned controls')
    for cid_string, control in controls.items():
        cid = int(cid_string)
        expected = control['expected']
        require(0 <= expected <= 4, f'Invalid control quantity for {cid}')
        # Check reference itself has not been modified to contradict its controls.
        require(quantities.get(cid, 0) == expected,
                f'Reference contradicts UI control {cid} ({control.get("name")})')
    return data, quantities, controls


def evaluate_controls(records, controls):
    by_id = {r['card_id']: r['field_b'] for r in records}
    validation = {}
    for cid_string, c in controls.items():
        cid = int(cid_string)
        expected = int(c['expected'])
        observed = by_id.get(cid)
        passed = (observed == expected if expected else observed is None)
        validation[cid_string] = {
            'name': c['name'], 'expected': expected,
            'observed': observed, 'passed': passed,
        }
    return validation


def assess_run(window, reference, controls):
    """Pure, offline-testable assessment of a contiguous candidate run."""
    rows = window['seed_records']
    reasons = []
    summary = window['seed_run_summary']
    if window['read_notes']:
        reasons.append('memory read was incomplete: ' + '; '.join(window['read_notes'][:3]))
    if window['seed_run_clipped_left'] or window['seed_run_clipped_right']:
        reasons.append('run was clipped by scan window')
    if len(rows) < MIN_RUN_RECORDS:
        reasons.append(f'only {len(rows)} records')
    if len(rows) != len({r['card_id'] for r in rows}):
        reasons.append('duplicate IDs')
    if summary['quantity_conflicts']:
        reasons.append('quantity conflicts')
    if not any(r['format'] == 'sentinel' for r in rows) or not any(
            r['format'] == 'non_sentinel' for r in rows):
        reasons.append('missing one of the two expected record formats')
    ids = {r['card_id']: r['field_b'] for r in rows}
    overlap = reference.keys() & ids.keys()
    coverage = len(overlap) / len(reference)
    qty_agreement = (sum(reference[cid] == ids[cid] for cid in overlap) / len(overlap)
                     if overlap else 0.0)
    ratio = len(rows) / len(reference)
    if not MIN_REFERENCE_SIZE_RATIO <= ratio <= MAX_REFERENCE_SIZE_RATIO:
        reasons.append(f'size ratio {ratio:.1%} outside reference range')
    if coverage < MIN_REFERENCE_COVERAGE:
        reasons.append(f'only {coverage:.1%} reference-ID coverage')
    if qty_agreement < MIN_QUANTITY_AGREEMENT:
        reasons.append(f'only {qty_agreement:.1%} reference quantity agreement')
    validations = evaluate_controls(rows, controls)
    failures = [f'{c["name"]}: expected {c["expected"]}, observed {c["observed"]}'
                for c in validations.values() if not c['passed']]
    if failures:
        reasons.append('UI controls fail: ' + '; '.join(failures[:5]))
    signature = tuple((r['card_id'], r['field_a'], r['field_b']) for r in rows)
    return {
        'valid': not reasons, 'reasons': reasons,
        'coverage': coverage, 'quantity_agreement': qty_agreement,
        'reference_additions': len(ids.keys() - reference.keys()),
        'reference_missing': len(reference.keys() - ids.keys()),
        'reference_quantity_changes': sum(reference[c] != ids[c] for c in overlap),
        'controls': validations, 'signature': signature,
        'count': len(rows),
    }


def select_consensus(windows, reference, controls):
    """Validate each complete run; require ONE passing group at >=2 locations."""
    groups = defaultdict(list)
    inspected = []
    seen_starts = set()
    for window in windows:
        start = int(window['seed_records'][0]['address'], 16)
        if start in seen_starts:
            continue  # multiple anchor hits pointing into the SAME memory copy
        seen_starts.add(start)
        review = assess_run(window, reference, controls)
        inspected.append((window, review))
        if review['valid']:
            groups[review['signature']].append((window, review))
    passing = [members for members in groups.values() if len(members) >= 2]
    require(len(passing) == 1,
            f'Need exactly one validated dataset found in 2+ locations; '
            f'found {len(passing)}. Distinct complete runs examined: {len(inspected)}. '
            f'Passing single-copy groups: {sum(len(g) == 1 for g in groups.values())}.')
    members = passing[0]
    # Never treat two anchors in one contiguous sequence as two independent copies.
    require(len({int(m[0]['seed_records'][0]['address'], 16) for m in members}) >= 2,
            'Matching anchors do not correspond to distinct memory sequences')
    return members, inspected


def build_payload(pid, selected, reference_path, reference, scanned_count):
    windows = [w for w, _ in selected]
    rows = windows[0]['seed_records']
    summary = selected[0][1]
    start = int(rows[0]['address'], 16)
    triples = [[r['card_id'], r['field_a'], r['field_b']] for r in rows]
    digest = hashlib.sha256(json.dumps(triples, separators=(',', ':')).encode()).hexdigest()
    return {
        'status': 'candidate_unconfirmed',
        'source': 'mtga_process_memory_read_only_mixed_format_autodiscovery',
        'extracted_at': datetime.now(timezone.utc).isoformat(),
        'pid': pid,
        'anchor_address': windows[0]['anchor'],
        'scan_start': hex(start),
        'scan_bytes': RECORD.size * len(rows),
        'anchor_run_length': len(rows),
        'selection_method': 'autodiscovery_matching_contiguous_mixed_runs_and_ui_controls',
        'selection_group_anchors': [w['anchor'] for w in windows],
        'selection_group_run_starts': [w['seed_records'][0]['address'] for w in windows],
        'reference_source': str(reference_path),
        'reference_comparison': {
            'reference_unique_ids': len(reference),
            'coverage': summary['coverage'],
            'quantity_agreement': summary['quantity_agreement'],
            'new_ids': summary['reference_additions'],
            'missing_ids': summary['reference_missing'],
            'changed_quantities': summary['reference_quantity_changes'],
        },
        'reference_validation': summary['controls'],
        'mixed_format_audit': {
            'candidate_unique_ids': len(rows),
            'format_counts': dict(Counter(r['format'] for r in rows)),
            'matching_copies': len(windows),
            'all_matching': True,
            'record_signature_sha256': digest,
            'anchor_hits_examined': scanned_count,
        },
        'runs': [{
            'run_id': 0,
            'start_address': hex(start),
            'record_count': len(rows),
            'records': [{
                'card_id': r['card_id'], 'quantity': r['field_b'],
                'field_a': r['field_a'], 'record_format': r['format'],
            } for r in rows],
        }],
        'caution': 'Unconfirmed candidate. Two copies can share errors; not proof of completeness.',
    }


def anchor_offsets(raw, base):
    """Yield validated 16-byte-aligned record starts inside a memory block."""
    sent_pattern = struct.pack('<III', SENTINEL_ANCHOR, SENTINEL, SENTINEL_ANCHOR)
    mixed_pattern = struct.pack('<I', MIXED_ANCHOR)
    found = set()
    pos = raw.find(sent_pattern)
    while pos >= 0:
        addr = base + pos
        if addr % 16 == 0 and pos + 16 <= len(raw):
            _, field_a, repeated, quantity = RECORD.unpack_from(raw, pos)
            if field_a == SENTINEL and repeated == SENTINEL_ANCHOR and 1 <= quantity <= 4:
                found.add(pos)
        pos = raw.find(sent_pattern, pos + 1)
    pos = raw.find(mixed_pattern)
    while pos >= 0:
        addr = base + pos
        if addr % 16 == 0 and pos + 16 <= len(raw):
            cid, meta, repeated, quantity = RECORD.unpack_from(raw, pos)
            if (cid == repeated == MIXED_ANCHOR and meta != SENTINEL
                    and 1 <= quantity <= 4):
                found.add(pos)
        pos = raw.find(mixed_pattern, pos + 1)
    return sorted(found)


def discover_anchors(handle, mem):
    """Search readable regions in bounded chunks for two stable card signatures."""
    kernel32, mbi_type, read_bytes = mem['kernel32'], mem['mbi'], mem['read_bytes']
    cursor = 0
    anchors = set()
    stats = {'regions': 0, 'chunks': 0, 'partial_chunks': 0, 'bytes_read': 0}
    while cursor < mem['max_address']:
        mbi = mbi_type()
        result = kernel32.VirtualQueryEx(
            handle, ctypes.c_void_p(cursor), ctypes.byref(mbi), ctypes.sizeof(mbi))
        if not result:
            break
        base = int(mbi.BaseAddress or 0)
        size = int(mbi.RegionSize)
        end = base + size
        if end <= cursor:
            raise RuntimeError('Invalid VirtualQueryEx region (non-increasing address)')
        cursor = end
        if not (mbi.State == mem['commit'] and
                (mbi.Protect & 0xFF) in mem['readable'] and
                not (mbi.Protect & mem['guard'])):
            continue
        stats['regions'] += 1
        pos = base
        while pos < end:
            primary = min(SCAN_CHUNK, end - pos)
            chunk = read_bytes(handle, pos, min(primary + SCAN_OVERLAP, end - pos))
            stats['chunks'] += 1
            stats['bytes_read'] += len(chunk)
            if len(chunk) < primary:
                stats['partial_chunks'] += 1
            # Count only records BEGINNING in the primary chunk, not in overlap.
            for offset in anchor_offsets(chunk, pos):
                if offset < primary:
                    anchors.add(pos + offset)
                    require(len(anchors) <= mem['max_anchors'],
                            f'More than {mem["max_anchors"]} anchor hits; aborting to avoid '
                            'unbounded inspection')
            pos += primary
    return sorted(anchors), stats


def read_window(handle, anchor, side_budget, mem):
    """Read +/- N bytes around an arbitrary validated anchor; never skip gaps."""
    kernel32, mbi_type, read_bytes = mem['kernel32'], mem['mbi'], mem['read_bytes']

    def region_at(address):
        mbi = mbi_type()
        result = kernel32.VirtualQueryEx(
            handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi))
        if not result:
            return None, f'VirtualQueryEx failed at {address:#x}'
        base, end = int(mbi.BaseAddress or 0), int(mbi.BaseAddress or 0) + int(mbi.RegionSize)
        if not (mbi.State == mem['commit'] and
                (mbi.Protect & 0xFF) in mem['readable'] and
                not (mbi.Protect & mem['guard'])):
            return None, f'unreadable memory at {address:#x}'
        return (base, end), None

    seed = read_bytes(handle, anchor, RECORD.size)
    if len(seed) != RECORD.size or 0 not in anchor_offsets(seed, anchor):
        raise RuntimeError(f'Anchor at {anchor:#x} is no longer a matching record')
    left, right = [], []
    notes = []
    left_cursor, right_cursor = anchor, anchor + RECORD.size
    left_count = right_count = 0
    while left_count < side_budget:
        region, error = region_at(left_cursor - 1)
        if error:
            notes.append('left: ' + error)
            break
        base, _ = region
        n = min(READ_CHUNK, side_budget - left_count, left_cursor - base)
        n -= n % RECORD.size
        if not n:
            notes.append('left: unaligned region boundary')
            break
        data = read_bytes(handle, left_cursor - n, n)
        if len(data) != n:
            notes.append(f'left: short read {len(data)}/{n}')
            break
        left.append(data)
        left_cursor -= n
        left_count += n
    while right_count < side_budget:
        region, error = region_at(right_cursor)
        if error:
            notes.append('right: ' + error)
            break
        _, end = region
        n = min(READ_CHUNK, side_budget - right_count, end - right_cursor)
        n -= n % RECORD.size
        if not n:
            notes.append('right: unaligned region boundary')
            break
        data = read_bytes(handle, right_cursor, n)
        if len(data) != n:
            notes.append(f'right: short read {len(data)}/{n}')
            break
        right.append(data)
        right_cursor += n
        right_count += n
    raw = b''.join(reversed(left)) + seed + b''.join(right)
    return {
        'start': left_cursor, 'end': right_cursor,
        'data': raw, 'left_bytes': left_count, 'right_bytes': right_count,
        'notes': notes,
    }


def self_test(reference_path):
    """Replay the real saved reference through parser/consensus without Arena."""
    _, ref, checks = load_reference(reference_path)
    source = json.loads(reference_path.read_text(encoding='utf-8'))
    rows = [r for run in source['runs'] for r in run['records']]
    raw_records = b''.join(RECORD.pack(
        r['card_id'], SENTINEL if r.get('field_a', -1) == -1 else r['field_a'],
        r['card_id'], r['quantity']) for r in rows)
    require(len(raw_records) == len(rows) * 16, 'Fixture encoding failed')
    windows = []
    for base in (0x10000000, 0x20000000):
        fixture = b'\x00' * 512 + raw_records + b'\x00' * 512
        anchors = anchor_offsets(fixture, base)
        require(len(anchors) == 2, f'Expected both anchors, found {len(anchors)}')
        # Each anchor in a physical copy must produce the same selected run.
        for pos in anchors:
            anchor = base + pos
            window = {'data': fixture, 'start': base, 'end': base + len(fixture),
                      'left_bytes': pos, 'right_bytes': len(fixture) - pos - 16,
                      'notes': []}
            windows.append(analyze_window(window, anchor, None, min_run=8))
    selected, reviewed = select_consensus(windows, ref, checks)
    require(len(selected) == 2 and len(reviewed) == 2, 'Expected two copies after deduplication')
    payload = build_payload(0, selected, reference_path, ref, len(windows))
    require(payload['anchor_run_length'] == len(rows), 'Replay has unexpected run length')
    require(payload['mixed_format_audit']['record_signature_sha256'] ==
            source['mixed_format_audit']['record_signature_sha256'],
            'Signature differs from saved reference')
    # Reject corrupted copy, wrong ownership, and unrelated false-positive runs.
    corrupted = json.loads(json.dumps(windows[1]))
    corrupted['seed_records'][10]['field_b'] = 1 if rows[10]['quantity'] != 1 else 2
    try:
        select_consensus([windows[0], corrupted], ref, checks)
    except RuntimeError:
        pass
    else:
        raise AssertionError('Failed to reject disagreeing copies')
    fail_controls = json.loads(json.dumps(checks))
    fail_controls['76519']['expected'] = 1  # Known UNOWNED card is not in the run.
    try:
        select_consensus(windows, ref, fail_controls)
    except RuntimeError:
        pass
    else:
        raise AssertionError('Failed to reject incorrect control expectation')
    print(f'SELF-TEST PASS: parsed {len(rows):,} records; both anchors found in each '
          'synthetic copy; duplicate anchors deduplicated; exact signatures match; '
          'bad memory copy and failed UI control rejected.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference', type=Path, required=True,
                        help='Saved 1660-ID collection_candidate.json; read-only reference')
    parser.add_argument('--output', type=Path,
                        help='New candidate filename; omit for discovery/validation only')
    parser.add_argument('--pid', type=int, help='Arena PID; auto-detect if omitted')
    parser.add_argument('--window-kb', type=int, default=128,
                        help='Read this many KB on each side of each anchor (default 128)')
    parser.add_argument('--max-anchors', type=int, default=128,
                        help='Fail if too many apparent anchors (default 128)')
    parser.add_argument('--self-test', action='store_true',
                        help='Offline replay of reference, including failure-case tests')
    args = parser.parse_args()
    if not args.reference.is_file():
        parser.error('Reference file not found')
    if not 64 <= args.window_kb <= 1024 or args.window_kb % 4:
        parser.error('--window-kb must be a multiple of 4 from 64 to 1024')
    if not 2 <= args.max_anchors <= 512:
        parser.error('--max-anchors must be in [2, 512]')
    if args.output:
        if args.output.name.lower() in PROTECTED_NAMES:
            parser.error('Refusing to overwrite a protected collection/data filename')
        if args.output.resolve() == args.reference.resolve() or args.output.exists():
            parser.error('Output must be a new file distinct from the reference')
    reference_data, reference, controls = load_reference(args.reference)
    if args.self_test:
        self_test(args.reference)
        return
    if sys.platform != 'win32' or ctypes.sizeof(ctypes.c_void_p) != 8:
        parser.error('For a live scan use 64-bit Windows Python (py.exe -3)')
    from find_arena import find_arena_pid
    from search_card_memory import (
        MEM_COMMIT, PAGE_GUARD, READABLE, MEMORY_BASIC_INFORMATION,
        PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, MAX_ADDRESS,
        kernel32, read_bytes,
    )
    pid = args.pid if args.pid is not None else find_arena_pid()
    require(pid, 'MTGA.exe is not running. Open Arena and visit Collection first.')
    mem = {
        'kernel32': kernel32, 'mbi': MEMORY_BASIC_INFORMATION,
        'read_bytes': read_bytes, 'max_address': MAX_ADDRESS,
        'commit': MEM_COMMIT, 'guard': PAGE_GUARD, 'readable': READABLE,
        'max_anchors': args.max_anchors,
    }
    handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    print(f'MTGA PID {pid} | mixed-format auto-discovery (READ-ONLY)', flush=True)
    try:
        print('Scanning readable memory for known card-record signatures...', flush=True)
        anchors, stats = discover_anchors(handle, mem)
        print(f'  Scanned {stats["bytes_read"] / (1024**3):.2f} GiB from '
              f'{stats["regions"]:,} readable regions; '
              f'{stats["partial_chunks"]} partial chunks.', flush=True)
        print(f'  Found {len(anchors)} anchor matches; examining contiguous runs...', flush=True)
        windows = []
        for index, anchor in enumerate(anchors, 1):
            try:
                raw = read_window(handle, anchor, args.window_kb * 1024, mem)
                analyzed = analyze_window(raw, anchor, None, min_run=8)
                windows.append(analyzed)
                print(f'  {index:>3}/{len(anchors)} {anchor:#x}: '
                      f'{analyzed["seed_run_summary"]["record_count"]:,} records')
            except (RuntimeError, ValueError) as exc:
                print(f'  {index:>3}/{len(anchors)} {anchor:#x}: skipped ({exc})')
    finally:
        kernel32.CloseHandle(handle)
    require(windows, 'No readable anchor-containing runs were found')
    reviewed_starts = set()
    for window in windows:
        run_start = int(window['seed_records'][0]['address'], 16)
        if run_start in reviewed_starts:
            continue
        reviewed_starts.add(run_start)
        assessment = assess_run(window, reference, controls)
        verdict = 'PASS' if assessment['valid'] else 'REJECT'
        print(f'  Run {run_start:#x}: {verdict}, {assessment["count"]:,} IDs, '
              f'reference coverage={assessment["coverage"]:.1%}, '
              f'quantity agreement={assessment["quantity_agreement"]:.1%}')
        for reason in assessment['reasons'][:3]:
            print(f'    - {reason}')
    selected, inspected = select_consensus(windows, reference, controls)
    summary = selected[0][1]
    payload = build_payload(pid, selected, args.reference, reference, len(anchors))
    fmt = payload['mixed_format_audit']['format_counts']
    print('\nPASS: exactly one validated dataset found')
    print(f'  Matching physical copies: {len(selected)}')
    print(f'  Candidate: {payload["anchor_run_length"]:,} Arena IDs, '
          f'{sum(r["quantity"] for r in payload["runs"][0]["records"]):,} copies')
    print(f'  Formats: sentinel={fmt.get("sentinel", 0):,}, '
          f'non-sentinel={fmt.get("non_sentinel", 0):,}')
    print(f'  Reference overlap: {summary["coverage"]:.2%}; '
          f'quantity agreement: {summary["quantity_agreement"]:.2%}')
    print(f'  Reference changes: new={summary["reference_additions"]}, '
          f'missing={summary["reference_missing"]}, '
          f'changed quantities={summary["reference_quantity_changes"]}')
    print(f'  UI controls: {len(summary["controls"])} / {len(summary["controls"])} passed')
    print(f'  Signature SHA-256: '
          f'{payload["mixed_format_audit"]["record_signature_sha256"]}')
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open('x', encoding='utf-8') as dest:
            json.dump(payload, dest, indent=2)
            dest.write('\n')
        print(f'Saved NEW candidate: {args.output}')
    else:
        print('Diagnostic-only mode: no output file written (--output to save).')
    print('Production collection.json and prior collection_candidate.json untouched.')
    print('Status: candidate_unconfirmed; not proof of completeness.')


if __name__ == '__main__':
    main()
