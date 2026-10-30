#!/usr/bin/env python3
"""Read-only, change-aware MTG Arena collection candidate exporter.

Standalone companion to extract_collection.py: does not modify the legacy extractor.
Windows 64-bit Python is required for live process inspection; --self-test also
works on Linux/WSL using the saved reference JSON.

Strategy:
  1. Scan readable MTGA.exe memory for known repeated-ID anchors (no addresses).
  2. Expand around each hit across *adjacent readable* VirtualQueryEx regions.
  3. Keep only complete, contiguous 16-byte mixed-format card sequences.
  4. Require two distinct memory copies with identical ordered triples.
  5. Require strong reference overlap/quantity agreement and compare historical
     UI checks as observations, NOT permanent ownership invariants.
     Report acquisitions, removals and quantity changes without rejecting them.
     Reject suspiciously large discrepancies and structurally invalid datasets.
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
    """Read an immutable snapshot and historical, potentially stale UI observations.

    Legacy files contain reference_validation; change-aware files store history in
    historical_ownership_checks. Both describe what was observed THEN, not now.
    """
    data = json.loads(path.read_text(encoding='utf-8'))
    require(isinstance(data, dict) and isinstance(data.get('runs'), list),
            'Reference must be an exported collection JSON containing runs')
    records = [r for run in data['runs'] for r in run.get('records', [])]
    require(len(records) >= MIN_RUN_RECORDS, 'Reference is unexpectedly small')
    quantities = {}
    for r in records:
        cid, qty = r['card_id'], r['quantity']
        require(type(cid) is int and 1 <= cid <= MAX_ARENA_ID and
                type(qty) is int and 1 <= qty <= 4,
                f'Invalid reference record {r!r}')
        require(cid not in quantities, f'Duplicate card ID {cid} in reference')
        quantities[cid] = qty
    source_checks = data.get('historical_ownership_checks')
    if source_checks is None:
        source_checks = data.get('reference_validation')
    require(isinstance(source_checks, dict) and len(source_checks) >= 10,
            'Reference lacks the historically verified UI controls')
    controls = {}
    for cid_string, control in source_checks.items():
        cid = int(cid_string)
        expected = control.get('baseline_quantity', control.get('expected'))
        require(type(expected) is int and 0 <= expected <= 4,
                f'Invalid historical control for {cid}')
        controls[str(cid)] = {'name': control.get('name', str(cid)),
                              'baseline_quantity': expected}
        # The legacy reference is itself the observation from the initial tests.
        if 'historical_ownership_checks' not in data:
            require(quantities.get(cid, 0) == expected,
                    f'Reference contradicts initial UI observation for {cid}')
    require(sum(c['baseline_quantity'] == 0 for c in controls.values()) >= 2,
            'Reference lacks historical unowned controls')
    return data, quantities, controls


def compare_historical_controls(records, controls):
    """Annotate changes since the old UI checks. Never use these as a veto."""
    by_id = {r['card_id']: r['field_b'] for r in records}
    results = {}
    for cid_string, control in controls.items():
        baseline = control['baseline_quantity']
        current = by_id.get(int(cid_string), 0)
        results[cid_string] = {
            'name': control['name'],
            'baseline_quantity': baseline,
            'observed_quantity': current,
            'unchanged': current == baseline,
            'change': current - baseline,
        }
    return results


def compute_reference_changes(rows, reference):
    """Complete JSON-serializable reference diff (0 means absent/unowned)."""
    observed = {r['card_id']: r['field_b'] for r in rows}
    added = [{'card_id': cid, 'previous_quantity': 0, 'current_quantity': observed[cid]}
             for cid in sorted(observed.keys() - reference.keys())]
    removed = [{'card_id': cid, 'previous_quantity': reference[cid], 'current_quantity': 0}
               for cid in sorted(reference.keys() - observed.keys())]
    changed = [{'card_id': cid, 'previous_quantity': reference[cid],
                'current_quantity': observed[cid]}
               for cid in sorted(reference.keys() & observed.keys())
               if reference[cid] != observed[cid]]
    return {'newly_owned': added, 'no_longer_present': removed,
            'quantity_changed': changed}


def assess_run(window, reference, controls):
    """Strict structural/reference screening; historical ownership is advisory."""
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
    for i, row in enumerate(rows):
        cid, a, qty = row['card_id'], row['field_a'], row['field_b']
        if not (type(cid) is int and 0 < cid <= MAX_ARENA_ID and
                type(a) is int and -1 <= a <= 0xffffffff and
                type(qty) is int and 1 <= qty <= 4 and
                row['format'] == ('sentinel' if a == -1 else 'non_sentinel')):
            reasons.append(f'invalid record {i}')
            break
        if i and int(row['address'], 16) != int(rows[i-1]['address'], 16) + RECORD.size:
            reasons.append(f'noncontiguous records at {i}')
            break
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
    history = compare_historical_controls(rows, controls)
    differences = compute_reference_changes(rows, reference)
    signature = tuple((r['card_id'], r['field_a'], r['field_b']) for r in rows)
    # MTGA_OWNERSHIP_CONSENSUS_V1: compare the ownership-bearing fields only.
    ownership_signature = tuple((r['card_id'], r['field_b']) for r in rows)
    return {
        'valid': not reasons, 'reasons': reasons,
        'coverage': coverage, 'quantity_agreement': qty_agreement,
        'reference_additions': len(differences['newly_owned']),
        'reference_missing': len(differences['no_longer_present']),
        'reference_quantity_changes': len(differences['quantity_changed']),
        'historical_checks': history, 'differences': differences,
        'signature': signature, 'ownership_signature': ownership_signature,
        'count': len(rows),
    }


# MTGA_CONSENSUS_DIAGNOSTICS_V1

def print_consensus_diagnostics(inspected, sample_limit=12):
    """Compare VALID complete copies only; diagnostics never authorise export.

    IDs, quantities, record formats, field A, and row ordering are compared
    independently, so differing metadata cannot be mistaken for ownership drift.
    """
    valid = [(win, assessment) for win, assessment in inspected if assessment['valid']]
    print('\nCONSENSUS DIAGNOSTICS (read-only; no snapshot accepted):', flush=True)
    print(f'  Passing structural/reference checks: {len(valid)} distinct runs', flush=True)
    for index, (win, assessment) in enumerate(valid[:8], 1):
        rows = win['seed_records']
        source = int(rows[0]['address'], 16)
        quantities = {r['card_id']: r['field_b'] for r in rows}
        digest = hashlib.sha256(json.dumps(sorted(quantities.items()),
                        separators=(',', ':')).encode('utf-8')).hexdigest()[:16]
        print(f'  Copy {index}: {source:#x}; records={len(rows)}, '
              f'owned-id/quantity digest={digest}', flush=True)
    if len(valid) < 2:
        print('  Fewer than two valid copies: no pairwise comparison is possible.', flush=True)
        return
    for i in range(min(len(valid), 8)):
        for j in range(i + 1, min(len(valid), 8)):
            a, b = (valid[i][0]['seed_records'], valid[j][0]['seed_records'])
            amap, bmap = ({r['card_id']: r for r in a}, {r['card_id']: r for r in b})
            ids_a, ids_b = set(amap), set(bmap)
            only_a, only_b = sorted(ids_a - ids_b), sorted(ids_b - ids_a)
            both = sorted(ids_a & ids_b)
            quantity_diffs = [cid for cid in both if
                              amap[cid]['field_b'] != bmap[cid]['field_b']]
            format_diffs = [cid for cid in both if
                            amap[cid]['format'] != bmap[cid]['format']]
            field_a_diffs = [cid for cid in both if
                             amap[cid]['field_a'] != bmap[cid]['field_a']]
            positions_a = {r['card_id']: k for k, r in enumerate(a)}
            positions_b = {r['card_id']: k for k, r in enumerate(b)}
            moved = [cid for cid in both if positions_a[cid] != positions_b[cid]]
            exact_ownership = (not only_a and not only_b and not quantity_diffs)
            print(f'  Compare copies {i+1} and {j+1}:', flush=True)
            print(f'    ID-only-A={len(only_a)}, ID-only-B={len(only_b)}, '
                  f'quantity disagreements={len(quantity_diffs)}', flush=True)
            print(f'    Field A disagreements={len(field_a_diffs)}, '
                  f'format disagreements={len(format_diffs)}, '
                  f'row position disagreements={len(moved)}', flush=True)
            print('    Identical ownership ID/quantity mapping: '
                  + ('YES' if exact_ownership else 'NO'), flush=True)
            for label, ids in (
                ('only copy A', only_a), ('only copy B', only_b),
                ('quantity disagreements', quantity_diffs),
                ('field A disagreements', field_a_diffs),
                ('format disagreements', format_diffs),
                ('position disagreements', moved),
            ):
                if not ids:
                    continue
                print(f'    Sample {label} (at most {sample_limit}):', flush=True)
                for cid in ids[:sample_limit]:
                    ra, rb = amap.get(cid), bmap.get(cid)
                    if ra is not None and rb is not None:
                        print(f'      {cid}: A=(qty {ra["field_b"]}, '
                              f'field_a {ra["field_a"]}, format {ra["format"]}, '
                              f'row {positions_a[cid]}); B=(qty {rb["field_b"]}, '
                              f'field_a {rb["field_a"]}, format {rb["format"]}, '
                              f'row {positions_b[cid]})', flush=True)
                    else:
                        print(f'      {cid}: present in '
                              f'{"A" if ra is not None else "B"} only', flush=True)
            if exact_ownership:
                print('    NOTE: Ownership agrees, but strict ordered-triple '
                      'consensus still does not. Do not loosen validation '
                      'until the differing fields are understood.', flush=True)
            else:
                print('    NOTE: Ownership itself differs between copies; '
                      'do not export either as verified.', flush=True)
    if len(valid) > 8:
        print(f'  Only first 8 of {len(valid)} passing copies compared.', flush=True)
    print('  No raw memory dumped; no collection output written by diagnostics.\n',
          flush=True)

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
            groups[review['ownership_signature']].append((window, review))
    passing = [members for members in groups.values() if len(members) >= 2]
    if len(passing) != 1:
        print_consensus_diagnostics(inspected)
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
    ownership_rows = [[r['card_id'], r['field_b']] for r in rows]
    ownership_digest = hashlib.sha256(json.dumps(
        ownership_rows, separators=(',', ':')).encode()).hexdigest()
    # Recheck agreement at serialization, even if consensus was selected above.
    require(len(windows) >= 2, 'Fewer than two physically distinct collection copies')
    require(len({int(w['seed_records'][0]['address'], 16) for w in windows}) >= 2,
            'Collection copies share the same memory start')
    for other in windows[1:]:
        candidate = [(r['card_id'], r['field_b']) for r in other['seed_records']]
        require(candidate == [(r['card_id'], r['field_b']) for r in rows],
                'Ownership changed between selected copies')
    field_a_disagreements = sorted({
        row['card_id']
        for other in windows[1:]
        for row, other_row in zip(rows, other['seed_records'])
        if row['field_a'] != other_row['field_a']
    })
    format_disagreements = sorted({
        row['card_id']
        for other in windows[1:]
        for row, other_row in zip(rows, other['seed_records'])
        if row['format'] != other_row['format']
    })
    strict_record_consensus = not field_a_disagreements and not format_disagreements
    return {
        'status': 'candidate_unconfirmed',
        'source': 'mtga_process_memory_read_only_mixed_format_autodiscovery',
        'extracted_at': datetime.now(timezone.utc).isoformat(),
        'pid': pid,
        'anchor_address': windows[0]['anchor'],
        'scan_start': hex(start),
        'scan_bytes': RECORD.size * len(rows),
        'anchor_run_length': len(rows),
        'selection_method': 'autodiscovery_ordered_ownership_consensus_change_aware',
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
        'historical_ownership_checks': summary['historical_checks'],
        'reference_changes': summary['differences'],
        'ownership_validation_policy': ('historical UI checks are advisory; ' 
            'two physically distinct structurally valid complete sequences must agree ' 
            'on ordered Arena IDs and quantities; field_a and format are NOT ' 
            'corroborated when copies disagree; strong reference similarity required'),
        'mixed_format_audit': {
            'candidate_unique_ids': len(rows),
            'format_counts': dict(Counter(r['format'] for r in rows)),
            'matching_copies': len(windows),
            'all_matching': strict_record_consensus,
            'ownership_consensus': True,
            'consensus_basis': 'ordered_card_id_quantity',
            'ownership_signature_sha256': ownership_digest,
            'auxiliary_field_source': 'first_selected_physical_copy_only',
            'auxiliary_field_a_disagreements': len(field_a_disagreements),
            'auxiliary_format_disagreements': len(format_disagreements),
            'auxiliary_disagreement_sample_ids': field_a_disagreements[:20],
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
    """Test saved baseline, legitimate ownership changes, and failure cases."""
    _, ref, controls = load_reference(reference_path)
    source = json.loads(reference_path.read_text(encoding='utf-8'))
    baseline_rows = [r for run in source['runs'] for r in run['records']]

    def replay(rows, bases=(0x10000000, 0x20000000)):
        raw_records = b''.join(RECORD.pack(
            r['card_id'], SENTINEL if r['field_a'] == -1 else r['field_a'],
            r['card_id'], r['quantity']) for r in rows)
        windows = []
        for base in bases:
            fixture = b'\x00' * 512 + raw_records + b'\x00' * 512
            anchors = anchor_offsets(fixture, base)
            require(anchors, 'Fixture has no known anchor')
            for offset in anchors:
                anchor = base + offset
                window = {'data': fixture, 'start': base, 'end': base + len(fixture),
                          'left_bytes': offset, 'right_bytes': len(fixture) - offset - 16,
                          'notes': []}
                windows.append(analyze_window(window, anchor, None, min_run=8))
        return windows

    import copy
    original = replay(baseline_rows)
    selected, inspected = select_consensus(original, ref, controls)
    require(len(selected) == 2 and len(inspected) == 2,
            'Expected matching copies after deduplication')
    digest = build_payload(0, selected, reference_path, ref, len(original))[
        'mixed_format_audit']['record_signature_sha256']
    require(digest == source['mixed_format_audit']['record_signature_sha256'],
            'Original reference signature mismatch')

    # A card that was owned x4 is now x3; this MUST NOT fail.
    changed = copy.deepcopy(baseline_rows)
    next(r for r in changed if r['card_id'] == 75446)['quantity'] = 3
    candidates = replay(changed)
    accepted, _ = select_consensus(candidates, ref, controls)
    check = accepted[0][1]['historical_checks']['75446']
    require(not check['unchanged'] and check['observed_quantity'] == 3,
            'Historical positive control was not reported as changed')
    require(accepted[0][1]['reference_quantity_changes'] == 1,
            'Changed quantity not included in diff')

    # A previously unowned card is acquired; the old negative control is
    # informational, NOT a permanent blacklist.
    acquired = copy.deepcopy(baseline_rows)
    acquired.append({'card_id': 76519, 'field_a': -1, 'quantity': 1})
    accepted, _ = select_consensus(replay(acquired), ref, controls)
    require(accepted[0][1]['reference_additions'] == 1 and
            accepted[0][1]['historical_checks']['76519']['observed_quantity'] == 1,
            'Historical unowned control incorrectly rejected a new acquisition')

    # If an old anchor card disappears, the other anchor should still locate
    # the dataset. The missing record is reported rather than vetoed.
    removed = [copy.deepcopy(r) for r in baseline_rows if r['card_id'] != 103481]
    accepted, _ = select_consensus(replay(removed), ref, controls)
    require(accepted[0][1]['reference_missing'] == 1 and
            accepted[0][1]['historical_checks']['103481']['observed_quantity'] == 0,
            'A card leaving the collection was not reported')

    # A single changed memory copy must not pass consensus.
    one_copy = replay(changed, (0x10000000,)) + replay(baseline_rows, (0x20000000,))
    try:
        select_consensus(one_copy, ref, controls)
    except RuntimeError:
        pass
    else:
        raise AssertionError('Mismatched physical copies were accepted')

    # A candidate that matches almost no reference IDs is still rejected.
    tiny = copy.deepcopy(baseline_rows[:25])
    try:
        select_consensus(replay(tiny), ref, controls)
    except RuntimeError:
        pass
    else:
        raise AssertionError('Unrelated short run was accepted')

    # A sufficiently large drift is suspicious and must fail closed.
    drift = copy.deepcopy(baseline_rows)
    for row in drift[:100]:
        row['quantity'] = row['quantity'] % 4 + 1
    try:
        select_consensus(replay(drift), ref, controls)
    except RuntimeError:
        pass
    else:
        raise AssertionError('Excessive reference changes were accepted')

    print(f'SELF-TEST PASS: {len(baseline_rows):,} reference records; '
          'unchanged replay; changed positive control; newly owned negative control; '
          'lost card/anchor; mismatched copies; unrelated short run; excessive drift.')

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
    parser.add_argument('--change-limit', type=int, default=25,
                        help='Maximum individual reference changes to print (default 25)')
    parser.add_argument('--self-test', action='store_true',
                        help='Offline replay of reference, including failure-case tests')
    args = parser.parse_args()
    if not args.reference.is_file():
        parser.error('Reference file not found')
    if not 64 <= args.window_kb <= 1024 or args.window_kb % 4:
        parser.error('--window-kb must be a multiple of 4 from 64 to 1024')
    if not 0 <= args.change_limit <= 1000:
        parser.error('--change-limit must be in [0, 1000]')
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
    print(f'  Ownership-agreeing physical copies: {len(selected)}')
    aux = payload['mixed_format_audit']
    print(f'  Ordered ID/quantity consensus: YES '
          f'(sha256 {aux["ownership_signature_sha256"][:16]})')
    print(f'  Auxiliary metadata: field_a disagrees on '
          f'{aux["auxiliary_field_a_disagreements"]} IDs; '
          f'format disagrees on {aux["auxiliary_format_disagreements"]} IDs')
    if not aux['all_matching']:
        print('  NOTE: exported field_a/format come from one physical copy; '
              'their values are NOT cross-copy verified')
    print(f'  Candidate: {payload["anchor_run_length"]:,} Arena IDs, '
          f'{sum(r["quantity"] for r in payload["runs"][0]["records"]):,} copies')
    print(f'  Formats: sentinel={fmt.get("sentinel", 0):,}, '
          f'non-sentinel={fmt.get("non_sentinel", 0):,}')
    print(f'  Reference overlap: {summary["coverage"]:.2%}; '
          f'quantity agreement: {summary["quantity_agreement"]:.2%}')
    print(f'  Reference changes: new={summary["reference_additions"]}, '
          f'missing={summary["reference_missing"]}, '
          f'changed quantities={summary["reference_quantity_changes"]}')
    history = summary['historical_checks']
    changed_controls = [(cid, c) for cid, c in history.items() if not c['unchanged']]
    print(f'  Historical UI checks: {len(history) - len(changed_controls)} unchanged, '
          f'{len(changed_controls)} changed (changes are advisory)')
    for cid, control in changed_controls:
        print(f'    UI history: {control["name"]} ({cid}) '
              f'{control["baseline_quantity"]} -> {control["observed_quantity"]}')
    changes = summary['differences']
    print('  Ownership changes vs reference (all included in exported JSON):')
    printed = 0
    for category in ('newly_owned', 'no_longer_present', 'quantity_changed'):
        for row in changes[category]:
            if printed >= args.change_limit:
                break
            print(f'    {category}: ID {row["card_id"]} '
                  f'{row["previous_quantity"]} -> {row["current_quantity"]}')
            printed += 1
    total_changes = sum(len(v) for v in changes.values())
    if total_changes > printed:
        print(f'    ... {total_changes - printed} further changes in JSON output')
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
