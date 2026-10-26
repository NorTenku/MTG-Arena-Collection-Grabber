#!/usr/bin/env python3
"""Offline, read-only structural, historical ownership and Scryfall audit.

Run with WSL Python; does not attach to the game process or modify any inputs.
"""
import argparse
from collections import Counter, defaultdict
import gzip
import hashlib
import json
from pathlib import Path
import sys


def load_candidate(path):
    with path.open('r', encoding='utf-8') as f:
        data = json.load(f)
    if not isinstance(data, dict) or not isinstance(data.get('runs'), list):
        raise ValueError('Expected candidate JSON with a runs list')
    records = [record for run in data['runs'] for record in run.get('records', [])]
    if not records:
        raise ValueError('No candidate records found')
    return data, records


def load_scryfall(path, requested):
    """Stream JSONL or JSONL.gz rather than reading the bulk file into RAM."""
    lookup = {}
    collisions = defaultdict(list)
    opener = gzip.open if path.suffix.lower() == '.gz' else open
    with opener(path, 'rt', encoding='utf-8') as f:
        for number, line in enumerate(f, 1):
            if not line.strip():
                continue
            try:
                card = json.loads(line)
            except json.JSONDecodeError as e:
                raise ValueError(f'Invalid Scryfall JSONL on line {number}: {e}') from e
            arena_id = card.get('arena_id')
            if not isinstance(arena_id, int) or isinstance(arena_id, bool) or arena_id not in requested:
                continue
            entry = {key: card.get(key) for key in ('name','set','collector_number','artist','type_line')}
            if arena_id in lookup and lookup[arena_id] != entry:
                collisions[arena_id].append(entry)
            else:
                lookup.setdefault(arena_id, entry)
    return lookup, collisions


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate', type=Path, default=Path('data/collection_candidate.json'))
    parser.add_argument('--scryfall', type=Path, default=Path('data/scryfall_default_cards.jsonl.gz'))
    parser.add_argument('--reference', type=Path,
                        help='Optional saved reference snapshot for verifying recorded changes')
    parser.add_argument('--unresolved-limit', type=int, default=40)
    args = parser.parse_args()
    if args.unresolved_limit < 0:
        parser.error('--unresolved-limit must be nonnegative')
    for label, path in (('candidate', args.candidate), ('scryfall', args.scryfall),
                        ('reference', args.reference)):
        if path is not None and not path.is_file():
            parser.error(f'{label} file not found: {path}')

    data, rows = load_candidate(args.candidate)
    problems = []
    ids = [r.get('card_id') for r in rows]
    if len(ids) != len(set(ids)):
        counts = Counter(ids)
        problems.append(f'duplicate Arena IDs: {[(k,v) for k,v in counts.items() if v>1][:10]}')
    for idx, row in enumerate(rows):
        cid, qty, a, fmt = (row.get(k) for k in ('card_id','quantity','field_a','record_format'))
        if not (type(cid) is int and cid > 0 and type(qty) is int and 1 <= qty <= 4
                and type(a) is int and fmt == ('sentinel' if a == -1 else 'non_sentinel')):
            problems.append(f'invalid record {idx}: {row}')
    declared_len = data.get('anchor_run_length')
    if declared_len != len(rows):
        problems.append(f'anchor_run_length is {declared_len}; actual {len(rows)}')
    for run in data['runs']:
        if run.get('record_count') != len(run.get('records', [])):
            problems.append('run record_count mismatch')

    digest = hashlib.sha256(json.dumps(
        [[r['card_id'],r['field_a'],r['quantity']] for r in rows],
        separators=(',',':')).encode('utf-8')).hexdigest()
    recorded_digest = data.get('mixed_format_audit', {}).get('record_signature_sha256')
    if recorded_digest != digest:
        problems.append('record signature SHA-256 differs from candidate metadata')
    format_counts = Counter(r['record_format'] for r in rows)
    recorded_counts = data.get('mixed_format_audit', {}).get('format_counts', {})
    if dict(format_counts) != recorded_counts:
        problems.append(f'format_counts mismatch: {dict(format_counts)} vs {recorded_counts}')

    by_id = {r['card_id']: r for r in rows}
    controls = data.get('historical_ownership_checks')
    new_format = controls is not None
    if new_format:
        # Historical controls describe previous observations only. Recheck the
        # comparison calculations, but DO NOT reject current legitimate changes.
        if data.get('reference_validation'):
            problems.append('change-aware export incorrectly contains strict reference_validation')
        changed_controls = []
        for key, control in controls.items():
            expected = control.get('baseline_quantity')
            current = by_id.get(int(key), {}).get('quantity', 0)
            if (type(expected) is not int or not 0 <= expected <= 4 or
                    control.get('observed_quantity') != current or
                    control.get('unchanged') != (expected == current) or
                    control.get('change') != (current - expected)):
                problems.append(f'bad historical comparison for Arena ID {key}')
            if expected != current:
                changed_controls.append((key, control.get('name'), expected, current))
        bad_controls = []  # Legacy controls only, below
    else:
        controls = data.get('reference_validation', {})
        bad_controls = []
        for key, control in controls.items():
            expected = control.get('expected')
            actual = by_id.get(int(key), {}).get('quantity')
            if expected == 0:
                if actual is not None:
                    bad_controls.append((key, expected, actual))
            elif actual != expected:
                bad_controls.append((key, expected, actual))
        if bad_controls:
            problems.append(f'legacy ownership controls disagree: {bad_controls}')
        changed_controls = []

    if args.reference:
        source = json.loads(args.reference.read_text(encoding='utf-8'))
        ref_rows = [r for run in source['runs'] for r in run.get('records', [])]
        ref_by_id = {r['card_id']: r['quantity'] for r in ref_rows}
        observed = {r['card_id']: r['quantity'] for r in rows}
        expected_differences = {
            'newly_owned': [{'card_id': cid, 'previous_quantity': 0,
                             'current_quantity': observed[cid]}
                            for cid in sorted(observed.keys() - ref_by_id.keys())],
            'no_longer_present': [{'card_id': cid, 'previous_quantity': ref_by_id[cid],
                                   'current_quantity': 0}
                                  for cid in sorted(ref_by_id.keys() - observed.keys())],
            'quantity_changed': [{'card_id': cid, 'previous_quantity': ref_by_id[cid],
                                  'current_quantity': observed[cid]}
                                 for cid in sorted(observed.keys() & ref_by_id.keys())
                                 if observed[cid] != ref_by_id[cid]],
        }
        if new_format and data.get('reference_changes') != expected_differences:
            problems.append('Recorded reference changes differ from actual changes')
        coverage = (len(observed.keys() & ref_by_id.keys()) / len(ref_by_id))
        agreement = (sum(observed[c] == ref_by_id[c]
                         for c in observed.keys() & ref_by_id.keys()) /
                     max(1, len(observed.keys() & ref_by_id.keys())))
        reference_comparison = data.get('reference_comparison', {})
        if new_format:
            for field, value in (('coverage', coverage), ('quantity_agreement', agreement)):
                if abs(reference_comparison.get(field, -1) - value) > 1e-9:
                    problems.append(f'Incorrect stored reference metric: {field}')
    else:
        expected_differences = None

    print('MTGA candidate — offline structural and Scryfall audit')
    print(f'Candidate: {args.candidate}')
    print(f'Scryfall:  {args.scryfall}')
    print(f'Status in file: {data.get("status")}')
    print(f'Records: {len(rows):,}; unique Arena IDs: {len(by_id):,}; copies: {sum(x["quantity"] for x in rows):,}')
    print(f'Record signature matches metadata: {digest == recorded_digest}')
    if new_format:
        print(f'Historical UI checks: {len(controls) - len(changed_controls)} unchanged, '
              f'{len(changed_controls)} changed (advisory; not failed controls)')
        for cid, name, old, current in changed_controls:
            print(f'  HISTORICAL CHANGE: {name} ({cid}) {old} -> {current}')
    else:
        print(f'Legacy ownership controls: {len(controls) - len(bad_controls)}/{len(controls)} match')
    if expected_differences is not None:
        print('Reference differences: ' + ', '.join(
            f'{kind}={len(expected_differences[kind])}' for kind in
            ('newly_owned', 'no_longer_present', 'quantity_changed')))
    print(f'Structural problems: {len(problems)}')
    for problem in problems[:20]:
        print('  ERROR:', problem)
    print()

    print('RECORD QUANTITIES')
    print('Format          IDs     Copies    x1    x2    x3    x4')
    for fmt in ('sentinel','non_sentinel'):
        subset = [r for r in rows if r['record_format'] == fmt]
        counts = Counter(r['quantity'] for r in subset)
        print(f'{fmt:<16}{len(subset):>5} {sum(r["quantity"] for r in subset):>9} '
              + ' '.join(f'{counts[q]:>5}' for q in range(1,5)))
    nfields = [r['field_a'] for r in rows if r['record_format']=='non_sentinel']
    if nfields:
        print(f'Non-sentinel Field A: {len(set(nfields))} distinct / {len(nfields)} records; min={min(nfields)} max={max(nfields)}')
    print()

    lookup, collisions = load_scryfall(args.scryfall, set(by_id))
    print('SCRYFALL ARENA-ID RESOLUTION (metadata only, NOT ownership validation)')
    for fmt in ('sentinel','non_sentinel','all'):
        subset = [r for r in rows if fmt == 'all' or r['record_format'] == fmt]
        resolved = sum(r['card_id'] in lookup for r in subset)
        print(f'{fmt:<16} resolved {resolved:>5}/{len(subset):<5} = {100*resolved/len(subset):5.2f}%'
              f'; unresolved {len(subset)-resolved}')
    print(f'Conflicting Scryfall records sharing one arena_id: {len(collisions)}')
    for cid, alternates in list(collisions.items())[:8]:
        print(f'  {cid}: {lookup[cid]} / alternate entries: {len(alternates)}')
    print()

    additional = [r for r in rows if r['record_format'] == 'non_sentinel']
    sets = Counter(lookup[r['card_id']].get('set') or 'unknown'
                   for r in additional if r['card_id'] in lookup)
    print('TOP SETS AMONG RESOLVED ADDITIONAL RECORDS')
    for set_code, count in sets.most_common(18):
        print(f'  {set_code:<8} {count:>4} IDs')
    print()

    for fmt, subset in (('additional non-sentinel',additional),('existing sentinel',
                          [r for r in rows if r['record_format']=='sentinel'])):
        unresolved = sorted([r for r in subset if r['card_id'] not in lookup],
                            key=lambda row: (-row['quantity'], row['card_id']))
        print(f'UNRESOLVED — {fmt}: {len(unresolved)}')
        for r in unresolved[:args.unresolved_limit]:
            print(f'  {r["card_id"]:>7} x{r["quantity"]} Field A={r["field_a"]}')
        if len(unresolved)>args.unresolved_limit:
            print(f'  ... {len(unresolved)-args.unresolved_limit} more')
        print()
    if problems:
        sys.exit(2)


if __name__ == '__main__':
    main()
