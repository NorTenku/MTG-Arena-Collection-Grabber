#!/usr/bin/env python3
"""Build an OWNED MTG Arena collection card index, read-only toward all inputs.

Unlike build_card_index.py / resolve_cards.py, this script reads a collection
candidate, not the deck-usage index. Exact Scryfall arena_id data supplies rich
metadata. Verified MTGA GrpId overrides supply *identity only* where Scryfall
has no exact arena_id; they do not imply Brawl legality, Oracle text, or colors.

No network requests. The output is a NEW file: existing files are never replaced.
Run from the MTGA project root with WSL Python. See --help and --self-test.
"""

import argparse
from collections import Counter
from datetime import datetime, timezone
import gzip
import json
import os
from pathlib import Path
import tempfile

DEFAULT_CANDIDATE = Path('data/collection_change_aware_candidate.json')
DEFAULT_SCRYFALL = Path('data/scryfall_default_cards.jsonl.gz')
DEFAULT_OVERRIDES = Path('data/arena_id_verified_overrides.json')
DEFAULT_OUTPUT = Path('data/resolved_collection_candidate.json')

PROTECTED_BASENAMES = {
    'collection.json', 'collection_candidate.json',
    'collection_auto_candidate.json', 'collection_change_aware_candidate.json',
    'card_index.json', 'resolved_cards.json', 'decks.json',
    'arena_id_verified_overrides.json', 'scryfall_default_cards.jsonl.gz',
}

FIELDS = (
    'name', 'mana_cost', 'mana_value', 'type_line', 'colors',
    'color_identity', 'rarity', 'set', 'collector_number', 'oracle_text',
    'legalities', 'scryfall_uri', 'scryfall_id', 'oracle_id', 'card_faces',
)


def load_collection(path):
    obj = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(obj, dict) or not isinstance(obj.get('runs'), list):
        raise ValueError('Expected candidate collection with runs list')
    rows = {}
    for run in obj['runs']:
        if not isinstance(run, dict) or not isinstance(run.get('records'), list):
            raise ValueError('Invalid collection run')
        if run.get('record_count') != len(run['records']):
            raise ValueError('Collection run record_count mismatch')
        for record in run['records']:
            if not isinstance(record, dict):
                raise ValueError('Collection record must be an object')
            cid, qty, field_a, fmt = (record.get(k) for k in
                                      ('card_id', 'quantity', 'field_a', 'record_format'))
            if (type(cid) is not int or cid <= 0 or type(qty) is not int or
                not 1 <= qty <= 4 or type(field_a) is not int or
                fmt != ('sentinel' if field_a == -1 else 'non_sentinel')):
                raise ValueError(f'Invalid collection record: {record}')
            if cid in rows:
                raise ValueError(f'Duplicate Arena ID {cid} across collection runs')
            rows[cid] = {'quantity': qty, 'field_a': field_a, 'record_format': fmt}
    if not rows:
        raise ValueError('Collection has no records')
    return obj, rows


def load_overrides(path):
    obj = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(obj, dict):
        raise ValueError('Override file must be an object keyed by Arena ID')
    entries = {}
    for key, entry in obj.items():
        try:
            cid = int(key)
        except (ValueError, TypeError) as exc:
            raise ValueError(f'Invalid override key {key!r}') from exc
        if (cid <= 0 or str(cid) != key or not isinstance(entry, dict) or
            type(entry.get('arena_id')) is not int or entry['arena_id'] != cid or
            not isinstance(entry.get('name'), str) or not entry['name'].strip() or
            not isinstance(entry.get('set'), str) or not entry['set'].strip() or
            not isinstance(entry.get('collector_number'), str) or
            not entry['collector_number'].strip() or
            entry.get('source') != 'mtga_local_sqlite_exact_grp_id' or
            entry.get('scryfall_id') is not None or
            entry.get('oracle_id') is not None):
            raise ValueError(f'Invalid or not exact-ID-verified override: {key}')
        entries[cid] = entry
    return entries


def iter_scryfall(path):
    opening = gzip.open if path.suffix.lower() == '.gz' else open
    with opening(path, 'rt', encoding='utf-8') as f:
        for line_no, line in enumerate(f, 1):
            if line.strip():
                try:
                    data = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f'Invalid Scryfall JSONL line {line_no}') from exc
                if not isinstance(data, dict):
                    raise ValueError(f'Scryfall JSONL line {line_no} is not an object')
                yield data


def get_exact_scryfall_matches(path, wanted):
    matches = {}
    records_scanned = 0
    for card in iter_scryfall(path):
        records_scanned += 1
        cid = card.get('arena_id')
        if type(cid) is not int or cid not in wanted:
            continue
        if not isinstance(card.get('name'), str) or not card['name'].strip():
            raise ValueError(f'Scryfall exact Arena ID {cid} lacks a name')
        if cid in matches:
            previous = matches[cid]
            if previous != card:
                raise ValueError(f'Conflicting Scryfall data for exact Arena ID {cid}')
        matches[cid] = card
    return matches, records_scanned


def build_index(collection_rows, scryfall, overrides, deck_index=None):
    if deck_index is not None and not isinstance(deck_index, dict):
        raise ValueError('Optional deck index must be an object')
    cards = {}
    stats = Counter()
    unresolved = []
    override_conflicts = []
    for cid, ownership in sorted(collection_rows.items()):
        sf = scryfall.get(cid)
        ov = overrides.get(cid)
        record = {
            'arena_id': cid,
            'owned_quantity': ownership['quantity'],
            'ownership_record_format': ownership['record_format'],
            'ownership_field_a': ownership['field_a'],
            'ownership_source': 'mtga_process_memory_candidate',
            'metadata_source': None,
            'metadata_level': 'unresolved',
        }
        record.update({field: None for field in FIELDS})
        if sf is not None:
            sf_mapping = {'mana_value': 'cmc', 'scryfall_id': 'id'}
            for field in FIELDS:
                record[field] = sf.get(sf_mapping.get(field, field))
            record['metadata_source'] = 'scryfall_exact_arena_id'
            record['metadata_level'] = 'scryfall_printing'
            stats['scryfall_exact'] += 1
            if ov is not None:
                stats['override_also_present_in_scryfall'] += 1
                if sf['name'] != ov['name'] or (sf.get('set') or '').lower() != ov['set'].lower():
                    override_conflicts.append({
                        'arena_id': cid, 'scryfall_name': sf['name'],
                        'override_name': ov['name'],
                        'scryfall_set': sf.get('set'), 'override_set': ov['set'],
                    })
        elif ov is not None:
            record.update({
                'name': ov['name'],
                'set': ov['set'],
                'collector_number': ov['collector_number'],
                'metadata_source': ov['source'],
                'metadata_level': 'arena_identity_only',
            })
            stats['arena_verified_identity_only'] += 1
        else:
            unresolved.append(cid)
            stats['unresolved'] += 1
        if deck_index is not None and str(cid) in deck_index:
            record['deck_usage'] = deck_index[str(cid)]
            stats['found_in_saved_decks'] += 1
        cards[str(cid)] = record
    summary = {
        'owned_arena_ids': len(cards),
        'recorded_owned_copies': sum(row['quantity'] for row in collection_rows.values()),
        'scryfall_exact_arena_ids': stats['scryfall_exact'],
        'arena_db_verified_identity_only': stats['arena_verified_identity_only'],
        'unresolved_arena_ids': len(unresolved),
        'full_scryfall_metadata_not_available': len(cards) - stats['scryfall_exact'],
        'also_present_in_override_file': stats['override_also_present_in_scryfall'],
        'overlapping_identity_disagreements': len(override_conflicts),
        'found_in_saved_decks': stats['found_in_saved_decks'],
    }
    return {'summary': summary, 'cards': cards,
            'unresolved_ids': unresolved,
            'scryfall_override_disagreements': override_conflicts}


def save_new_json(path, data, inputs):
    if path.name.lower() in PROTECTED_BASENAMES:
        raise ValueError(f'Refusing to write protected filename: {path.name}')
    if any(path.resolve() == p.resolve() for p in inputs):
        raise ValueError('Output must not be an input file')
    if os.path.lexists(path):
        raise FileExistsError(f'Output already exists: {path}')
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile('w', dir=path.parent, suffix='.tmp',
                                         encoding='utf-8', delete=False) as f:
            temporary = Path(f.name)
            json.dump(data, f, indent=2, ensure_ascii=False)
            f.write('\n')
            f.flush()
            os.fsync(f.fileno())
        # Atomic no-overwrite publish on the same filesystem.
        os.link(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def run_self_test():
    import io
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        candidate = root / 'candidate.json'
        candidate.write_text(json.dumps({'status': 'candidate_unconfirmed',
            'runs': [{'record_count': 3, 'records': [
                {'card_id': 10, 'quantity': 2, 'field_a': -1, 'record_format': 'sentinel'},
                {'card_id': 20, 'quantity': 1, 'field_a': 7, 'record_format': 'non_sentinel'},
                {'card_id': 30, 'quantity': 3, 'field_a': -1, 'record_format': 'sentinel'},
            ]}]}), encoding='utf-8')
        overrides = root / 'overrides.json'
        overrides.write_text(json.dumps({'20': {'arena_id': 20, 'name': 'A-Rebalanced Example',
            'set': 'abc', 'collector_number': '5', 'scryfall_id': None, 'oracle_id': None,
            'source': 'mtga_local_sqlite_exact_grp_id'}}), encoding='utf-8')
        scryfall_file = root / 'scryfall.jsonl.gz'
        with gzip.open(scryfall_file, 'wt', encoding='utf-8') as file:
            file.write(json.dumps({'arena_id': 10, 'id': 'uuid-a', 'name': 'Paper Example',
                                   'set': 'xyz', 'cmc': 2, 'color_identity': ['W'],
                                   'legalities': {'historicbrawl': 'legal'}}) + '\n')
            file.write(json.dumps({'arena_id': 99, 'name': 'Unowned Example'}) + '\n')
        collection, rows = load_collection(candidate)
        assert collection['status'] == 'candidate_unconfirmed'
        ov = load_overrides(overrides)
        sf, scanned = get_exact_scryfall_matches(scryfall_file, set(rows))
        assert scanned == 2
        result = build_index(rows, sf, ov, {'10': {'deck_count': 2}})
        assert result['summary']['owned_arena_ids'] == 3
        assert result['summary']['scryfall_exact_arena_ids'] == 1
        assert result['summary']['arena_db_verified_identity_only'] == 1
        assert result['unresolved_ids'] == [30]
        assert result['cards']['20']['name'] == 'A-Rebalanced Example'
        assert result['cards']['20']['legalities'] is None
        assert result['cards']['20']['color_identity'] is None
        assert result['cards']['10']['legalities']['historicbrawl'] == 'legal'
        assert result['cards']['10']['deck_usage']['deck_count'] == 2
        out = root / 'output.json'
        save_new_json(out, result, [candidate, overrides, scryfall_file])
        before = out.read_bytes()
        try:
            save_new_json(out, {'cards': {}}, [candidate])
            raise AssertionError('Existing output overwritten')
        except FileExistsError:
            assert out.read_bytes() == before
        try:
            save_new_json(root / 'resolved_cards.json', result, [candidate])
            raise AssertionError('Protected basename accepted')
        except ValueError:
            pass
        duplicate = root / 'duplicate.json'
        duplicate.write_text(json.dumps({'runs': [{'record_count': 2, 'records': [
            {'card_id': 10, 'quantity': 2, 'field_a': -1, 'record_format': 'sentinel'},
            {'card_id': 10, 'quantity': 1, 'field_a': -1, 'record_format': 'sentinel'}]}]}))
        try:
            load_collection(duplicate)
            raise AssertionError('Duplicate collection ID accepted')
        except ValueError:
            pass
        conflict = dict(sf)
        conflict[20] = {'arena_id': 20, 'name': 'Completely Different', 'set': 'zzz'}
        overlap = build_index(rows, conflict, ov)
        assert overlap['summary']['overlapping_identity_disagreements'] == 1
        assert overlap['cards']['20']['metadata_source'] == 'scryfall_exact_arena_id'
        assert overlap['cards']['20']['name'] == 'Completely Different'
    print('SELF-TEST PASS: exact Scryfall ID, verified Arena fallback, unknown metadata, '
          'unresolved retention, deck usage separation, conflicts, duplicates, '
          'atomic no-overwrite output.')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--candidate', type=Path, default=DEFAULT_CANDIDATE)
    p.add_argument('--scryfall', type=Path, default=DEFAULT_SCRYFALL)
    p.add_argument('--overrides', type=Path, default=DEFAULT_OVERRIDES)
    p.add_argument('--deck-index', type=Path,
                   help='Optional EXISTING deck-usage index, attached only as context')
    p.add_argument('--output', type=Path, default=DEFAULT_OUTPUT)
    p.add_argument('--self-test', action='store_true')
    args = p.parse_args()
    if args.self_test:
        run_self_test()
        return
    inputs = [args.candidate, args.scryfall, args.overrides]
    if args.deck_index:
        inputs.append(args.deck_index)
    for path in inputs:
        if not path.is_file():
            p.error(f'Input file does not exist: {path}')
    if args.output.name.lower() in PROTECTED_BASENAMES:
        p.error(f'Protected output filename: {args.output.name}')
    if args.output.exists() or os.path.lexists(args.output):
        p.error(f'Output exists; choose a NEW file: {args.output}')
    if any(args.output.resolve() == x.resolve() for x in inputs):
        p.error('Output must be different from every input')
    candidate, ownership = load_collection(args.candidate)
    overrides = load_overrides(args.overrides)
    scryfall, scanned = get_exact_scryfall_matches(args.scryfall, set(ownership))
    deck_index = (json.loads(args.deck_index.read_text(encoding='utf-8'))
                  if args.deck_index else None)
    result = build_index(ownership, scryfall, overrides, deck_index)
    result.update({
        'status': 'resolved_collection_candidate_unconfirmed',
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'source_collection_status': candidate.get('status'),
        'sources': {'collection': str(args.candidate),
                    'scryfall_bulk': str(args.scryfall),
                    'arena_id_overrides': str(args.overrides),
                    'deck_index': str(args.deck_index) if args.deck_index else None},
        'caution': ('An exact Arena identity is not proof of complete Scryfall rules or '
                    'format legality. Unknown fields are null. Ownership is provisional.'),
    })
    save_new_json(args.output, result, inputs)
    counts = result['summary']
    print(f'Scryfall records scanned: {scanned:,}')
    print(f'Owned Arena IDs: {counts["owned_arena_ids"]:,}; recorded copies: '
          f'{counts["recorded_owned_copies"]:,}')
    print(f'Exact Scryfall IDs: {counts["scryfall_exact_arena_ids"]:,}')
    print(f'Verified Arena-ID fallback: {counts["arena_db_verified_identity_only"]:,}')
    print(f'Unresolved identities: {counts["unresolved_arena_ids"]:,}')
    print(f'Without full Scryfall metadata: {counts["full_scryfall_metadata_not_available"]:,}')
    print(f'Override/Scryfall identity disagreements: '
          f'{counts["overlapping_identity_disagreements"]:,}')
    print(f'Saved NEW candidate index: {args.output}')
    print('No production files or game data changed.')


if __name__ == '__main__':
    main()
