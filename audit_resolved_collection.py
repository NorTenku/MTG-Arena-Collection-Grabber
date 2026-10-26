#!/usr/bin/env python3
"""Offline, read-only cross-check for resolve_collection_cards.py output.

Independently checks every owned Arena ID and its quantity against the candidate
collection; verifies exact Arena DB fallback names and honest unknown rules fields.
"""
import argparse
from collections import Counter
import json
from pathlib import Path
import sys


def run(candidate_path, overrides_path, index_path):
    candidate = json.loads(candidate_path.read_text(encoding='utf-8'))
    overrides = json.loads(overrides_path.read_text(encoding='utf-8'))
    result = json.loads(index_path.read_text(encoding='utf-8'))
    problems = []
    originals = {}
    for run in candidate.get('runs', []):
        for row in run.get('records', []):
            key = str(row['card_id'])
            if key in originals:
                problems.append(f'Collection duplicate ID {key}')
            originals[key] = row
    cards = result.get('cards')
    if not isinstance(cards, dict):
        raise ValueError('Missing or malformed cards object')
    missing = sorted(set(originals) - set(cards), key=int)
    surplus = sorted(set(cards) - set(originals), key=int)
    if missing:
        problems.append(f'Owned IDs missing in index: {missing[:10]}')
    if surplus:
        problems.append(f'Extraneous IDs in index: {surplus[:10]}')
    source_counts = Counter()
    unresolved = []
    identity_only_ids = set()
    for key, card in cards.items():
        base = originals.get(key)
        if base is None:
            continue
        if card.get('arena_id') != int(key):
            problems.append(f'{key}: incorrect arena_id')
        if card.get('owned_quantity') != base['quantity']:
            problems.append(f'{key}: owned quantity differs from collection')
        if card.get('ownership_record_format') != base['record_format']:
            problems.append(f'{key}: wrong record format')
        if card.get('ownership_field_a') != base['field_a']:
            problems.append(f'{key}: wrong field_a')
        source = card.get('metadata_level')
        source_counts[source] += 1
        if source == 'arena_identity_only':
            identity_only_ids.add(key)
            ov = overrides.get(key)
            if ov is None or card.get('name') != ov.get('name') or card.get('set') != ov.get('set') or card.get('collector_number') != ov.get('collector_number'):
                problems.append(f'{key}: Arena DB identity not supported by exact override')
            if card.get('metadata_source') != 'mtga_local_sqlite_exact_grp_id':
                problems.append(f'{key}: incorrect Arena DB provenance')
            for field in ('mana_cost','mana_value','type_line','colors','color_identity',
                          'rarity','oracle_text','legalities','scryfall_uri','scryfall_id',
                          'oracle_id','card_faces'):
                if card.get(field) is not None:
                    problems.append(f'{key}: speculative {field} populated from name-only override')
        elif source == 'scryfall_printing':
            if card.get('metadata_source') != 'scryfall_exact_arena_id' or not card.get('name'):
                problems.append(f'{key}: malformed Scryfall provenance/name')
        elif source == 'unresolved':
            unresolved.append(key)
            if key in overrides:
                problems.append(f'{key}: verified Arena DB override was overlooked')
            for field in ('name','set','collector_number','mana_cost','mana_value',
                          'type_line','colors','color_identity','rarity','oracle_text',
                          'legalities','scryfall_uri','scryfall_id','oracle_id','card_faces',
                          'metadata_source'):
                if card.get(field) is not None:
                    problems.append(f'{key}: unresolved entry claims {field}')
        else:
            problems.append(f'{key}: unknown metadata level {source!r}')
    summary = result.get('summary')
    if not isinstance(summary, dict):
        raise ValueError('Missing summary object')
    expected = {
        'owned_arena_ids': len(originals),
        'recorded_owned_copies': sum(row['quantity'] for row in originals.values()),
        'scryfall_exact_arena_ids': source_counts['scryfall_printing'],
        'arena_db_verified_identity_only': source_counts['arena_identity_only'],
        'unresolved_arena_ids': len(unresolved),
        'full_scryfall_metadata_not_available': len(originals)-source_counts['scryfall_printing'],
    }
    for label, value in expected.items():
        if summary.get(label) != value:
            problems.append(f'Summary {label}: expected {value}, got {summary.get(label)}')
    expected_unresolved = sorted((int(key) for key in unresolved))
    if result.get('unresolved_ids') != expected_unresolved:
        problems.append('Unresolved ID list disagrees with card entries')
    print('Resolved MTGA collection — offline cross-check')
    print(f'Owned Arena IDs: {len(originals):,}')
    print(f'Recorded copies: {expected["recorded_owned_copies"]:,}')
    print(f'Exact Scryfall identities: {source_counts["scryfall_printing"]:,}')
    print(f'Verified Arena DB identity-only: {source_counts["arena_identity_only"]:,}')
    print(f'Unresolved identities: {len(unresolved):,}')
    print(f'Not supported by full Scryfall printing metadata: {expected["full_scryfall_metadata_not_available"]:,}')
    print(f'Structural/metadata consistency problems: {len(problems)}')
    for problem in problems[:30]:
        print('ERROR:', problem)
    if problems:
        raise SystemExit(1)
    print('PASS: ownership, IDs, quantities, verified identities and unknown fields consistent.')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--candidate', type=Path, default=Path('data/collection_change_aware_candidate.json'))
    p.add_argument('--overrides', type=Path, default=Path('data/arena_id_verified_overrides.json'))
    p.add_argument('--resolved', type=Path, default=Path('data/resolved_collection_candidate.json'))
    args = p.parse_args()
    for filename in (args.candidate,args.overrides,args.resolved):
        if not filename.is_file():
            p.error(f'Missing input: {filename}')
    run(args.candidate,args.overrides,args.resolved)


if __name__ == '__main__':
    main()
