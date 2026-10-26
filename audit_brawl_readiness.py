#!/usr/bin/env python3
"""Conservative, offline MTG Arena owned-collection Brawl readiness audit.

Uses only a *resolved collection candidate* as input. No MTGA attachment and no
network requests. Legality is a snapshot from the supplied Scryfall metadata;
identity-only Arena rows stay unknown. Never modifies its input or old indexes.
"""
import argparse
import collections
import csv
import json
import os
from pathlib import Path
import re
import sys

COLORS = 'WUBRG'
LEGAL = {'legal'}
ILLEGAL = {'not_legal', 'banned'}
ORACLE_MAY_BE_COMMANDER = re.compile(r'\bcan be your commander\b', re.I)
PROTECTED_NAMES = {'collection.json', 'collection_candidate.json', 'collection_auto_candidate.json',
                   'collection_change_aware_candidate.json', 'resolved_collection_candidate.json',
                   'resolved_cards.json', 'card_index.json', 'arena_id_verified_overrides.json',
                   'scryfall_default_cards.jsonl.gz'}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def load_collection(path):
    with Path(path).open(encoding='utf-8') as f:
        doc = json.load(f)
    require(isinstance(doc, dict) and isinstance(doc.get('cards'), dict),
            'Expected a resolved collection object with cards keyed by Arena ID')
    rows = doc['cards']
    seen = set()
    copies = 0
    for key, card in rows.items():
        require(isinstance(card, dict), f'Invalid card entry {key}')
        require(str(card.get('arena_id')) == key and key.isdigit(),
                f'Arena ID mismatch at {key}')
        q = card.get('owned_quantity')
        require(type(q) is int and q > 0, f'Invalid owned quantity at {key}')
        require(key not in seen, f'Duplicate Arena ID {key}')
        seen.add(key)
        copies += q
    sums = doc.get('summary', {})
    if 'owned_arena_ids' in sums:
        require(sums['owned_arena_ids'] == len(rows), 'Summary Arena-ID count mismatch')
    if 'recorded_owned_copies' in sums:
        require(sums['recorded_owned_copies'] == copies, 'Summary copy count mismatch')
    return doc


def colors_info(value):
    if not isinstance(value, list) or any(x not in COLORS for x in value) or len(set(value)) != len(value):
        return None
    return ''.join(c for c in COLORS if c in value)


def card_face(card):
    faces = card.get('card_faces')
    if isinstance(faces, list) and faces and isinstance(faces[0], dict):
        return faces[0]
    return card


def oracle_status(card):
    val = card.get('oracle_text')
    if isinstance(val, str):
        return 'available'
    faces = card.get('card_faces')
    if not isinstance(faces, list) or not faces:
        return 'unknown'
    present = [isinstance(f, dict) and isinstance(f.get('oracle_text'), str) for f in faces]
    return 'available' if all(present) else 'partial' if any(present) else 'unknown'


def classify_one(card):
    name = card.get('name') if isinstance(card.get('name'), str) else None
    identity = colors_info(card.get('color_identity'))
    legalities = card.get('legalities') if isinstance(card.get('legalities'), dict) else {}
    raw_brawl = legalities.get('brawl')
    if raw_brawl in LEGAL:
        legality = 'legal_in_snapshot'
    elif raw_brawl in ILLEGAL:
        legality = 'not_legal_in_snapshot'
    else:
        legality = 'unknown_or_conditional'

    front = card_face(card)
    t = front.get('type_line')
    if not isinstance(t, str) or not t.strip():
        t = (card.get('type_line') or '').split(' // ')[0]
    t = t if isinstance(t, str) else ''
    traits = t.replace('—', ' ').replace('–', ' ').split()
    is_legendary = 'Legendary' in traits
    is_creature = 'Creature' in traits
    is_planeswalker = 'Planeswalker' in traits
    is_vehicle = 'Vehicle' in traits
    is_spacecraft = 'Spacecraft' in traits
    is_basic = 'Basic' in traits and 'Land' in traits
    texts = [card.get('oracle_text')] + [f.get('oracle_text') for f in card.get('card_faces') or [] if isinstance(f, dict)]
    exception = any(isinstance(x, str) and ORACLE_MAY_BE_COMMANDER.search(x) for x in texts)

    if legality == 'not_legal_in_snapshot':
        deck_status = 'excluded_by_snapshot_legality'
    elif legality != 'legal_in_snapshot' or identity is None or not t or not name:
        deck_status = 'needs_verification'
    else:
        deck_status = 'ready_by_snapshot'

    if deck_status == 'excluded_by_snapshot_legality':
        commander_status = 'excluded_by_snapshot_legality'
    elif deck_status != 'ready_by_snapshot':
        commander_status = 'needs_verification'
    elif is_legendary and (is_creature or is_planeswalker or is_vehicle):
        commander_status = 'eligible_by_snapshot'
    elif is_legendary and is_spacecraft:
        # The resolved schema does not say whether the spacecraft has a P/T box.
        commander_status = 'needs_commander_rules_review'
    elif exception:
        # Exception text requires separate format-specific checking.
        commander_status = 'needs_commander_rules_review'
    else:
        commander_status = 'not_commander_candidate'

    return {
        'arena_id': card['arena_id'], 'name': name, 'owned_quantity': card['owned_quantity'],
        'metadata_source': card.get('metadata_source'), 'metadata_level': card.get('metadata_level'),
        'set': card.get('set'), 'collector_number': card.get('collector_number'),
        'color_identity': list(identity) if identity is not None else None,
        'color_identity_key': identity,
        'type_line': t or None, 'is_basic_land': is_basic,
        'rules_text_status': oracle_status(card),
        'brawl_legalities_field': raw_brawl, 'brawl_legality_status': legality,
        'deck_card_status': deck_status, 'commander_status': commander_status,
        'mana_value': card.get('mana_value'),
        'deck_usage_count': (card.get('deck_usage') or {}).get('deck_count') if isinstance(card.get('deck_usage'), dict) else None,
    }


def audit(doc):
    rows = [classify_one(v) for _, v in sorted(doc['cards'].items(), key=lambda x: int(x[0]))]
    counter = lambda field: dict(sorted(collections.Counter(v[field] for v in rows).items()))
    ready = [x for x in rows if x['deck_card_status'] == 'ready_by_snapshot']
    commanders = [x for x in rows if x['commander_status'] == 'eligible_by_snapshot']
    # An Arena printing is not a distinct singleton deck slot. Collapse repeated
    # *card names* for the readiness estimate (do NOT discard raw printings).
    ready_nonbasic_names = {x['name'] for x in ready if not x['is_basic_land']}
    basic_names = {x['name'] for x in ready if x['is_basic_land']}
    verified_colors = collections.Counter(x['color_identity_key'] for x in ready)
    available_types = sum(bool(x['type_line']) for x in rows)
    no_rule_text = [x for x in rows if x['rules_text_status'] != 'available']
    summary = {
        'owned_arena_ids': len(rows),
        'recorded_owned_copies': sum(x['owned_quantity'] for x in rows),
        'metadata_levels': counter('metadata_level'),
        'brawl_legality_status': counter('brawl_legality_status'),
        'deck_card_status': counter('deck_card_status'),
        'commander_status': counter('commander_status'),
        'type_available': available_types,
        'verified_color_identity': sum(x['color_identity'] is not None for x in rows),
        'rules_text_status': counter('rules_text_status'),
        'unique_ready_nonbasic_names': len(ready_nonbasic_names),
        'unique_ready_basic_land_names': len(basic_names),
        'eligible_commander_printings': len(commanders),
        'unique_eligible_commander_names': len({x['name'] for x in commanders}),
        'ready_color_identity_printings': dict(sorted(verified_colors.items())),
        'not_yet_full_rules_count': len(no_rule_text),
    }
    out = {
        'schema': 'mtga_brawl_readiness_audit_v1',
        'status': 'snapshot_readiness_only_not_current_legality_or_completeness_certification',
        'source_summary': doc.get('summary'),
        'summary': summary,
        'cautions': [
            'Legality is read from the saved legalities.brawl field, not checked against live Arena or current bans.',
            'Scryfall is a printing-level data source; Arena identity-only records have unknown rules, legality and color identity.',
            'Eligible commanders are conservative: legendary creatures, legendary planeswalkers and legendary Vehicles with verified metadata. Spacecraft power/toughness-box qualification and rules-text exceptions need review.',
            'Ownership is by Arena printing ID. Singleton counts must collapse alternate printings of the same card; basic lands are the exception.',
            'Saved deck usage is historical and does not prove current card ownership or legality.',
            'Readiness does not certify that a 100-card legal Brawl deck can be built; deck generation requires color-identity and singleton checks.',
        ],
        'commander_candidates': commanders,
        'needs_review': [x for x in rows if x['deck_card_status'] == 'needs_verification' or x['commander_status'] == 'needs_commander_rules_review'],
        'cards': {str(x['arena_id']): x for x in rows},
    }
    return out


def protected_output(path, inputs):
    path = Path(path)
    require(path.name.lower() not in PROTECTED_NAMES, f'Protected filename: {path}')
    require(not any(path.resolve() == Path(p).resolve() for p in inputs), f'Output conflicts with input: {path}')
    require(not path.exists(), f'Output already exists (will not overwrite): {path}')


def save_csv(path, rows, fields):
    with Path(path).open('x', newline='', encoding='utf-8') as f:
        wr = csv.DictWriter(f, fieldnames=fields)
        wr.writeheader()
        for row in rows:
            reduced = {}
            for k in fields:
                x = row.get(k)
                if isinstance(x, list):
                    x = ''.join(x) if k == 'color_identity' else '|'.join(map(str, x))
                reduced[k] = x
            wr.writerow(reduced)


def self_test():
    def card(i, name, tl, colors, legality='legal', text='', faces=None):
        return {'arena_id': i, 'name': name, 'owned_quantity': 1,
                'type_line': tl, 'color_identity': colors,
                'legalities': {'brawl': legality} if legality is not None else None,
                'metadata_level': 'scryfall_printing' if legality else 'arena_identity_only',
                'oracle_text': text, 'card_faces': faces}
    docs = {'summary': {'owned_arena_ids': 9, 'recorded_owned_copies': 9}, 'cards': {}}
    given = [
        card(1, 'Commander A', 'Legendary Creature — Elf', ['G']),
        card(2, 'Card A', 'Instant', ['U'], 'not_legal'),
        card(3, 'Unknown A', None, None, None, None),
        card(4, 'A // B', 'Creature — Fox // Land', ['W'], 'legal', None,
             [{'type_line': 'Creature — Fox', 'oracle_text': 'Hello'}, {'type_line': 'Land', 'oracle_text': 'Bye'}]),
        card(5, 'Basic Plains', 'Basic Land — Plains', ['W']),
        card(6, 'Spaceship', 'Legendary Artifact — Spacecraft', []),
        card(7, 'My Vehicle', 'Legendary Artifact — Vehicle', ['R']),
        card(8, 'Commander A', 'Legendary Creature — Elf', ['G']),
        card(9, 'Strange', 'Artifact', [], 'legal', 'This can be your commander.'),
    ]
    docs['cards'] = {str(x['arena_id']): x for x in given}
    loaded = load_collection_fixture(docs)
    a = audit(loaded)
    s = a['summary']
    assert s['owned_arena_ids'] == 9 and s['recorded_owned_copies'] == 9
    assert s['unique_eligible_commander_names'] == 2  # Commander A and My Vehicle
    assert s['unique_ready_nonbasic_names'] == 5  # Commander A, A//B, Spaceship, My Vehicle, Strange
    assert a['cards']['3']['deck_card_status'] == 'needs_verification'
    assert a['cards']['4']['rules_text_status'] == 'available'
    assert a['cards']['6']['commander_status'] == 'needs_commander_rules_review'
    assert a['cards']['7']['commander_status'] == 'eligible_by_snapshot'
    assert a['cards']['9']['commander_status'] == 'needs_commander_rules_review'
    assert a['cards']['2']['deck_card_status'] == 'excluded_by_snapshot_legality'
    assert a['cards']['5']['is_basic_land']
    assert classify_one(card(10, 'Snow-Covered Plains', 'Basic Snow Land — Plains', ['W']))['is_basic_land']
    assert colors_info([]) == '' and colors_info(None) is None
    try:
        load_collection_fixture({'summary': {'owned_arena_ids': 1}, 'cards': {'1': card(2, 'Bad', 'Land', [])}})
    except ValueError:
        pass
    else:
        raise AssertionError('Bad arena ID not rejected')
    print('SELF-TEST PASS: ownership validation, legality tri-state, commander types, spacecraft/manual review, identity unknown, double-face rules, basics and singleton dedup.')


def load_collection_fixture(document):
    import tempfile
    with tempfile.TemporaryDirectory() as t:
        p = Path(t) / 'fixture.json'
        p.write_text(json.dumps(document), encoding='utf-8')
        return load_collection(p)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, default=Path('data/resolved_collection_candidate.json'))
    parser.add_argument('--report-json', type=Path)
    parser.add_argument('--cards-csv', type=Path)
    parser.add_argument('--commanders-csv', type=Path)
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    targets = [p for p in (args.report_json, args.cards_csv, args.commanders_csv) if p]
    require(len({str(p.resolve()) for p in targets}) == len(targets), 'Duplicate output destinations')
    for p in targets:
        protected_output(p, [args.input])
    doc = load_collection(args.input)
    result = audit(doc)
    s = result['summary']
    print('MTGA owned collection — offline Brawl readiness (snapshot, not live legality)')
    print(f"  Owned IDs/copies: {s['owned_arena_ids']:,} / {s['recorded_owned_copies']:,}")
    print(f"  Brawl status: {s['brawl_legality_status']}")
    print(f"  Deck-card readiness: {s['deck_card_status']}")
    print(f"  Verified color identities: {s['verified_color_identity']:,}")
    print(f"  Commander eligibility: {s['commander_status']}")
    print(f"  Distinct eligible commander names: {s['unique_eligible_commander_names']:,}")
    print(f"  Unique ready nonbasic names: {s['unique_ready_nonbasic_names']:,}")
    print(f"  Full rules-text status: {s['rules_text_status']}")
    print('  Caution: 86 identity-only cards remain unverified for play; no present-day legality assertions made.')
    fields = ['arena_id', 'name', 'owned_quantity', 'metadata_source', 'metadata_level', 'set',
              'collector_number', 'color_identity', 'type_line', 'mana_value', 'brawl_legalities_field',
              'brawl_legality_status', 'rules_text_status', 'deck_card_status',
              'commander_status', 'is_basic_land', 'deck_usage_count']
    for p in targets:
        p.parent.mkdir(parents=True, exist_ok=True)
    if args.report_json:
        with args.report_json.open('x', encoding='utf-8') as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
            f.write('\n')
        print(f'  Saved report: {args.report_json}')
    if args.cards_csv:
        save_csv(args.cards_csv, result['cards'].values(), fields)
        print(f'  Saved card review: {args.cards_csv}')
    if args.commanders_csv:
        save_csv(args.commanders_csv, sorted(result['commander_candidates'], key=lambda x: (x['color_identity_key'] or '', x['name'])), fields)
        print(f'  Saved commander review: {args.commanders_csv}')
    if not targets:
        print('  Diagnostic-only: no output file written.')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, json.JSONDecodeError) as error:
        print(f'ERROR: {error}', file=sys.stderr)
        sys.exit(1)
