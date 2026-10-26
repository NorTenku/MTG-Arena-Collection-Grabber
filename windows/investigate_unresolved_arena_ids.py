#!/usr/bin/env python3
"""Investigate unmapped MTGA Arena IDs without inventing card identities.

Offline by default: reads collection_candidate.json and local Scryfall
JSONL(.gz) and reports exact Arena-ID gaps and nearby-ID *hints*.
Optionally resolves the gaps using MTGA's local SQLite card database by exact GrpId.
With explicit --online, queries Scryfall /cards/arena/{id} for each unresolved ID
(rate limited). Only returns mappings when the response's arena_id exactly
matches the requested ID. 404 / connectivity failures NEVER become mappings.

Outputs use exclusive create: existing files and collection data stay intact.
No Arena process is accessed. Python standard library only.
"""
import argparse
from collections import Counter, defaultdict
import csv
import gzip
import json
import re
import sqlite3
from pathlib import Path
import sys
import time
from urllib import error, request

USER_AGENT = 'MTGA-Collection-Research/0.1 (local personal metadata reconciliation)'
SCRYFALL_BASE = 'https://api.scryfall.com/cards/arena/'


def load_collection(path: Path):
    payload = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(payload, dict) or not isinstance(payload.get('runs'), list):
        raise ValueError('Expected a collection JSON with a runs list')
    rows = [r for run in payload['runs'] for r in run.get('records', [])]
    by_id = {}
    for row in rows:
        cid, qty = row.get('card_id'), row.get('quantity')
        if type(cid) is not int or cid <= 0 or type(qty) is not int or not 1 <= qty <= 4:
            raise ValueError(f'Invalid collection record: {row!r}')
        if cid in by_id:
            raise ValueError(f'Duplicate Arena ID: {cid}')
        by_id[cid] = row
    if not by_id:
        raise ValueError('No collection records found')
    return by_id


def index_scryfall(path: Path, needed_ids: set):
    """Stream local Scryfall JSONL, retaining only metadata for requested IDs."""
    lookup, duplicates = {}, []
    opener = gzip.open if path.suffix.lower() == '.gz' else open
    with opener(path, 'rt', encoding='utf-8') as stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            card = json.loads(line)
            if not isinstance(card, dict):
                continue
            cid = card.get('arena_id')
            if type(cid) is not int or cid not in needed_ids:
                continue
            brief = {
                'arena_id': cid, 'name': card.get('name'), 'set': card.get('set'),
                'collector_number': card.get('collector_number'),
                'scryfall_id': card.get('id'), 'oracle_id': card.get('oracle_id'),
                'type_line': card.get('type_line'),
            }
            if cid in lookup and brief != lookup[cid]:
                duplicates.append((cid, line_number))
            else:
                lookup.setdefault(cid, brief)
    return lookup, duplicates


def index_mtga_local_db(path: Path, requested_ids: set):
    """Read exact card identities from Arena's own SQLite DB, WITHOUT modifying it.

    Expected schema: Cards(GrpId,TitleId,ExpansionCode,CollectorNumber,...) and
    Localizations_enUS(LocId,Formatted,Loc). No guessing from ID proximity.
    """
    if not requested_ids:
        return {}, {}
    db_uri = path.resolve().as_uri() + '?mode=ro'
    connection = sqlite3.connect(db_uri, uri=True, timeout=5)
    try:
        cur = connection.cursor()
        tables = {row[0] for row in cur.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        if not {'Cards', 'Localizations_enUS'} <= tables:
            raise ValueError('Not a supported Arena card database: Cards or Localizations_enUS missing')
        cols = {row[1] for row in cur.execute('PRAGMA table_info(Cards)')}
        required = {'GrpId','TitleId','ExpansionCode','CollectorNumber'}
        if not required <= cols:
            raise ValueError('Missing required Arena Cards columns: ' +
                             ', '.join(sorted(required - cols)))
        loccols = {row[1] for row in cur.execute('PRAGMA table_info(Localizations_enUS)')}
        if not {'LocId','Formatted','Loc'} <= loccols:
            raise ValueError('Unexpected Arena enUS localization table schema')
        output = {}
        missing_localization = {}
        for start in range(0, len(requested_ids), 500):
            group = sorted(requested_ids)[start:start + 500]
            placeholders = ','.join('?' for _ in group)
            sql = f"""SELECT c.GrpId, c.TitleId, c.ExpansionCode,
                       c.CollectorNumber, l.Formatted, l.Loc
                       FROM Cards c LEFT JOIN Localizations_enUS l
                       ON l.LocId = c.TitleId
                       WHERE c.GrpId IN ({placeholders})
                       ORDER BY c.GrpId, l.Formatted"""
            candidates = defaultdict(list)
            for cid, title_id, expansion, collector, fmt, name in cur.execute(sql, group):
                candidates[int(cid)].append((int(title_id or 0), expansion, collector, fmt, name))
            for cid, variants in candidates.items():
                # Set and collector number must not conflict for one exact GrpId.
                printings = {(str(x[1] or ''),str(x[2] or '')) for x in variants}
                if len(printings) != 1:
                    missing_localization[cid] = 'Conflicting printings for same Arena GrpId'
                    continue
                preferred = sorted(variants, key=lambda x: (x[3] != 0, x[3] != 1, x[3] is None))
                chosen = next((x for x in preferred if isinstance(x[4],str) and x[4].strip()), None)
                if chosen is None:
                    missing_localization[cid] = 'Arena DB record found but localized name missing'
                    continue
                name = re.sub(r'<[^>]+>', '', chosen[4]).strip()
                if not name:
                    missing_localization[cid] = 'Arena DB localized name was blank'
                    continue
                output[cid] = {
                    'arena_id': cid, 'name': name,
                    'set': str(chosen[1] or '').lower(),
                    'collector_number': str(chosen[2] or ''),
                    'source': 'mtga_local_sqlite_exact_grp_id',
                    'source_db': str(path),
                    'scryfall_id': None, 'oracle_id': None,
                    'note': 'Exact Arena ID and local name; Scryfall legality and oracle metadata still unknown',
                }
        return output, missing_localization
    finally:
        connection.close()


def nearby_hint(cid, known, radius=6):
    """Heuristic, informational neighbors; NEVER an automatic card assignment."""
    nearby = [(abs(other-cid), other, known[other]) for other in known
              if 0 < abs(other-cid) <= radius]
    nearby.sort(key=lambda item: (item[0], item[1]))
    return [{
        'arena_id': other, 'id_delta': other-cid,
        'name': card['name'], 'set': card['set'],
        'collector_number': card['collector_number'],
    } for _, other, card in nearby[:4]]


def exact_online_lookup(cid, *, timeout=15, opener=None):
    """Return ('verified'|'missing'|'error'|'rate_limited', card-or-message)."""
    opener = opener or request.urlopen
    req = request.Request(
        SCRYFALL_BASE + str(cid),
        headers={'User-Agent': USER_AGENT, 'Accept': 'application/json'},
    )
    try:
        with opener(req, timeout=timeout) as response:
            data = json.loads(response.read())
    except error.HTTPError as exc:
        if exc.code == 404:
            return 'missing', 'Scryfall returned HTTP 404 for this Arena ID'
        if exc.code in (429, 503):
            return 'rate_limited', f'Scryfall returned HTTP {exc.code}'
        return 'error', f'Scryfall returned HTTP {exc.code}'
    except (error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        return 'error', str(exc)
    if (not isinstance(data, dict) or data.get('object') != 'card' or
            type(data.get('arena_id')) is not int or data['arena_id'] != cid or
            not isinstance(data.get('name'), str) or not data['name']):
        return 'error', 'Response did not contain a card with the exact requested arena_id'
    return 'verified', {
        'arena_id': cid, 'name': data['name'], 'set': data.get('set'),
        'collector_number': data.get('collector_number'),
        'scryfall_id': data.get('id'), 'oracle_id': data.get('oracle_id'),
        'type_line': data.get('type_line'),
        'color_identity': data.get('color_identity'),
        'legalities': data.get('legalities'),
        'source': 'scryfall_api_exact_arena_id',
        'uri': data.get('uri'),
    }


def analyze(collection, local, *, mtga_local=None, mtga_db_notes=None,
            online=False, limit=86, delay=0.20,
            lookup_func=exact_online_lookup, sleep_func=time.sleep):
    missing = [cid for cid in sorted(collection) if cid not in local]
    mtga_local = mtga_local or {}
    mtga_db_notes = mtga_db_notes or {}
    if limit < 0 or delay < 0:
        raise ValueError('limit and delay must be nonnegative')
    # Prioritize exact local game identifiers, then live Scryfall for the rest.
    remaining_after_db = [cid for cid in missing if cid not in mtga_local]
    requests_made, online_matches, statuses = 0, {}, {}
    suspended = False
    if online:
        for cid in remaining_after_db[:limit]:
            if requests_made:
                sleep_func(delay)
            status, outcome = lookup_func(cid)
            statuses[cid] = {'status': status}
            if status == 'verified':
                if outcome.get('arena_id') != cid:
                    statuses[cid] = {'status': 'error', 'details': 'Lookup returned mismatched ID'}
                else:
                    online_matches[cid] = outcome
            else:
                statuses[cid]['details'] = str(outcome)
            requests_made += 1
            if status in ('rate_limited', 'error') or statuses[cid]['status'] == 'error':
                suspended = True
                break
    verified = {**mtga_local, **online_matches}
    records, counts = [], Counter()
    for cid in missing:
        row = collection[cid]
        if cid in mtga_local:
            status = {'status': 'resolved_mtga_local_db'}
        else:
            status = statuses.get(cid, {'status': 'not_queried'})
        entry = {
            'arena_id': cid, 'quantity': row['quantity'],
            'record_format': row.get('record_format', 'unknown'),
            'field_a': row.get('field_a'),
            'online_status': status['status'],
            'online_details': status.get('details'),
            'local_db_note': mtga_db_notes.get(cid),
            'verified_card': verified.get(cid),
            'nearest_known_arena_ids_HINT_ONLY': nearby_hint(cid, local),
        }
        records.append(entry)
        counts[entry['online_status']] += 1
    return {
        'status': 'partial_online_lookup' if suspended else 'completed_requested_checks',
        'source_collection_ids': len(collection),
        'locally_resolved_ids': len(local),
        'initial_unresolved_ids': len(missing),
        'unresolved_quantity_copies': sum(collection[cid]['quantity'] for cid in missing),
        'initial_unresolved_by_record_format': dict(Counter(
            collection[cid].get('record_format', 'unknown') for cid in missing)),
        'local_game_db_verified_new_mappings': len(mtga_local),
        'local_game_db_unresolved_notes': {str(k): v for k,v in mtga_db_notes.items()},
        'online_requested': online,
        'online_requests_made': requests_made,
        'online_result_counts': dict(counts),
        'verified_online_mappings': len(online_matches),
        'verified_new_mappings': len(verified),
        'still_unresolved_ids': len(missing) - len(verified),
        'scryfall_api_verified_overrides': {str(k): v for k, v in sorted(online_matches.items())},
        'verified_overrides': {str(k): v for k, v in sorted(verified.items())},
        'records': records,
        'note': ('Nearby IDs are triage hints only. Do not infer identity or set from them. '
                 'Scryfall 404 means its API did not resolve the ID, not that the card is unowned. '
                 'Local Arena DB matches provide identity, not automatic Scryfall legality.'),
    }


def write_json_exclusive(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8') as out:
        json.dump(value, out, indent=2, ensure_ascii=False)
        out.write('\n')


def write_csv_exclusive(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8', newline='') as out:
        writer = csv.writer(out)
        writer.writerow(('arena_id','quantity','record_format','field_a',
                         'online_status','verified_name','verified_set',
                         'closest_known_hints_NON_AUTHORITATIVE'))
        for row in rows:
            verified = row['verified_card'] or {}
            hints = '; '.join(f"{i['arena_id']} ({i['id_delta']:+d}) "
                              f"{i['name']} [{i['set']}]" for i in
                              row['nearest_known_arena_ids_HINT_ONLY'])
            writer.writerow((row['arena_id'], row['quantity'], row['record_format'],
                             row['field_a'], row['online_status'],
                             verified.get('name'), verified.get('set'), hints))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--candidate', type=Path, default=Path('data/collection_candidate.json'))
    p.add_argument('--scryfall', type=Path, default=Path('data/scryfall_default_cards.jsonl.gz'))
    p.add_argument('--mtga-db', type=Path,
                   help='Optional Arena Raw_CardDatabase_*.mtga SQLite file, opened read-only')
    p.add_argument('--online', action='store_true',
                   help='Opt in to live exact-Arena-ID requests to Scryfall')
    p.add_argument('--limit', type=int, default=86,
                   help='Maximum online requests; 0 disables requests (default 86)')
    p.add_argument('--delay', type=float, default=0.20,
                   help='Seconds between Scryfall API requests (minimum 0.1; default 0.2)')
    p.add_argument('--report-json', type=Path, help='Write a new, detailed JSON report')
    p.add_argument('--review-csv', type=Path, help='Write a new CSV of unresolved IDs')
    p.add_argument('--verified-overrides', type=Path,
                   help='Write a new JSON mapping of exact-ID matches from Arena DB and/or Scryfall API')
    args = p.parse_args()
    if args.limit < 0 or args.limit > 500 or (args.online and args.delay < 0.1):
        p.error('limit must be 0–500; online delay must be >= 0.1 seconds')
    for label, path in [('candidate',args.candidate),('scryfall',args.scryfall),('mtga-db',args.mtga_db)]:
        if path is not None and not path.is_file():
            p.error(f'{label} file not found: {path}')
    outputs = [x for x in (args.report_json,args.review_csv,args.verified_overrides) if x]
    if len({str(x.resolve()) for x in outputs}) != len(outputs):
        p.error('Output paths must be distinct')
    for output in outputs:
        if output.exists():
            p.error(f'Refusing to overwrite existing file: {output}')
        if output.resolve() in (args.candidate.resolve(), args.scryfall.resolve()) or (
                args.mtga_db and output.resolve() == args.mtga_db.resolve()):
            p.error('Refusing to overwrite an input')
    collection = load_collection(args.candidate)
    known, collisions = index_scryfall(args.scryfall, set(collection))
    if collisions:
        p.error(f'Conflicting local Scryfall records for the same Arena ID: {collisions[:5]}')
    try:
        mtga_known, db_notes = index_mtga_local_db(args.mtga_db, set(collection) - set(known)) if args.mtga_db else ({}, {})
    except (sqlite3.Error, ValueError, OSError) as exc:
        p.error(f'Could not read local Arena card DB: {exc}')
    report = analyze(collection, known, mtga_local=mtga_known, mtga_db_notes=db_notes,
                     online=args.online, limit=args.limit, delay=args.delay)
    print('MTGA unresolved Arena-ID investigation (collection files unchanged)')
    print(f'  Candidate IDs: {len(collection):,}')
    print(f'  Local Scryfall exact Arena-ID matches: {len(known):,}')
    print(f'  Missing from local Scryfall: {report["initial_unresolved_ids"]:,} '
          f'({report["unresolved_quantity_copies"]:,} recorded copies)')
    print(f'  Breakdown: {report["initial_unresolved_by_record_format"]}')
    if args.mtga_db:
        print(f'  Exact local Arena DB matches: {report["local_game_db_verified_new_mappings"]}')
        print(f'  Local DB rows without usable names: {len(db_notes)}')
    if args.online:
        print(f'  API requests made: {report["online_requests_made"]}')
        print(f'  API verified new mappings: {report["verified_online_mappings"]}')
        print(f'  API statuses: {report["online_result_counts"]}')
        if report['status'] == 'partial_online_lookup':
            print('  WARNING: Lookups stopped early after a network/API error or rate limit.')
    else:
        print('  Online checks disabled; no network requests made.')
    print(f'  Total newly verified exact-ID mappings: {report["verified_new_mappings"]}')
    print(f'  Still unresolved after all sources: {report["still_unresolved_ids"]}')
    print('  Illustrative unresolved IDs (nearby-ID hints are NOT identity evidence):')
    for row in report['records'][:12]:
        nearby = row['nearest_known_arena_ids_HINT_ONLY']
        hint = f"nearby {nearby[0]['arena_id']} [{nearby[0]['set']}]" if nearby else 'no close known ID'
        verified = row['verified_card']
        name = f" -> VERIFIED {verified['name']}" if verified else ''
        print(f'    {row["arena_id"]:>7} x{row["quantity"]} ({hint}){name}')
    if args.report_json:
        write_json_exclusive(args.report_json, report)
        print(f'  Saved JSON: {args.report_json}')
    if args.review_csv:
        write_csv_exclusive(args.review_csv, report['records'])
        print(f'  Saved CSV: {args.review_csv}')
    if args.verified_overrides:
        # This is never a mapping of guessed neighbors or 404 records.
        write_json_exclusive(args.verified_overrides, report['verified_overrides'])
        print(f'  Saved verified-only mapping: {args.verified_overrides}')
    print('  Unresolved cards were not removed from the collection.')


if __name__ == '__main__':
    main()
