#!/usr/bin/env python3
"""Install fail-closed diagnostics in the existing MTGA Windows extractor.

This is deliberately NOT a consensus relaxation. It only prints why physical
copies fail to group, and leaves the acceptance and export logic unchanged.
Run from the WSL repository root. No Arena access is performed by installer.
"""
import argparse
import os
from pathlib import Path
import stat
import tempfile

TARGET = Path('windows/extract_collection_mixed_change_aware.py')
MARKER = '# MTGA_CONSENSUS_DIAGNOSTICS_V1'
INSERT_BEFORE = '\ndef select_consensus(windows, reference, controls):\n'
ORIGINAL_NEEDLE = ('    passing = [members for members in groups.values() if len(members) >= 2]\n'
                   '    require(len(passing) == 1,\n')
REPLACEMENT = ('    passing = [members for members in groups.values() if len(members) >= 2]\n'
               '    if len(passing) != 1:\n'
               '        print_consensus_diagnostics(inspected)\n'
               '    require(len(passing) == 1,\n')

DIAGNOSTICS = '''
# MTGA_CONSENSUS_DIAGNOSTICS_V1

def print_consensus_diagnostics(inspected, sample_limit=12):
    """Compare VALID complete copies only; diagnostics never authorise export.

    IDs, quantities, record formats, field A, and row ordering are compared
    independently, so differing metadata cannot be mistaken for ownership drift.
    """
    valid = [(win, assessment) for win, assessment in inspected if assessment['valid']]
    print('\\nCONSENSUS DIAGNOSTICS (read-only; no snapshot accepted):', flush=True)
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
    print('  No raw memory dumped; no collection output written by diagnostics.\\n',
          flush=True)
'''


def changed_source(source):
    if MARKER in source:
        raise ValueError('Diagnostics already installed; no changes made')
    if source.count(INSERT_BEFORE) != 1 or source.count(ORIGINAL_NEEDLE) != 1:
        raise ValueError('Extractor source differs from supported layout; do NOT patch automatically')
    source = source.replace(INSERT_BEFORE, '\n' + DIAGNOSTICS + INSERT_BEFORE, 1)
    source = source.replace(ORIGINAL_NEEDLE, REPLACEMENT, 1)
    compile(source, str(TARGET), 'exec')
    return source


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', type=Path, default=TARGET)
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    if args.self_test:
        base = '''import hashlib\nimport json\ndef require(test, why):\n    if not test: raise RuntimeError(why)\n\ndef select_consensus(windows, reference, controls):\n    groups = {}\n    passing = [members for members in groups.values() if len(members) >= 2]\n    require(len(passing) == 1,\n            'No consensus')\n'''
        result = changed_source(base)
        assert MARKER in result and 'print_consensus_diagnostics(inspected)' in result
        assert result.count('    require(len(passing) == 1,') == 1
        print('SELF-TEST PASS: change is diagnostics-only; original fail-closed require retained')
        return
    target = args.target.resolve()
    if not target.is_file():
        parser.error(f'Extractor not found: {target}')
    original = target.read_text(encoding='utf-8')
    try:
        revised = changed_source(original)
    except ValueError as error:
        parser.error(str(error))
    backup = target.with_name(target.name + '.pre_consensus_diagnostics.bak')
    if backup.exists():
        parser.error(f'Backup already exists; refusing to overwrite: {backup}')
    print(f'Original: {target}')
    print(f'Backup:   {backup}')
    if args.dry_run:
        print('DRY RUN PASS: patch locators and Python syntax verified; no files written')
        return
    # Exclusive backup creation; never overwrite original backup or data files.
    try:
        with backup.open('x', encoding='utf-8') as f:
            f.write(original)
    except FileExistsError:
        parser.error('Backup appeared while installing; refusing to overwrite')
    mode = stat.S_IMODE(target.stat().st_mode)
    fd, temp_name = tempfile.mkstemp(prefix=target.name + '.', suffix='.tmp', dir=target.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(revised)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(temp_name, mode)
        os.replace(temp_name, target)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)
    print('INSTALLED: strict consensus requirement unchanged; next ./mtga run will show pairwise diagnostics on failure')
    print(f'To restore: cp {backup} {target}')


if __name__ == '__main__':
    main()
