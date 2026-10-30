#!/usr/bin/env python3
"""Safely patch the MTGA change-aware extractor to validate OWNERSHIP consensus.

Requires at least two independent, fully structurally validated sequences with
identical ORDERED (Arena ID, quantity) pairs. Auxiliary field A / format may
vary between the copies, and disagreement is reported in the snapshot.

No process access or live collection reading. Run from the WSL repo root.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import contextlib
import io
import os
from pathlib import Path
import stat
import sys
import tempfile

TARGET = Path('windows/extract_collection_mixed_change_aware.py')
MARKER = '# MTGA_OWNERSHIP_CONSENSUS_V1'
BACKUP_SUFFIX = '.pre_ownership_consensus.bak'


def substitute_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise ValueError(f'Unexpected {label} source layout ({count} matches); refusing patch')
    return text.replace(old, new, 1)


def patched_source(source: str) -> str:
    if MARKER in source:
        raise ValueError('Ownership-consensus patch already installed; no changes made')
    source = substitute_once(source,
        '    signature = tuple((r[\'card_id\'], r[\'field_a\'], r[\'field_b\']) for r in rows)\n',
        '    signature = tuple((r[\'card_id\'], r[\'field_a\'], r[\'field_b\']) for r in rows)\n'
        '    # MTGA_OWNERSHIP_CONSENSUS_V1: compare the ownership-bearing fields only.\n'
        '    ownership_signature = tuple((r[\'card_id\'], r[\'field_b\']) for r in rows)\n',
        'assessment signature')
    source = substitute_once(source,
        "        'signature': signature, 'count': len(rows),\n",
        "        'signature': signature, 'ownership_signature': ownership_signature,\n"
        "        'count': len(rows),\n",
        'assessment return')
    source = substitute_once(source,
        "            groups[review['signature']].append((window, review))\n",
        "            groups[review['ownership_signature']].append((window, review))\n",
        'consensus grouping')

    # The original triple digest is retained so the standalone auditor still
    # confirms exactly which primary copy supplied field_a and format.
    source = substitute_once(source,
        "    digest = hashlib.sha256(json.dumps(triples, separators=(',', ':')).encode()).hexdigest()\n",
        """    digest = hashlib.sha256(json.dumps(triples, separators=(',', ':')).encode()).hexdigest()
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
""",
        'payload digest')
    source = substitute_once(source,
        "        'selection_method': 'autodiscovery_matching_contiguous_mixed_runs_change_aware',\n",
        "        'selection_method': 'autodiscovery_ordered_ownership_consensus_change_aware',\n",
        'selection method')
    source = substitute_once(source,
        "        'ownership_validation_policy': ('historical UI checks are advisory; ' \n"
        "            'two matching complete sequences and strong reference similarity required'),\n",
        "        'ownership_validation_policy': ('historical UI checks are advisory; ' \n"
        "            'two physically distinct structurally valid complete sequences must agree ' \n"
        "            'on ordered Arena IDs and quantities; field_a and format are NOT ' \n"
        "            'corroborated when copies disagree; strong reference similarity required'),\n",
        'policy label')
    source = substitute_once(source,
        "            'matching_copies': len(windows),\n            'all_matching': True,\n"
        "            'record_signature_sha256': digest,\n",
        "            'matching_copies': len(windows),\n"
        "            'all_matching': strict_record_consensus,\n"
        "            'ownership_consensus': True,\n"
        "            'consensus_basis': 'ordered_card_id_quantity',\n"
        "            'ownership_signature_sha256': ownership_digest,\n"
        "            'auxiliary_field_source': 'first_selected_physical_copy_only',\n"
        "            'auxiliary_field_a_disagreements': len(field_a_disagreements),\n"
        "            'auxiliary_format_disagreements': len(format_disagreements),\n"
        "            'auxiliary_disagreement_sample_ids': field_a_disagreements[:20],\n"
        "            'record_signature_sha256': digest,\n",
        'payload audit fields')
    source = substitute_once(source,
        "    print(f'  Matching physical copies: {len(selected)}')\n",
        """    print(f'  Ownership-agreeing physical copies: {len(selected)}')
    aux = payload['mixed_format_audit']
    print(f'  Ordered ID/quantity consensus: YES '
          f'(sha256 {aux["ownership_signature_sha256"][:16]})')
    print(f'  Auxiliary metadata: field_a disagrees on '
          f'{aux["auxiliary_field_a_disagreements"]} IDs; '
          f'format disagrees on {aux["auxiliary_format_disagreements"]} IDs')
    if not aux['all_matching']:
        print('  NOTE: exported field_a/format come from one physical copy; '
              'their values are NOT cross-copy verified')
""",
        'console reporting')
    compile(source, str(TARGET), 'exec')
    return source


def offline_regression(source: str, target: Path) -> None:
    """Run synthetic consensus tests against revised code, no Arena/baseline."""
    # Load the exact patched text as a module, not the installed original.
    import types
    directory = str(target.resolve().parent)
    sys.path.insert(0, directory)
    module = types.ModuleType('mtga_candidate_consensus_regression')
    module.__file__ = str(target)
    try:
        exec(compile(source, str(target), 'exec'), module.__dict__)
    finally:
        sys.path.pop(0)

    original = []
    for i in range(400):
        cid = 60001 + i
        a = -1 if i % 2 == 0 else (i + 10)
        original.append({'card_id': cid, 'field_a': a, 'field_b': (i % 4) + 1,
                         'format': 'sentinel' if a == -1 else 'non_sentinel'})
    ref = {r['card_id']: r['field_b'] for r in original}

    def window(rows, base):
        copied = deepcopy(rows)
        for i, item in enumerate(copied):
            item['address'] = hex(base + i * 16)
        return {'seed_records': copied,
                'seed_run_summary': {'quantity_conflicts': []},
                'read_notes': [], 'seed_run_clipped_left': False,
                'seed_run_clipped_right': False, 'anchor': hex(base + 16)}

    first = window(original, 0x10000000)
    second_rows = deepcopy(original)
    # Flip formats and modify auxiliary integers without touching ownership.
    for i in range(0, 60):
        r = second_rows[i]
        r['field_a'] = (i + 1000) if r['field_a'] == -1 else -1
        r['format'] = 'non_sentinel' if r['field_a'] != -1 else 'sentinel'
    second = window(second_rows, 0x20000000)
    chosen, _ = module.select_consensus([first, second], ref, {})
    assert len(chosen) == 2, 'Same ownership with different auxiliaries must pass'
    payload = module.build_payload(0, chosen, Path('baseline.json'), ref, 2)
    audit = payload['mixed_format_audit']
    assert audit['ownership_consensus'] is True
    assert audit['all_matching'] is False
    assert audit['auxiliary_field_a_disagreements'] == 60
    assert audit['auxiliary_format_disagreements'] == 60
    assert payload['runs'][0]['records'][0]['field_a'] == original[0]['field_a']

    # No auxiliary mismatches: strict record matching remains detectable.
    strict, _ = module.select_consensus([first, window(original, 0x30000000)], ref, {})
    assert module.build_payload(0, strict, Path('baseline.json'), ref, 2)[
        'mixed_format_audit']['all_matching'] is True

    # Fail closed for a quantity disagreement, same IDs reordered, one copy.
    badqty = deepcopy(second_rows)
    badqty[10]['field_b'] = 2 if badqty[10]['field_b'] != 2 else 3
    reordered = deepcopy(second_rows)
    reordered[10], reordered[11] = reordered[11], reordered[10]
    for title, windows in (
        ('changed quantity', [first, window(badqty, 0x20000000)]),
        ('changed order', [first, window(reordered, 0x20000000)]),
        ('one copy', [first]),
    ):
        try:
            # The installed diagnostic hook prints detailed disagreement rows
            # on expected failure; keep self-test output brief.
            with contextlib.redirect_stdout(io.StringIO()):
                module.select_consensus(windows, ref, {})
        except RuntimeError:
            pass
        else:
            raise AssertionError(f'Fail-closed regression failed: {title}')
    print('SELF-TEST PASS: auxiliary-only differences accepted; quantity/order/single-copy '
          'differences rejected; provenance and record digest preserved')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', type=Path, default=TARGET)
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    target = args.target.resolve()
    if not target.is_file():
        parser.error(f'Target extractor not found: {target}')
    original = target.read_text(encoding='utf-8')
    try:
        revised = patched_source(original)
        offline_regression(revised, target)
    except (ValueError, AssertionError, RuntimeError, SyntaxError) as exc:
        parser.error(str(exc))
    if args.self_test:
        print('No files modified (--self-test)')
        return
    backup = target.with_name(target.name + BACKUP_SUFFIX)
    if backup.exists():
        parser.error(f'Backup already exists; refusing to overwrite {backup}')
    print(f'  Target: {target}')
    print(f'  Backup: {backup}')
    if args.dry_run:
        print('DRY RUN PASS: file patch compatible, source compiles; no files modified')
        return
    mode = stat.S_IMODE(target.stat().st_mode)
    try:
        with backup.open('x', encoding='utf-8') as dest:
            dest.write(original)
    except FileExistsError:
        parser.error('Backup was created by another process; refusing overwrite')
    fd, temp = tempfile.mkstemp(prefix=target.name + '.', suffix='.tmp', dir=target.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as dest:
            dest.write(revised)
            dest.flush()
            os.fsync(dest.fileno())
        os.chmod(temp, mode)
        os.replace(temp, target)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)
    print('INSTALLED: two-copy ordered ownership consensus; auxiliary differences noted')
    print('Original extractor saved to:', backup)


if __name__ == '__main__':
    main()
