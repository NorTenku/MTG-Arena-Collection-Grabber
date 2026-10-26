#!/usr/bin/env python3
"""One-command, non-destructive MTG Arena collection capture for WSL2.

Run `./mtga` (or `python3 collection_control.py`) from anywhere.  The Windows
extractor is launched via py.exe; independent audits, card resolution and
optional Brawl-readiness are run in WSL Python.  Every capture writes to a new
run directory; no production data or baseline is overwritten.

The live capture still has status candidate_unconfirmed.  This controller does
not claim collection completeness or independently verify current Brawl rules.
"""
from __future__ import annotations

import argparse
from datetime import datetime
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Callable

ROOT = Path(__file__).resolve().parent
RUNS_SUBDIR = Path('data/snapshots')
RUN_PREFIX = 'mtga-run-'
DEFAULT_REFERENCE = Path('data/collection_candidate.json')
DEFAULT_SCRYFALL = Path('data/scryfall_default_cards.jsonl.gz')
DEFAULT_OVERRIDES = Path('data/arena_id_verified_overrides.json')
DEFAULT_DECK_INDEX = Path('data/card_index.json')


class ControlError(Exception):
    pass


def fail_if_missing(paths: list[Path]) -> None:
    missing = [p for p in paths if not p.is_file()]
    if missing:
        raise ControlError('Missing required files:\n  ' + '\n  '.join(str(p) for p in missing))


def required_paths(root: Path, reference: Path, scan_only: bool, no_brawl: bool) -> list[Path]:
    paths = [
        root / 'windows/extract_collection.py',
        root / 'windows/extract_collection_mixed_change_aware.py',
        root / 'windows/inspect_mixed_collection.py',
        root / 'windows/search_card_memory.py',
        root / 'windows/find_arena.py',
        root / 'windows/audit_collection_change_aware.py',
        reference,
        root / DEFAULT_SCRYFALL,
    ]
    if not scan_only:
        paths += [root / 'resolve_collection_cards.py',
                  root / 'audit_resolved_collection.py', root / DEFAULT_OVERRIDES]
        if not no_brawl:
            paths.append(root / 'audit_brawl_readiness.py')
    return paths


def wsl_windows_path(path: Path, invoke: Callable = subprocess.run) -> str:
    try:
        result = invoke(['wslpath', '-w', str(path.resolve())],
                        text=True, capture_output=True, check=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ControlError(f'Unable to translate WSL path {path}: {exc}') from exc
    converted = result.stdout.strip()
    if not converted:
        raise ControlError(f'Empty Windows path for {path}')
    return converted


def make_steps(root: Path, reference: Path, dest: Path, *,
               scan_only: bool, no_brawl: bool, use_deck_index: bool,
               translator: Callable[[Path], str]) -> list[tuple[str, list[str], str]]:
    """Pure command planner. stage title, argv, logfile name."""
    snapshot = dest / 'collection_snapshot.json'
    resolved = dest / 'resolved_collection_snapshot.json'
    scryfall = root / DEFAULT_SCRYFALL
    overrides = root / DEFAULT_OVERRIDES
    def windows(path: Path) -> str:
        return translator(path)
    steps = [
        ('Read MTGA memory (change-aware)',
         ['py.exe', '-3', windows(root / 'windows/extract_collection.py'),
          '--reference', windows(reference), '--output', windows(snapshot)],
         '01-extraction.log'),
        ('Audit collection snapshot',
         [sys.executable, str(root / 'windows/audit_collection_change_aware.py'),
          '--candidate', str(snapshot), '--reference', str(reference),
          '--scryfall', str(scryfall)],
         '02-collection-audit.log'),
    ]
    if not scan_only:
        resolve_cmd = [sys.executable, str(root / 'resolve_collection_cards.py'),
                       '--candidate', str(snapshot), '--scryfall', str(scryfall),
                       '--overrides', str(overrides), '--output', str(resolved)]
        if use_deck_index:
            resolve_cmd += ['--deck-index', str(root / DEFAULT_DECK_INDEX)]
        steps += [
            ('Resolve owned card identities', resolve_cmd, '03-resolution.log'),
            ('Audit resolved ownership',
             [sys.executable, str(root / 'audit_resolved_collection.py'),
              '--candidate', str(snapshot), '--overrides', str(overrides),
              '--resolved', str(resolved)], '04-resolution-audit.log'),
        ]
        if not no_brawl:
            steps.append(('Produce Brawl readiness report',
                          [sys.executable, str(root / 'audit_brawl_readiness.py'),
                           '--input', str(resolved),
                           '--report-json', str(dest / 'brawl_readiness.json'),
                           '--cards-csv', str(dest / 'brawl_cards.csv'),
                           '--commanders-csv', str(dest / 'brawl_commanders.csv')],
                          '05-brawl-audit.log'))
    return steps


def make_directory(parent: Path, clock: Callable[[], datetime] = datetime.now) -> Path:
    parent.mkdir(parents=True, exist_ok=True)
    stamp = clock().astimezone().strftime('%Y%m%d-%H%M%S')
    for number in range(1000):
        suffix = '' if number == 0 else f'-{number:03d}'
        run_dir = parent / (RUN_PREFIX + stamp + suffix)
        try:
            run_dir.mkdir(mode=0o750)
            return run_dir
        except FileExistsError:
            continue
    raise ControlError('Too many run directories for the current second')


def show_command(args: list[str]) -> str:
    import shlex
    return shlex.join(args)


def stream_step(title: str, argv: list[str], logfile: Path,
                popen: Callable = subprocess.Popen) -> None:
    print(f'\n=== {title} ===', flush=True)
    print(f'Log: {logfile}', flush=True)
    try:
        with logfile.open('x', encoding='utf-8') as log:
            with popen(argv, cwd=ROOT, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, text=True,
                       encoding='utf-8', errors='replace', bufsize=1) as process:
                if process.stdout is None:
                    raise ControlError(f'Unable to capture output: {title}')
                for line in process.stdout:
                    print(line, end='', flush=True)
                    log.write(line)
                    log.flush()
                code = process.wait()
                if code != 0:
                    raise ControlError(f'{title} FAILED (exit {code}). See {logfile}')
    except OSError as exc:
        raise ControlError(f'{title}: {exc}') from exc


def check_outputs(dest: Path, *, scan_only: bool, no_brawl: bool) -> None:
    needed = [dest / 'collection_snapshot.json']
    if not scan_only:
        needed.append(dest / 'resolved_collection_snapshot.json')
        if not no_brawl:
            needed += [dest / n for n in
                       ('brawl_readiness.json', 'brawl_cards.csv', 'brawl_commanders.csv')]
    fail_if_missing(needed)


def inspect_snapshot(dest: Path, scan_only: bool, no_brawl: bool) -> dict:
    snap = json.loads((dest / 'collection_snapshot.json').read_text(encoding='utf-8'))
    records = [r for run in snap['runs'] for r in run['records']]
    summary = {
        'status': 'candidate_unconfirmed',
        'collection_ids': len(records),
        'recorded_copies': sum(r['quantity'] for r in records),
        'reference_changes': {k: len(snap.get('reference_changes', {}).get(k, []))
                              for k in ('newly_owned', 'no_longer_present', 'quantity_changed')},
    }
    if not scan_only:
        resolved = json.loads((dest / 'resolved_collection_snapshot.json').read_text(encoding='utf-8'))
        counts = resolved['summary']
        if counts['owned_arena_ids'] != summary['collection_ids'] or counts['recorded_owned_copies'] != summary['recorded_copies']:
            raise ControlError('Resolved counts disagree with extracted snapshot')
        summary.update({'resolved_identities': counts['owned_arena_ids'] - counts['unresolved_arena_ids'],
                        'identity_only': counts['arena_db_verified_identity_only'],
                        'unresolved_identities': counts['unresolved_arena_ids']})
        if not no_brawl:
            brawl = json.loads((dest / 'brawl_readiness.json').read_text(encoding='utf-8'))
            if brawl['summary']['owned_arena_ids'] != summary['collection_ids']:
                raise ControlError('Brawl audit counts disagree with extracted snapshot')
            summary['commander_names_by_snapshot'] = brawl['summary']['unique_eligible_commander_names']
    return summary


def latest_successful(root: Path) -> Path | None:
    parent = root / RUNS_SUBDIR
    if not parent.is_dir():
        return None
    candidates = (p for p in parent.glob(RUN_PREFIX + '*')
                  if p.is_dir() and (p / 'run_summary.json').is_file())
    return max(candidates, key=lambda p: p.name, default=None)


def doctor(root: Path, reference: Path, scan_only: bool, no_brawl: bool) -> bool:
    required = required_paths(root, reference, scan_only, no_brawl)
    missing = [p for p in required if not p.is_file()]
    print('MTGA collection controller — environment check (no game access)')
    for name in ('py.exe', 'wslpath'):
        found = shutil.which(name)
        print(f'  {name}: {found or "NOT FOUND"}')
    print(f'  Root: {root}')
    print(f'  Baseline: {reference}')
    print(f'  Required files: {len(required) - len(missing)}/{len(required)} present')
    for path in missing:
        print(f'  MISSING: {path}')
    optional = root / DEFAULT_DECK_INDEX
    print(f'  Optional saved-deck index: {"available" if optional.is_file() else "absent (fine)"}')
    good = not missing and all(shutil.which(n) for n in ('py.exe', 'wslpath'))
    print('READY' if good else 'NOT READY')
    return good


def run(args: argparse.Namespace, *, root: Path = ROOT) -> Path | None:
    reference = args.reference
    reference = (root / reference).resolve() if not reference.is_absolute() else reference.resolve()
    if args.scan_only and args.no_brawl:
        raise ControlError('--no-brawl is redundant with --scan-only; choose one')
    if args.action == 'latest':
        latest = latest_successful(root)
        if latest is None:
            print('No completed controller run found.')
            return None
        print(f'Latest completed run: {latest}')
        resolved = latest / 'resolved_collection_snapshot.json'
        print(f'Upload to deck-building chat: {resolved if resolved.is_file() else "No resolved index (scan-only run)"}')
        print(f'Raw collection snapshot: {latest / "collection_snapshot.json"}')
        return latest
    if args.action == 'doctor':
        if not doctor(root, reference, args.scan_only, args.no_brawl):
            raise ControlError('Missing prerequisites; review the doctor report')
        return None
    fail_if_missing(required_paths(root, reference, args.scan_only, args.no_brawl))
    if not shutil.which('py.exe') or not shutil.which('wslpath'):
        raise ControlError('Requires WSL2 with py.exe and wslpath accessible. Try ./mtga doctor')
    if not sys.platform.startswith('linux'):
        raise ControlError('Run this controller from WSL Linux, not Windows Python')
    # Explicitly show the commands without creating any output directory.
    if args.dry_run:
        preview = root / RUNS_SUBDIR / (RUN_PREFIX + 'PREVIEW')
        steps = make_steps(root, reference, preview, scan_only=args.scan_only,
                           no_brawl=args.no_brawl,
                           use_deck_index=(root / DEFAULT_DECK_INDEX).is_file(),
                           translator=wsl_windows_path)
        print('DRY RUN: no files created and no Arena process accessed.')
        for title, command, logfile in steps:
            print(f'\n{title}:\n  {show_command(command)}\n  log: {logfile}')
        return None
    dest = make_directory(root / RUNS_SUBDIR)
    print('MTGA collection controller — read-only extraction')
    print(f'Run directory: {dest}', flush=True)
    print(f'Reference (never modified): {reference}', flush=True)
    steps = make_steps(root, reference, dest, scan_only=args.scan_only,
                       no_brawl=args.no_brawl,
                       use_deck_index=(root / DEFAULT_DECK_INDEX).is_file(),
                       translator=wsl_windows_path)
    try:
        for title, command, logfile in steps:
            stream_step(title, command, dest / logfile)
            # Stop immediately if a child falsely returns success but did not write output.
            if logfile == '01-extraction.log':
                fail_if_missing([dest / 'collection_snapshot.json'])
            if logfile == '03-resolution.log':
                fail_if_missing([dest / 'resolved_collection_snapshot.json'])
        check_outputs(dest, scan_only=args.scan_only, no_brawl=args.no_brawl)
        details = inspect_snapshot(dest, args.scan_only, args.no_brawl)
        manifest = {
            'workflow_status': 'all_requested_stages_passed',
            'candidate_status': 'candidate_unconfirmed',
            'source_reference': str(reference),
            'outputs': {'collection': 'collection_snapshot.json',
                        'resolved_collection': None if args.scan_only else 'resolved_collection_snapshot.json',
                        'brawl_readiness': None if args.scan_only or args.no_brawl else 'brawl_readiness.json'},
            'results': details,
            'caution': ('Memory dataset completeness and live Brawl legality are unproven. '
                        'This run never modifies Arena memory or production collection files.'),
        }
        with (dest / 'run_summary.json').open('x', encoding='utf-8') as fh:
            json.dump(manifest, fh, indent=2)
            fh.write('\n')
    except Exception:
        print(f'\nRun NOT marked complete; available diagnostic files: {dest}', file=sys.stderr)
        raise
    print('\n=== SUCCESS: all requested stages passed ===')
    print(f'  Arena IDs: {details["collection_ids"]:,}; copies: {details["recorded_copies"]:,}')
    changes = details['reference_changes']
    print(f'  Changes vs baseline: +{changes["newly_owned"]}, '
          f'-{changes["no_longer_present"]}, qty changed={changes["quantity_changed"]}')
    print(f'  Raw snapshot: {dest / "collection_snapshot.json"}')
    if not args.scan_only:
        print(f'  READY TO UPLOAD: {dest / "resolved_collection_snapshot.json"}')
    if not args.scan_only and not args.no_brawl:
        print(f'  Brawl audit: {dest / "brawl_readiness.json"}')
    print(f'  Run report: {dest / "run_summary.json"}')
    print('  Status: candidate_unconfirmed (completeness not proved).')
    return dest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description='One command to extract, audit, and resolve your MTG Arena collection from WSL2.')
    parser.add_argument('action', nargs='?', default='run', choices=('run', 'doctor', 'latest'),
                        help='run (default), doctor (check dependencies), latest (show last output)')
    parser.add_argument('--reference', type=Path, default=DEFAULT_REFERENCE,
                        help='Saved extraction comparison baseline; not modified')
    parser.add_argument('--scan-only', action='store_true',
                        help='Run memory capture + structural audit; do not resolve cards')
    parser.add_argument('--no-brawl', action='store_true',
                        help='Extract, audit and resolve cards, skipping Brawl review outputs')
    parser.add_argument('--dry-run', action='store_true',
                        help='Show the steps and paths without reading the game or writing files')
    args = parser.parse_args(argv)
    try:
        run(args)
        return 0
    except (ControlError, OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        print(f'ERROR: {error}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
