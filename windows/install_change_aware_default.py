#!/usr/bin/env python3
"""Safely make the validated, change-aware extractor the default command.

Run this ONCE with WSL Python from the repository root, after placing this file
and extract_collection_mixed_change_aware.py in windows/. The existing legacy
extractor is copied to extract_collection_legacy.py, without overwriting it.
The resulting extract_collection.py is a small delegating wrapper: it provides
--reference automatically but retains all change-aware extractor options.

No MTGA process is accessed by this installer. It does not touch data/.
"""
from pathlib import Path
import argparse
import os
import stat
import tempfile

MARKER = '# MTGA_COLLECTION_CHANGE_AWARE_DEFAULT_V1'
WRAPPER = '''#!/usr/bin/env python3
# MTGA_COLLECTION_CHANGE_AWARE_DEFAULT_V1
"""Default read-only MTGA collection extractor.

Delegates to extract_collection_mixed_change_aware.py. Omitting --reference
uses the saved validated collection_candidate.json as the comparison baseline.
Omitting --output performs a read-only diagnostic (no JSON written).
Legacy CLI commands remain available via extract_collection_legacy.py.
"""
import sys
from pathlib import Path
from extract_collection_mixed_change_aware import main

if __name__ == '__main__':
    if '--reference' not in sys.argv[1:] and not any(
        argument.startswith('--reference=') for argument in sys.argv[1:]
    ):
        reference = Path(__file__).resolve().parent.parent / 'data' / 'collection_candidate.json'
        sys.argv.extend(['--reference', str(reference)])
    main()
'''


def install(windows: Path, dry_run: bool = False) -> str:
    windows = windows.resolve()
    destination = windows / 'extract_collection.py'
    backup = windows / 'extract_collection_legacy.py'
    deps = [
        windows / 'extract_collection_mixed_change_aware.py',
        windows / 'inspect_mixed_collection.py',
        windows / 'search_card_memory.py',
        windows / 'find_arena.py',
        windows.parent / 'data' / 'collection_candidate.json',
    ]
    missing = [str(p) for p in deps if not p.is_file()]
    if missing:
        raise RuntimeError('Missing required files:\n  ' + '\n  '.join(missing))
    if not destination.is_file():
        raise RuntimeError(f'Original extractor not found: {destination}')
    existing = destination.read_text(encoding='utf-8')
    if MARKER in existing:
        if backup.is_file():
            return f'ALREADY INSTALLED: {destination}\nLegacy preserved at: {backup}'
        raise RuntimeError('Default wrapper exists but legacy backup is missing. Investigate manually.')
    if backup.exists():
        raise RuntimeError(f'Refusing to overwrite pre-existing backup: {backup}. Check before installing.')
    if dry_run:
        return f'DRY RUN OK: would preserve {destination.name} as {backup.name} and install wrapper.'
    # Exclusive-create prevents accidental replacement of any pre-existing backup.
    old_bytes = destination.read_bytes()
    descriptor = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, destination.stat().st_mode & 0o777)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(old_bytes)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        # Do not install if backup could not be saved.
        raise
    fd, staged_name = tempfile.mkstemp(prefix='.extract_collection.', suffix='.tmp', dir=windows)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as stream:
            stream.write(WRAPPER)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(staged_name, destination.stat().st_mode & 0o777)
        os.replace(staged_name, destination)
    finally:
        if os.path.exists(staged_name):
            os.unlink(staged_name)
    return (f'INSTALLED: {destination}\n'
            f'Preserved legacy extractor: {backup}\n'
            'Default uses data/collection_candidate.json if --reference is omitted.\n'
            'No collection JSON or Arena memory was altered.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--windows-dir', type=Path, default=Path(__file__).resolve().parent,
                        help='Location of windows/ directory (default: alongside installer)')
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args()
    try:
        print(install(args.windows_dir, args.dry_run))
    except (OSError, RuntimeError) as exc:
        parser.exit(2, f'INSTALL ABORTED: {exc}\n')


if __name__ == '__main__':
    main()
