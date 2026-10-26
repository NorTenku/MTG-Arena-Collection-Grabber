#!/usr/bin/env python3
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
