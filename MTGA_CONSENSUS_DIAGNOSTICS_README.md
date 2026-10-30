# MTG Arena collection — diagnosing conflicting physical copies

**Problem observed 2026-10-30:** `./mtga` found two 1,938-record collections, each
passing reference validation, but rejected them because the complete ordered
`(card_id, field_a, quantity)` signatures differ. The third anchor points into
an already-seen contiguous sequence, not a third independent copy.

The existing validator deliberately requires two physically separate, strictly
identical record sequences. This package does **not** relax the requirement or
make an unconfirmed candidate available for downstream resolution.

## Install in WSL project root

Copy `install_consensus_diagnostics.py` alongside `mtga` in your project root.

```bash
cd ~/projects/mtga-collection-grabber
python3 install_consensus_diagnostics.py --self-test
python3 install_consensus_diagnostics.py --dry-run
python3 install_consensus_diagnostics.py
```

The installer only edits `windows/extract_collection_mixed_change_aware.py`.
It creates an **exclusive** backup next to the script named
`extract_collection_mixed_change_aware.py.pre_consensus_diagnostics.bak`.
It checks the expected source layout and Python syntax before installing,
refuses to overwrite a prior backup, and does not touch any collection data.
If it reports that the source layout differs, **do not force the patch**;
share that message and the updated source file.

## Reproduce

Run Arena on the Collection screen and then:

```bash
./mtga
```

If strict consensus fails again, the extraction log will now include:

```
CONSENSUS DIAGNOSTICS (read-only; no snapshot accepted):
  Copy 1: ...
  Copy 2: ...
  Compare copies 1 and 2:
    ID-only-A=..., ID-only-B=..., quantity disagreements=...
    Field A disagreements=..., format disagreements=..., row position disagreements=...
    Identical ownership ID/quantity mapping: YES/NO
    Sample ...
```

Please share the **CONSENSUS DIAGNOSTICS** section and the final error. The
field values are Arena IDs, counts, and offsets, not raw process memory.

- **YES** for identical ownership means card IDs and quantities agree despite
  differences in other fields, and we can then investigate a narrowly defined
  alternative validation method rather than blindly weakening all checks.
- **NO** means the two physical copies disagree about owned card quantities
  or ID membership, and neither can be treated as independently validated.

**Important:** 96.4% quantity agreement in the original logs is the agreement
of *each* run with the October 2026 baseline; it is **not** a comparison of
the two physical copies against each other. The diagnostics fix this blind spot.

## Revert

```bash
cp windows/extract_collection_mixed_change_aware.py.pre_consensus_diagnostics.bak \
   windows/extract_collection_mixed_change_aware.py
```

The `./mtga` controller and all downstream scripts are unchanged. Previous
successful snapshots are unaffected. A failed live extraction never gets a
`run_summary.json` and should not replace `./mtga latest`.
