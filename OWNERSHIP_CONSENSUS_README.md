# MTGA Collection Grabber: ownership-based two-copy consensus

## What happened (30 October 2026)

The new Arena collection scan found two complete, structurally valid memory
sequences, each with **1,938 IDs**. The diagnostic showed:

- **0** IDs missing between copies
- **0** owned-quantity disagreements
- **0** changes of record position
- **844** different auxiliary `field_a` values
- **722** record-format labels differing (a classification derived from `field_a`)

The original validator compared each ordered `(card_id, field_a, quantity)`
triple. That made it reject two copies that **agreed on every ownership-bearing
field**. The 96.4% comparison shown in earlier logs was each copy's agreement
with the *old* baseline, not agreement of one copy with the other.

This patch changes the consensus key to **ordered `(card_id, quantity)` pairs**.
It does NOT accept a single copy, change the structural/reference validators,
permit different card quantities or IDs, or permit different ordering. It retains
the original `field_a` values and format labels from the first selected copy,
but marks those auxiliary values as **not cross-copy corroborated** when they
differ. The existing record SHA-256 is unchanged, so existing offline auditors
can independently verify the chosen primary copy's output.

This is still a `candidate_unconfirmed` snapshot and not proof of exhaustive
collection capture or current Arena format legality.

## Installation

Unzip `install_ownership_consensus.py` into the **repository root** (alongside
`mtga`). From WSL:

```bash
cd ~/projects/mtga-collection-grabber
python3 install_ownership_consensus.py --self-test
python3 install_ownership_consensus.py --dry-run
python3 install_ownership_consensus.py
```

The installer checks that the extractor source matches the expected source
layout, including the previously installed diagnostics patch, and refuses to
proceed if it does not. It creates a NEW backup, without replacing the
existing diagnostics backup:

`windows/extract_collection_mixed_change_aware.py.pre_ownership_consensus.bak`

Then run the extractor's original offline regressions:

```bash
python3 windows/extract_collection.py --self-test
```

With Arena running on its Collection screen, try the normal one-command flow:

```bash
./mtga
./mtga latest
```

You should see lines such as:

```
PASS: exactly one validated dataset found
  Ownership-agreeing physical copies: 2
  Ordered ID/quantity consensus: YES (...)
  Auxiliary metadata: field_a disagrees on ... IDs; format disagrees on ... IDs
  NOTE: exported field_a/format come from one physical copy; their values are NOT cross-copy verified
```

The controller continues through the existing independent auditors and
resolver. New Arena IDs can still lack Scryfall or verified local Arena
identity metadata; this is a separate, visible resolution issue. All outputs
still go to a NEW timestamped snapshot folder. `./mtga latest` continues to
refer only to successful completed runs.

## Reverting this change

If it behaves unexpectedly, restore **only** the backup made immediately before
this patch:

```bash
cp windows/extract_collection_mixed_change_aware.py.pre_ownership_consensus.bak \
   windows/extract_collection_mixed_change_aware.py
```

The original strict consensus + diagnostic messages return. No data files need
restoring.

## Safety and limitations

- Process-memory inspection remains **read-only**; game files are untouched.
- No previous collection or reference file is replaced.
- At least two physically separate complete memory sequences must pass all
  previous structural and reference screening and match on ordered IDs and
  quantities.
- The copies may be correlated, so agreement cannot certify completeness.
- Exact semantics of `field_a` have not been established. Preserve these values
  for research, but never use differences in them as an ownership change.
- If the scan finds only one full copy, rejects reference similarity, or finds
  conflicting quantities/IDs, it will still fail closed.
- The installer intentionally edits one Python script, not the controller or
  the original baseline. Commit tested source changes separately from any
  personal collection snapshots.
