
#!/usr/bin/env python3

import argparse
import gzip
import json
from collections import Counter, defaultdict
from pathlib import Path


def load_collection(path):
    with path.open(encoding="utf-8") as file:
        return json.load(file)


def load_scryfall_index(path, wanted_ids):
    """Read the compressed Scryfall JSONL cache incrementally."""
    index = {}

    with gzip.open(path, "rt", encoding="utf-8") as file:
        for line in file:
            if not line.strip():
                continue

            card = json.loads(line)
            arena_id = card.get("arena_id")

            if arena_id is not None:
                arena_id = int(arena_id)

                if arena_id in wanted_ids:
                    index[arena_id] = {
                        "name": card.get("name"),
                        "set": card.get("set"),
                        "rarity": card.get("rarity"),
                        "type_line": card.get("type_line"),
                    }

    return index


def audit_collection(snapshot):
    quantities = defaultdict(set)
    occurrences = Counter()
    issues = []
    records = []

    for index, run in enumerate(snapshot["runs"]):
        run_records = run["records"]

        if run.get("record_count") != len(run_records):
            issues.append(
                f"Run {index}: record_count does not match"
            )

        for record in run_records:
            card_id = int(record["card_id"])
            quantity = int(record["quantity"])

            quantities[card_id].add(quantity)
            occurrences[card_id] += 1
            records.append((card_id, quantity))

            if card_id <= 0 or not 1 <= quantity <= 4:
                issues.append(
                    f"Invalid record: {card_id} x{quantity}"
                )

    conflicts = {
        card_id: sorted(values)
        for card_id, values in quantities.items()
        if len(values) > 1
    }

    duplicates = {
        card_id: count
        for card_id, count in occurrences.items()
        if count > 1
    }

    distribution = Counter(
        next(iter(values))
        for values in quantities.values()
        if len(values) == 1
    )

    return {
        "unique_ids": len(quantities),
        "total_records": len(records),
        "run_count": len(snapshot["runs"]),
        "quantity_distribution": dict(sorted(distribution.items())),
        "total_copies": sum(
            quantity * count
            for quantity, count in distribution.items()
        ),
        "conflicts": conflicts,
        "duplicates": duplicates,
        "issues": issues,
        "quantities": quantities,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Audit a provisional MTG Arena collection."
    )

    parser.add_argument(
        "--collection",
        type=Path,
        default=Path("data/collection.json"),
    )
    parser.add_argument(
        "--scryfall",
        type=Path,
        default=Path("data/scryfall_default_cards.jsonl.gz"),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data/collection_audit.json"),
    )

    args = parser.parse_args()

    snapshot = load_collection(args.collection)
    audit = audit_collection(snapshot)

    print("MTG Arena Collection Audit")
    print("=" * 45)
    print(f"Snapshot status: {snapshot.get('status', 'unknown')}")
    print(f"Unique IDs: {audit['unique_ids']:,}")
    print(f"Total records: {audit['total_records']:,}")
    print(f"Contiguous runs: {audit['run_count']:,}")
    print(f"Total copies: {audit['total_copies']:,}")
    print(f"Duplicate IDs: {len(audit['duplicates']):,}")
    print(f"Quantity conflicts: {len(audit['conflicts']):,}")
    print(f"Structural issues: {len(audit['issues']):,}")

    print("\nQuantity distribution:")
    for quantity, count in audit["quantity_distribution"].items():
        print(f"  x{quantity}: {count:,} IDs")

    print("\nResolving against Scryfall...")

    scryfall = load_scryfall_index(
        args.scryfall,
        set(audit["quantities"]),
    )

    resolved_ids = set(scryfall)
    all_ids = set(audit["quantities"])
    unresolved_ids = sorted(all_ids - resolved_ids)

    percentage = (
        100 * len(resolved_ids) / len(all_ids)
        if all_ids else 0
    )

    print(f"Resolved: {len(resolved_ids):,}")
    print(f"Unresolved: {len(unresolved_ids):,}")
    print(f"Resolution rate: {percentage:.2f}%")

    print("\nUnresolved IDs (first 30):")
    print(unresolved_ids[:30])

    report = {
        "source": str(args.collection),
        "snapshot_status": snapshot.get("status"),
        "unique_ids": audit["unique_ids"],
        "total_records": audit["total_records"],
        "run_count": audit["run_count"],
        "total_copies": audit["total_copies"],
        "quantity_distribution": audit["quantity_distribution"],
        "duplicate_ids": audit["duplicates"],
        "quantity_conflicts": audit["conflicts"],
        "structural_issues": audit["issues"],
        "scryfall_resolved_count": len(resolved_ids),
        "scryfall_unresolved_count": len(unresolved_ids),
        "scryfall_resolution_percent": round(percentage, 2),
        "unresolved_ids": unresolved_ids,
    }

    args.output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with args.output.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=2)

    print(f"\nSaved audit: {args.output}")


if __name__ == "__main__":
    main()
