
import json
from collections import Counter
from pathlib import Path


EXPORT = Path("data/collection_prototype.json")


def main():
    with EXPORT.open(encoding="utf-8") as file:
        data = json.load(file)

    runs = data["runs"]

    print(f"Status: {data['status']}")
    print(f"Runs: {len(runs):,}")

    lengths = sorted(
        (run["record_count"] for run in runs),
        reverse=True,
    )

    print("Largest runs:", lengths[:10])

    candidates = {}

    for run in runs:
        for record in run["records"]:
            card_id = str(record["card_id"])
            quantity = record["quantity"]

            candidates.setdefault(card_id, set()).add(quantity)

    conflicts = {
        card_id: quantities
        for card_id, quantities in candidates.items()
        if len(quantities) > 1
    }

    print(f"Unique candidate IDs: {len(candidates):,}")
    print(f"Conflicting quantities: {len(conflicts):,}")

    distribution = Counter()

    for quantities in candidates.values():
        if len(quantities) == 1:
            distribution[next(iter(quantities))] += 1

    print("Quantity distribution:")

    for quantity, count in sorted(distribution.items()):
        print(f"  {quantity} copies: {count:,} cards")


if __name__ == "__main__":
    main()
