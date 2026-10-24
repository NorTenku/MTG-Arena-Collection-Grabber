
import argparse
import json
from pathlib import Path


def load_snapshot(path):
    with path.open(encoding="utf-8") as file:
        data = json.load(file)

    if data.get("status") != "provisional":
        raise ValueError(
            f"Unexpected snapshot status in {path}"
        )

    cards = {}

    for run in data["runs"]:
        for record in run["records"]:
            card_id = int(record["card_id"])
            quantity = int(record["quantity"])

            cards.setdefault(card_id, set()).add(quantity)

    return data, cards


def compare_snapshots(first, second):
    first_ids = set(first)
    second_ids = set(second)

    shared = first_ids & second_ids
    removed = first_ids - second_ids
    added = second_ids - first_ids

    quantity_changes = {
        card_id: (
            sorted(first[card_id]),
            sorted(second[card_id]),
        )
        for card_id in shared
        if first[card_id] != second[card_id]
    }

    return shared, removed, added, quantity_changes


def main():
    parser = argparse.ArgumentParser(
        description="Compare two MTG Arena collection snapshots."
    )

    parser.add_argument(
        "first",
        type=Path,
        help="Earlier collection snapshot",
    )

    parser.add_argument(
        "second",
        type=Path,
        help="Later collection snapshot",
    )

    args = parser.parse_args()

    first_data, first_cards = load_snapshot(args.first)
    second_data, second_cards = load_snapshot(args.second)

    shared, removed, added, changes = compare_snapshots(
        first_cards,
        second_cards,
    )

    first_conflicts = {
        card_id: quantities
        for card_id, quantities in first_cards.items()
        if len(quantities) > 1
    }

    second_conflicts = {
        card_id: quantities
        for card_id, quantities in second_cards.items()
        if len(quantities) > 1
    }

    print("MTG Arena Snapshot Comparison")
    print("=" * 40)

    print(f"First snapshot:  {args.first}")
    print(f"Second snapshot: {args.second}")

    print(
        f"\nFirst extracted at: "
        f"{first_data.get('extracted_at', 'unknown')}"
    )
    print(
        f"Second extracted at: "
        f"{second_data.get('extracted_at', 'unknown')}"
    )

    print(f"\nFirst unique IDs:  {len(first_cards):,}")
    print(f"Second unique IDs: {len(second_cards):,}")

    print(f"\nShared IDs:       {len(shared):,}")
    print(f"Missing in second: {len(removed):,}")
    print(f"New in second:     {len(added):,}")
    print(f"Quantity changes:  {len(changes):,}")

    print(
        f"\nFirst quantity conflicts: "
        f"{len(first_conflicts):,}"
    )
    print(
        f"Second quantity conflicts: "
        f"{len(second_conflicts):,}"
    )

    print("\nIDs missing in second snapshot:")
    print(sorted(removed)[:50])

    print("\nIDs new in second snapshot:")
    print(sorted(added)[:50])

    print("\nQuantity changes:")

    for card_id, (old, new) in sorted(changes.items())[:50]:
        print(f"  {card_id}: {old} -> {new}")

    if not changes:
        print("  None")


if __name__ == "__main__":
    main()
