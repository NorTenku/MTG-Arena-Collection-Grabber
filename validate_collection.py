
import gzip
import json
from collections import Counter
from pathlib import Path


COLLECTION_PATH = Path("data/collection_prototype.json")
SCRYFALL_PATH = Path("data/scryfall_default_cards.jsonl.gz")


def main():
    with COLLECTION_PATH.open(encoding="utf-8") as file:
        collection = json.load(file)

    extracted = {}

    for run in collection["runs"]:
        for record in run["records"]:
            card_id = record["card_id"]
            quantity = record["quantity"]

            extracted.setdefault(card_id, set()).add(quantity)

    print(f"Extracted IDs: {len(extracted):,}")

    resolved = {}

    with gzip.open(
        SCRYFALL_PATH,
        "rt",
        encoding="utf-8",
    ) as file:
        for line in file:
            card = json.loads(line)
            arena_id = card.get("arena_id")

            if arena_id in extracted:
                resolved[arena_id] = {
                    "name": card["name"],
                    "set": card["set"],
                    "collector_number": card["collector_number"],
                }

    unresolved = sorted(set(extracted) - set(resolved))

    print(f"Resolved IDs: {len(resolved):,}")
    print(f"Unresolved IDs: {len(unresolved):,}")

    if extracted:
        percentage = len(resolved) / len(extracted) * 100
        print(f"Resolution rate: {percentage:.2f}%")

    print("\nSample resolved cards:")

    for card_id in list(sorted(resolved))[:20]:
        card = resolved[card_id]
        quantities = sorted(extracted[card_id])

        print(
            f"  {card_id}: {card['name']} "
            f"({card['set']}) x{quantities}"
        )

    print("\nUnresolved Arena IDs:")
    print(unresolved[:50])

    sets = Counter(
        card["set"]
        for card in resolved.values()
    )

    print("\nTop sets:")

    for set_code, count in sets.most_common(15):
        print(f"  {set_code}: {count}")


if __name__ == "__main__":
    main()
