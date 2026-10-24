
import gzip
import json
from pathlib import Path

DATABASE = Path("data/scryfall_default_cards.jsonl.gz")

REFERENCE_CARDS = {
    "Charmed Stray": 4,
    "Fleeting Flight": 1,
    "Healer's Hawk": 2,
}


def main():
    if not DATABASE.exists():
        raise SystemExit(f"Database not found: {DATABASE}")

    matches = {name: [] for name in REFERENCE_CARDS}

    with gzip.open(DATABASE, "rt", encoding="utf-8") as file:
        for line in file:
            if not line.strip():
                continue

            card = json.loads(line)
            name = card.get("name")
            arena_id = card.get("arena_id")

            if name not in matches or arena_id is None:
                continue

            matches[name].append({
                "arena_id": arena_id,
                "set": card.get("set"),
                "collector_number": card.get("collector_number"),
            })

    for name, quantity in REFERENCE_CARDS.items():
        print(f"\n{name} — owned quantity: {quantity}")

        if not matches[name]:
            print("  No Arena IDs found in Scryfall database.")
            continue

        for card in sorted(
            matches[name],
            key=lambda item: item["arena_id"],
        ):
            print(
                f"  Arena ID: {card['arena_id']} "
                f"| Set: {card['set']} "
                f"| Number: {card['collector_number']}"
            )


if __name__ == "__main__":
    main()
