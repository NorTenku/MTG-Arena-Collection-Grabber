
import json
from collections import defaultdict
from pathlib import Path

INPUT_FILE = Path("data/decks.json")
OUTPUT_FILE = Path("data/card_index.json")


def build_index(decks):
    index = defaultdict(lambda: {
        "deck_count": 0,
        "max_quantity": 0,
        "commander_count": 0,
        "sections": set(),
        "missing_quantity_entries": 0,
    })

    for deck in decks:
        seen_in_deck = set()

        for section in (
            "main_deck",
            "command_zone",
            "sideboard",
        ):
            for card in deck.get(section, []):
                if not isinstance(card, dict):
                    continue

                card_id = card.get("cardId")

                if type(card_id) is not int:
                    continue

                entry = index[card_id]
                entry["sections"].add(section)
                seen_in_deck.add(card_id)

                if section == "command_zone":
                    entry["commander_count"] += 1

                quantity = card.get("quantity")

                if type(quantity) is int and quantity > 0:
                    entry["max_quantity"] = max(
                        entry["max_quantity"],
                        quantity,
                    )
                else:
                    entry["missing_quantity_entries"] += 1

        for card_id in seen_in_deck:
            index[card_id]["deck_count"] += 1

    return {
        str(card_id): {
            **details,
            "sections": sorted(details["sections"]),
        }
        for card_id, details in sorted(index.items())
    }


def main():
    with INPUT_FILE.open(encoding="utf-8") as file:
        decks = json.load(file)

    index = build_index(decks)

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with OUTPUT_FILE.open("w", encoding="utf-8") as file:
        json.dump(index, file, indent=2)

    print(f"Decks processed: {len(decks)}")
    print(f"Unique card IDs: {len(index)}")
    print(
        "Unique commander IDs:",
        sum(
            1 for card in index.values()
            if card["commander_count"] > 0
        ),
    )
    print(f"Saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
