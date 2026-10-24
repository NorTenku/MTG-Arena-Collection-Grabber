
import json
from pathlib import Path


DATA_FILE = Path("data/decks.json")


def describe(value):
    """Return field names and types without exposing values."""
    if isinstance(value, dict):
        return {
            key: type(child).__name__
            for key, child in value.items()
        }

    if isinstance(value, list):
        return {
            "type": "list",
            "length": len(value),
            "element_types": sorted({
                type(item).__name__
                for item in value
            }),
        }

    return type(value).__name__


def main():
    with DATA_FILE.open(encoding="utf-8") as file:
        decks = json.load(file)

    print(f"Loaded {len(decks)} decks")

    for section in ("main_deck", "command_zone", "sideboard"):
        for deck in decks:
            entries = deck.get(section, [])

            if entries:
                print(f"\nSection: {section}")
                print(f"Deck: {deck['name']}")
                print("Entry structure:")
                print(json.dumps(
                    describe(entries[0]),
                    indent=2
                ))
                break


if __name__ == "__main__":
    main()
