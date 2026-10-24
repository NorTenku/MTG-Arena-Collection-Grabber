
import json
from pathlib import Path


INDEX_FILE = Path("data/card_index.json")
DATABASE_FILE = Path("data/scryfall_default_cards.json")
OUTPUT_FILE = Path("data/resolved_cards.json")


def simplify_card(card):
    return {
        "arena_id": card.get("arena_id"),
        "name": card.get("name"),
        "mana_cost": card.get("mana_cost"),
        "mana_value": card.get("cmc"),
        "type_line": card.get("type_line"),
        "colors": card.get("colors", []),
        "color_identity": card.get("color_identity", []),
        "rarity": card.get("rarity"),
        "set": card.get("set"),
        "collector_number": card.get("collector_number"),
        "oracle_text": card.get("oracle_text"),
        "legalities": card.get("legalities", {}),
        "scryfall_uri": card.get("scryfall_uri"),
        "card_faces": card.get("card_faces", []),
    }


def main():
    print("Loading Arena card index...")

    with INDEX_FILE.open(encoding="utf-8") as file:
        card_index = json.load(file)

    print(f"Arena IDs to resolve: {len(card_index):,}")
    print("Loading Scryfall database...")

    with DATABASE_FILE.open(encoding="utf-8") as file:
        cards = json.load(file)

    print(f"Scryfall records: {len(cards):,}")

    arena_lookup = {}

    for card in cards:
        arena_id = card.get("arena_id")

        if arena_id is not None:
            arena_lookup[str(arena_id)] = card

    print(f"Indexed Arena IDs: {len(arena_lookup):,}")

    resolved = {}
    unresolved = []

    for arena_id, deck_info in card_index.items():
        card = arena_lookup.get(arena_id)

        if card is None:
            unresolved.append(arena_id)
            continue

        resolved[arena_id] = {
            **simplify_card(card),
            "deck_usage": deck_info,
        }

    output = {
        "cards": resolved,
        "unresolved_ids": sorted(
            unresolved,
            key=int,
        ),
    }

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with OUTPUT_FILE.open("w", encoding="utf-8") as file:
        json.dump(output, file, indent=2)

    print("\nResolution complete")
    print(f"Resolved: {len(resolved):,}")
    print(f"Unresolved: {len(unresolved):,}")
    print(f"Saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
