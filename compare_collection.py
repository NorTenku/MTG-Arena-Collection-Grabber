
import json
from pathlib import Path


COLLECTION_PATH = Path("data/collection_prototype.json")
DECK_INDEX_PATH = Path("data/card_index.json")


def main():
    with COLLECTION_PATH.open(encoding="utf-8") as file:
        collection = json.load(file)

    with DECK_INDEX_PATH.open(encoding="utf-8") as file:
        deck_index = json.load(file)

    collection_ids = {
        str(record["card_id"])
        for run in collection["runs"]
        for record in run["records"]
    }

    if isinstance(deck_index, dict):
        deck_ids = set(deck_index.keys())
    elif isinstance(deck_index, list):
        deck_ids = {
            str(item["arena_id"])
            for item in deck_index
            if isinstance(item, dict) and "arena_id" in item
        }
    else:
        raise ValueError("Unexpected card_index.json format")

    overlap = collection_ids & deck_ids

    print(f"Collection candidates: {len(collection_ids):,}")
    print(f"Saved-deck IDs: {len(deck_ids):,}")
    print(f"Overlap: {len(overlap):,}")

    print(
        "Candidate IDs absent from saved decks:",
        f"{len(collection_ids - deck_ids):,}",
    )

    print(
        "Saved-deck IDs absent from candidate collection:",
        f"{len(deck_ids - collection_ids):,}",
    )

    if deck_ids:
        print(
            "Saved-deck ID coverage:",
            f"{len(overlap) / len(deck_ids) * 100:.2f}%",
        )


if __name__ == "__main__":
    main()
