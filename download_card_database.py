
import gzip
import json
import shutil
import tempfile
from pathlib import Path

import requests


DATA_DIR = Path("data")

INDEX_FILE = DATA_DIR / "card_index.json"
CACHE_FILE = DATA_DIR / "scryfall_default_cards.jsonl.gz"
OUTPUT_FILE = DATA_DIR / "resolved_cards.json"

BULK_API = "https://api.scryfall.com/bulk-data/default-cards"

HEADERS = {
    "User-Agent": "MTGACollectionGrabber/0.1",
    "Accept": "application/json",
}


def load_card_index():
    with INDEX_FILE.open(encoding="utf-8") as file:
        return json.load(file)


def download_database():
    if CACHE_FILE.exists():
        print(f"Using cached database: {CACHE_FILE}")
        return

    print("Retrieving Scryfall bulk metadata...")

    response = requests.get(
        BULK_API,
        headers=HEADERS,
        timeout=30,
    )
    response.raise_for_status()

    metadata = response.json()

    download_url = metadata.get("jsonl_download_uri")

    if not download_url:
        raise RuntimeError(
            "Scryfall did not provide jsonl_download_uri"
        )

    print(f"Database updated: {metadata.get('updated_at')}")
    print(
        f"Compressed size: "
        f"{metadata.get('compressed_size', 0):,} bytes"
    )

    print("Downloading compressed database...")

    DATA_DIR.mkdir(parents=True, exist_ok=True)

    with tempfile.NamedTemporaryFile(
        mode="wb",
        dir=DATA_DIR,
        suffix=".tmp",
        delete=False,
    ) as temporary:
        temporary_path = Path(temporary.name)

    try:
        with requests.get(
            download_url,
            headers=HEADERS,
            stream=True,
            timeout=(15, 120),
        ) as response:
            response.raise_for_status()

            with temporary_path.open("wb") as output:
                for chunk in response.iter_content(
                    chunk_size=1024 * 1024
                ):
                    if chunk:
                        output.write(chunk)

        temporary_path.replace(CACHE_FILE)

    finally:
        temporary_path.unlink(missing_ok=True)

    print(f"Database cached: {CACHE_FILE}")


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


def resolve_cards(card_index):
    wanted_ids = set(card_index)
    resolved = {}

    print("Scanning Scryfall database...")

    records_scanned = 0

    with gzip.open(
        CACHE_FILE,
        mode="rt",
        encoding="utf-8",
    ) as file:
        for line in file:
            if not line.strip():
                continue

            records_scanned += 1
            card = json.loads(line)

            arena_id = card.get("arena_id")

            if arena_id is None:
                continue

            arena_id = str(arena_id)

            if arena_id not in wanted_ids:
                continue

            resolved[arena_id] = {
                **simplify_card(card),
                "deck_usage": card_index[arena_id],
            }

    unresolved = sorted(
        wanted_ids - set(resolved),
        key=int,
    )

    print(f"Records scanned: {records_scanned:,}")

    return {
        "cards": resolved,
        "unresolved_ids": unresolved,
    }


def main():
    card_index = load_card_index()

    print(f"Arena IDs to resolve: {len(card_index):,}")

    download_database()

    results = resolve_cards(card_index)

    with OUTPUT_FILE.open("w", encoding="utf-8") as file:
        json.dump(results, file, indent=2)

    print("\nResolution complete")
    print(f"Resolved: {len(results['cards']):,}")
    print(f"Unresolved: {len(results['unresolved_ids']):,}")
    print(f"Saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
