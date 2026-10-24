
import json
import time
from pathlib import Path

import requests


INPUT_FILE = Path("data/card_index.json")
OUTPUT_FILE = Path("data/resolved_cards.json")

SCRYFALL_URL = "https://api.scryfall.com/cards/collection"

BATCH_SIZE = 75
REQUEST_DELAY = 0.15


def load_card_ids():
    with INPUT_FILE.open(encoding="utf-8") as file:
        index = json.load(file)

    return list(index.keys())


def fetch_cards(session, card_ids):
    identifiers = [
        {"arena_id": int(card_id)}
        for card_id in card_ids
    ]

    response = session.post(
        SCRYFALL_URL,
        json={"identifiers": identifiers},
        timeout=30,
    )

    response.raise_for_status()
    return response.json()


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
    }


def main():
    card_ids = load_card_ids()
    resolved = {}
    unresolved = set()

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with requests.Session() as session:
        session.headers.update({
            "User-Agent": "MTGACollectionGrabber/0.1",
            "Accept": "application/json",
        })

        for offset in range(0, len(card_ids), BATCH_SIZE):
            batch = card_ids[offset:offset + BATCH_SIZE]

            try:
                data = fetch_cards(session, batch)
                except requests.HTTPError as error:
                    response = error.response
                    status = response.status_code if response is not None else None

                    print(f"HTTP error at batch {offset}: {status}")

                    if status == 429:
                        print("Rate limited. Stopping requests.")
                    elif status == 400:
                        print("Bad request. Check request format.")
                    else:
                        print(f"Unexpected HTTP error: {error}")

                    break

                except requests.RequestException as error:
                    print(f"Network error at batch {offset}: {error}")
                break

            for card in data.get("data", []):
                arena_id = card.get("arena_id")

                if arena_id is not None:
                    resolved[str(arena_id)] = simplify_card(card)

            for item in data.get("not_found", []):
                arena_id = item.get("arena_id")

                if arena_id is not None:
                    unresolved.add(str(arena_id))

            print(
                f"Processed {min(offset + BATCH_SIZE, len(card_ids))}"
                f"/{len(card_ids)} IDs"
            )

            time.sleep(REQUEST_DELAY)

    unresolved.update(set(card_ids) - set(resolved))

    output = {
        "cards": resolved,
        "unresolved_ids": sorted(unresolved, key=int),
    }

    with OUTPUT_FILE.open("w", encoding="utf-8") as file:
        json.dump(output, file, indent=2)

    print("\nResolution complete")
    print(f"Resolved: {len(resolved)}")
    print(f"Unresolved: {len(unresolved)}")
    print(f"Saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
