
import json
from pathlib import Path

import requests

INDEX_FILE = Path("data/card_index.json")


def main():
    with INDEX_FILE.open(encoding="utf-8") as file:
        card_index = json.load(file)

    arena_id = int(next(iter(card_index)))

    url = f"https://api.scryfall.com/cards/arena/{arena_id}"

    print(f"Testing Arena ID: {arena_id}")

    response = requests.get(
        url,
        headers={
            "User-Agent": "MTGACollectionGrabber/0.1",
            "Accept": "application/json",
        },
        timeout=30,
    )

    print(f"HTTP status: {response.status_code}")

    data = response.json()

    if response.ok:
        print(json.dumps({
            "arena_id": data.get("arena_id"),
            "name": data.get("name"),
            "set": data.get("set"),
            "type_line": data.get("type_line"),
            "color_identity": data.get("color_identity"),
        }, indent=2))
    else:
        print(json.dumps({
            "code": data.get("code"),
            "details": data.get("details"),
        }, indent=2))


if __name__ == "__main__":
    main()
