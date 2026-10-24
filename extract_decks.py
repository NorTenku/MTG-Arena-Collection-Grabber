
import json
from pathlib import Path

from inspect_log import find_log_directory


OUTPUT_DIR = Path("data")
OUTPUT_FILE = OUTPUT_DIR / "decks.json"


def find_deck_data(log_path: Path):
    """Find the most recent cached deck data in an Arena log."""
    latest = None

    with log_path.open(
        "r", encoding="utf-8", errors="replace"
    ) as file:
        for line in file:
            start = line.find("{")

            if start == -1:
                continue

            try:
                data = json.loads(line[start:])
            except json.JSONDecodeError:
                continue

            if not isinstance(data, dict):
                continue

            if isinstance(data.get("DecksInternal"), dict):
                latest = data

    return latest


def extract_decks(data):
    """Extract card lists without exporting account identifiers."""
    raw_decks = data.get("DecksInternal", {})
    decks = []

    for index, deck in enumerate(raw_decks.values(), start=1):
        if not isinstance(deck, dict):
            continue

        decks.append({
            "name": f"Cached Deck {index}",
            "main_deck": deck.get("MainDeck", []),
            "command_zone": deck.get("CommandZone", []),
            "sideboard": deck.get("Sideboard", []),
        })

    return decks


def main():
    log_dir = find_log_directory()

    if log_dir is None:
        print("MTG Arena log directory not found.")
        return

    log_path = log_dir / "Player.log"

    if not log_path.exists():
        print("Player.log not found.")
        return

    data = find_deck_data(log_path)

    if data is None:
        print("No cached deck data found.")
        return

    decks = extract_decks(data)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    with OUTPUT_FILE.open("w", encoding="utf-8") as file:
        json.dump(decks, file, indent=2)

    print(f"Extracted {len(decks)} cached decks.")
    print(f"Saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
