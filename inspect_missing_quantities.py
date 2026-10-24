
import json
from collections import Counter
from pathlib import Path

with Path("data/decks.json").open(encoding="utf-8") as f:
    decks = json.load(f)

for deck_number, deck in enumerate(decks, start=1):
    cards = deck.get("main_deck", [])

    missing = [
        card for card in cards
        if isinstance(card, dict)
        and "cardId" in card
        and "quantity" not in card
    ]

    if not missing:
        continue

    ids = Counter(
        card["cardId"]
        for card in cards
        if isinstance(card, dict) and "cardId" in card
    )

    print(f"\nDeck {deck_number}")
    print(f"Entries missing quantity: {len(missing)}")

    for card in missing:
        card_id = card["cardId"]
        print(
            f"  Card ID {card_id}: "
            f"{ids[card_id]} occurrences in main deck"
        )
