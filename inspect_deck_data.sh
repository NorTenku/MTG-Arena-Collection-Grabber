python3 - <<'PY'
import json

with open("data/decks.json", encoding="utf-8") as f:
    decks = json.load(f)

print(f"Total decks: {len(decks)}")

for deck in decks:
    print(
        f"{deck['name']}: "
        f"{len(deck['main_deck'])} main deck entries, "
        f"{len(deck['command_zone'])} commander entries"
    )
PY