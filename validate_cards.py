
import json
from collections import Counter
from pathlib import Path

INPUT_FILE = Path("data/decks.json")


def main():
    with INPUT_FILE.open(encoding="utf-8") as file:
        decks = json.load(file)

    issues = Counter()
    examples = []
    total_entries = 0

    for deck_index, deck in enumerate(decks, start=1):
        for section in (
            "main_deck",
            "command_zone",
            "sideboard",
        ):
            for entry_index, card in enumerate(
                deck.get(section, []),
                start=1,
            ):
                total_entries += 1

                if not isinstance(card, dict):
                    issue = "not_a_dictionary"
                elif "cardId" not in card:
                    issue = "missing_card_id"
                elif "quantity" not in card:
                    issue = "missing_quantity"
                else:
                    continue

                issues[issue] += 1

                if len(examples) < 10:
                    examples.append({
                        "deck": deck_index,
                        "section": section,
                        "entry": entry_index,
                        "issue": issue,
                        "keys": (
                            sorted(card.keys())
                            if isinstance(card, dict)
                            else []
                        ),
                    })

    print(f"Decks inspected: {len(decks)}")
    print(f"Card entries inspected: {total_entries}")

    print("\nIssues:")
    for issue, count in issues.items():
        print(f"  {issue}: {count}")

    print("\nFirst 10 problematic entries:")
    print(json.dumps(examples, indent=2))


if __name__ == "__main__":
    main()
