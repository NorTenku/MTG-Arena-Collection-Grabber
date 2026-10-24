
import json
from pathlib import Path

from inspect_log import find_log_directory


TARGET_LINES = {77, 108, 138}


def describe(value, depth=0):
    """Describe JSON structure without displaying values."""

    if depth >= 3:
        return type(value).__name__

    if isinstance(value, dict):
        return {
            key: describe(child, depth + 1)
            for key, child in list(value.items())[:15]
        }

    if isinstance(value, list):
        return {
            "type": "list",
            "length": len(value),
            "first_item": (
                describe(value[0], depth + 1)
                if value else None
            ),
        }

    return type(value).__name__


def inspect_entry(line_number, line):
    print(f"\n{'=' * 50}")
    print(f"Line: {line_number}")
    print(f"Length: {len(line):,} characters")

    start = line.find("{")

    if start == -1:
        print("No JSON object detected")
        return

    try:
        data = json.loads(line[start:])
    except json.JSONDecodeError:
        print("Could not parse as a complete JSON object")
        return

    print("JSON structure:")
    print(json.dumps(describe(data), indent=2))


def main():
    log_dir = find_log_directory()

    if log_dir is None:
        print("Arena log directory not found")
        return

    log_path = log_dir / "Player.log"

    with log_path.open(
        "r", encoding="utf-8", errors="replace"
    ) as file:
        for number, line in enumerate(file, start=1):
            if number in TARGET_LINES:
                inspect_entry(number, line)


if __name__ == "__main__":
    main()
