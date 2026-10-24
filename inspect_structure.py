
from pathlib import Path
from collections import Counter
import json

from inspect_log import find_log_directory


def inspect_structure(path: Path) -> None:
    if not path.is_file():
        print(f"Log not found: {path}")
        return

    line_sizes = []
    json_fields = Counter()
    json_lines = 0

    with path.open(
        "r", encoding="utf-8", errors="replace"
    ) as file:
        for line_number, line in enumerate(file, start=1):
            line_sizes.append(
                (line_number, len(line))
            )

            start = line.find("{")

            if start == -1:
                continue

            try:
                data = json.loads(line[start:])
            except json.JSONDecodeError:
                continue

            json_lines += 1

            if isinstance(data, dict):
                json_fields.update(data.keys())

    print(f"\nFile: {path.name}")
    print(f"Total lines: {len(line_sizes)}")
    print(f"JSON lines detected: {json_lines}")

    print("\nLargest log entries:")
    for number, size in sorted(
        line_sizes,
        key=lambda item: item[1],
        reverse=True,
    )[:10]:
        print(f"  Line {number}: {size:,} characters")

    print("\nMost common JSON fields:")
    for field, count in json_fields.most_common(20):
        print(f"  {field}: {count}")


def main() -> None:
    log_dir = find_log_directory()

    if log_dir is None:
        print("Could not locate Arena logs.")
        return

    for filename in ("Player.log", "Player-prev.log"):
        inspect_structure(log_dir / filename)


if __name__ == "__main__":
    main()
