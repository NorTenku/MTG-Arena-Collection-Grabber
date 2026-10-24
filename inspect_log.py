
from pathlib import Path
from collections import Counter
import re

KEYWORDS = (
    "GetPlayerCards",
    "Card_GetAllCards",
    "Collection",
    "StartHook",
    "DeckSummaries",
)


def find_log_directory() -> Path | None:
    """Find MTG Arena's Windows log directory from WSL."""
    users_dir = Path("/mnt/c/Users")

    if not users_dir.exists():
        return None

    for user_dir in users_dir.iterdir():
        candidate = (
            user_dir
            / "AppData"
            / "LocalLow"
            / "Wizards Of The Coast"
            / "MTGA"
        )

        if (candidate / "Player.log").is_file():
            return candidate

    return None


def inspect_log(path: Path) -> None:
    if not path.is_file():
        print(f"Not found: {path}")
        return

    print(f"\nLog: {path.name}")
    print(f"Size: {path.stat().st_size:,} bytes")

    counts = Counter()
    lines_read = 0

    with path.open(
        "r", encoding="utf-8", errors="replace"
    ) as file:
        for line in file:
            lines_read += 1
            for keyword in KEYWORDS:
                if re.search(
                    re.escape(keyword),
                    line,
                    flags=re.IGNORECASE,
                ):
                    counts[keyword] += 1

    print(f"Lines scanned: {lines_read:,}")

    for keyword in KEYWORDS:
        print(f"  {keyword}: {counts[keyword]}")


def main() -> None:
    print("MTG Arena log diagnostics (WSL)")

    log_dir = find_log_directory()

    if log_dir is None:
        print("Could not locate MTG Arena logs.")
        return

    print(f"Directory: {log_dir}")

    for filename in ("Player.log", "Player-prev.log"):
        inspect_log(log_dir / filename)


if __name__ == "__main__":
    main()
