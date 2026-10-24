
import argparse
import json
from pathlib import Path


def load_records(path):
    with Path(path).open(encoding="utf-8") as file:
        snapshot = json.load(file)

    records = {}

    for run in snapshot["runs"]:
        for record in run["records"]:
            card_id = int(record["card_id"])
            quantity = int(record["quantity"])

            records.setdefault(card_id, set()).add(quantity)

    return records


def classify_candidate(baseline, candidate):
    baseline_ids = set(baseline)
    candidate_ids = set(candidate)

    shared = baseline_ids & candidate_ids

    matching = {
        card_id
        for card_id in shared
        if baseline[card_id] == candidate[card_id]
    }

    quantity_mismatches = shared - matching

    conflicts = {
        card_id
        for card_id, quantities in candidate.items()
        if len(quantities) > 1
    }

    coverage = (
        len(shared) / len(baseline_ids)
        if baseline_ids else 0
    )

    precision = (
        len(shared) / len(candidate_ids)
        if candidate_ids else 0
    )

    agreement = (
        len(matching) / len(shared)
        if shared else 0
    )

    return {
        "candidate_count": len(candidate_ids),
        "shared_count": len(shared),
        "extra_count": len(candidate_ids - baseline_ids),
        "missing_count": len(baseline_ids - candidate_ids),
        "coverage": coverage,
        "precision": precision,
        "quantity_agreement": agreement,
        "quantity_mismatches": len(quantity_mismatches),
        "conflicts": len(conflicts),
    }


def main():
    parser = argparse.ArgumentParser(
        description="Classify MTG Arena collection candidates."
    )

    parser.add_argument(
        "--baseline",
        type=Path,
        required=True,
    )

    parser.add_argument(
        "candidates",
        type=Path,
        nargs="+",
    )

    args = parser.parse_args()

    baseline = load_records(args.baseline)

    print(f"Baseline: {len(baseline):,} unique IDs")

    for path in args.candidates:
        candidate = load_records(path)
        result = classify_candidate(baseline, candidate)

        print(f"\nCandidate: {path}")
        print("-" * 55)

        print(f"Unique IDs:        {result['candidate_count']:,}")
        print(f"Shared IDs:        {result['shared_count']:,}")
        print(f"Additional IDs:    {result['extra_count']:,}")
        print(f"Missing IDs:       {result['missing_count']:,}")

        print(f"Coverage:          {result['coverage']:.2%}")
        print(f"Precision:         {result['precision']:.2%}")
        print(
            f"Quantity agreement: "
            f"{result['quantity_agreement']:.2%}"
        )

        print(
            f"Quantity mismatches: "
            f"{result['quantity_mismatches']}"
        )

        print(f"Internal conflicts: {result['conflicts']}")


if __name__ == "__main__":
    main()
