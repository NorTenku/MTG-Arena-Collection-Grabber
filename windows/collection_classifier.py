
import json
from pathlib import Path


def records_from_runs(runs):
    records = {}

    for run in runs:
        for record in run["records"]:
            card_id = int(record["card_id"])
            quantity = int(record["quantity"])
            records.setdefault(card_id, set()).add(quantity)

    return records


def records_from_flat_list(records):
    result = {}

    for record in records:
        card_id = int(record["card_id"])
        quantity = int(record["quantity"])
        result.setdefault(card_id, set()).add(quantity)

    return result


def load_baseline(path):
    with Path(path).open(encoding="utf-8") as file:
        snapshot = json.load(file)

    return records_from_runs(snapshot["runs"])


def classify_candidate(baseline, candidate):
    baseline_ids = set(baseline)
    candidate_ids = set(candidate)

    shared = baseline_ids & candidate_ids

    matching = {
        card_id
        for card_id in shared
        if baseline[card_id] == candidate[card_id]
    }

    conflicts = {
        card_id
        for card_id, quantities in candidate.items()
        if len(quantities) > 1
    }

    return {
        "candidate_count": len(candidate_ids),
        "shared_count": len(shared),
        "extra_count": len(candidate_ids - baseline_ids),
        "missing_count": len(baseline_ids - candidate_ids),
        "coverage": len(shared) / len(baseline_ids)
        if baseline_ids else 0,
        "precision": len(shared) / len(candidate_ids)
        if candidate_ids else 0,
        "quantity_agreement": len(matching) / len(shared)
        if shared else 0,
        "quantity_mismatches": len(shared - matching),
        "conflicts": len(conflicts),
    }
