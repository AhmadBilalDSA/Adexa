import json
import os
from collections import Counter

INPUT_FILE = "data/adexa_dataset.json"
OUTPUT_FILE = "data/adexa_dataset_clean.json"
REPORT_FILE = "data/validation_report.json"

VALID_STRATEGIES = [
    "SWITCH_BOOLEAN",
    "SWITCH_TIME"
]

VALID_FAILURES = [
    "incomplete_statement",
    "malformed_syntax",
    "logical_error",
    "invalid_time_function",
    "boolean_no_effect"
]

TIME_KEYWORDS = [
    "sleep("
]

BOOLEAN_KEYWORDS = [
    "=",
    ">",
    "<",
    " and ",
    " or ",
    "length(",
    "ascii("
]

BAD_PATTERNS = [
    "select",
    "union",
    "information_schema",
    "database()",
    "schema()",
    "case when",
    "benchmark",
    "/*",
    "&lt;",
    "&gt;",
    "sleep(0)",
    "---",
    "\\",
    "\""
]


def normalize(payload):
    return " ".join(
        payload.strip().lower().split()
    )


def has_required_fields(entry):
    required = [
        "original_payload",
        "broken_payload",
        "failure_type",
        "strategy",
        "repaired_payload",
        "explanation",
        "verified"
    ]

    return all(
        field in entry
        for field in required
    )


def valid_field_types(entry):
    string_fields = [
        "original_payload",
        "broken_payload",
        "failure_type",
        "strategy",
        "repaired_payload",
        "explanation"
    ]

    for field in string_fields:
        if not isinstance(entry[field], str):
            return False

    if not isinstance(entry["verified"], bool):
        return False

    return True


def valid_strategy(entry):
    return entry["strategy"] in VALID_STRATEGIES


def valid_failure(entry):
    return entry["failure_type"] in VALID_FAILURES


def contains_bad_patterns(payload):
    payload = payload.lower()

    return any(
        pattern in payload
        for pattern in BAD_PATTERNS
    )


def payload_too_long(payload):
    return len(payload) > 60


def repair_changed(entry):
    return (
        normalize(entry["broken_payload"])
        !=
        normalize(entry["repaired_payload"])
    )


def explanation_valid(entry):
    explanation = entry["explanation"].strip().lower()

    if len(explanation.split()) < 4:
        return False

    banned = [
        "already valid",
        "no change needed"
    ]

    return not any(
        phrase in explanation
        for phrase in banned
    )


def strategy_matches_payload(entry):
    strategy = entry["strategy"]
    repaired = entry["repaired_payload"].lower()

    if strategy == "SWITCH_TIME":
        return any(
            keyword in repaired
            for keyword in TIME_KEYWORDS
        )

    if strategy == "SWITCH_BOOLEAN":
        return any(
            keyword in repaired
            for keyword in BOOLEAN_KEYWORDS
        )

    return False


def comment_restored(entry):
    original = entry["original_payload"].strip()
    repaired = entry["repaired_payload"].strip()

    if original.endswith("-- -"):
        return repaired.endswith("-- -")

    return True


def suspicious_rewrite(entry):
    repaired = entry["repaired_payload"].lower()

    bad_rewrites = [
        "length('x')=length('x')",
        "length('abc')=length('abc')",
        "length('test')=length('test')",
        "ascii('a')=ascii('a')",
        "ascii('b')=ascii('b')",
        "ascii('c')=ascii('c')"
    ]

    return any(
        pattern in repaired
        for pattern in bad_rewrites
    )


def exact_restoration(entry):
    return (
        normalize(entry["original_payload"])
        ==
        normalize(entry["repaired_payload"])
    )


def obviously_wrong_semantics(entry):
    original = normalize(entry["original_payload"])
    repaired = normalize(entry["repaired_payload"])

    # If controlled corruption was just syntax damage,
    # large semantic rewrites are suspicious.
    if entry["failure_type"] in [
        "malformed_syntax",
        "incomplete_statement"
    ]:
        original_core = (
            original
            .replace(" -- -", "")
            .replace(" --", "")
        )

        repaired_core = (
            repaired
            .replace(" -- -", "")
            .replace(" --", "")
        )

        # Examples like:
        # LENGTH('x')=1 -> LENGTH('x')=2
        # are suspicious for syntax-only failures.
        if "length(" in original_core and "length(" in repaired_core:
            if original_core != repaired_core:
                return True

        if "ascii(" in original_core and "ascii(" in repaired_core:
            if original_core != repaired_core:
                return True

    return False


def structurally_valid(entry):
    if not isinstance(entry, dict):
        return False

    if not has_required_fields(entry):
        return False

    if not valid_field_types(entry):
        return False

    if not valid_strategy(entry):
        return False

    if not valid_failure(entry):
        return False

    repaired = entry["repaired_payload"]

    if not repaired:
        return False

    if payload_too_long(repaired):
        return False

    if not repair_changed(entry):
        return False

    if contains_bad_patterns(repaired):
        return False

    if not strategy_matches_payload(entry):
        return False

    if not explanation_valid(entry):
        return False

    if not comment_restored(entry):
        return False

    if suspicious_rewrite(entry):
        return False

    return True


def classify_repair(entry):
    if not structurally_valid(entry):
        return "invalid"

    if exact_restoration(entry):
        return "exact_restoration"

    if obviously_wrong_semantics(entry):
        return "suspicious"

    return "alternative_repair"


def remove_duplicates(data):
    seen = set()
    clean = []

    for entry in data:
        key = (
            normalize(entry["original_payload"]),
            normalize(entry["broken_payload"]),
            normalize(entry["repaired_payload"]),
            entry["failure_type"],
            entry["strategy"]
        )

        if key not in seen:
            seen.add(key)
            clean.append(entry)

    return clean


def main():
    if not os.path.exists(INPUT_FILE):
        print("❌ Dataset file not found")
        return

    try:
        with open(INPUT_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as error:
        print(f"❌ Invalid JSON: {error}")
        return
    except OSError as error:
        print(f"❌ Could not read dataset: {error}")
        return

    if not isinstance(data, list):
        print("❌ Dataset root must be a JSON list")
        return

    print(f"📦 Total entries: {len(data)}")

    valid_entries = []

    classifications = Counter()
    failures = Counter()
    strategies = Counter()

    for entry in data:
        try:
            classification = classify_repair(entry)
            classifications[classification] += 1

            if isinstance(entry, dict):
                failures[
                    entry.get("failure_type", "missing")
                ] += 1

                strategies[
                    entry.get("strategy", "missing")
                ] += 1

            if classification in [
                "exact_restoration",
                "alternative_repair"
            ]:
                clean_entry = entry.copy()
                clean_entry["quality_class"] = classification

                valid_entries.append(clean_entry)

        except Exception:
            classifications["invalid"] += 1

    before_duplicates = len(valid_entries)

    valid_entries = remove_duplicates(valid_entries)

    duplicates_removed = (
        before_duplicates - len(valid_entries)
    )

    print()
    print("===== REPAIR QUALITY =====")

    print(
        f"🎯 Exact restoration: "
        f"{classifications['exact_restoration']}"
    )

    print(
        f"🔄 Alternative repair: "
        f"{classifications['alternative_repair']}"
    )

    print(
        f"⚠️ Suspicious repair: "
        f"{classifications['suspicious']}"
    )

    print(
        f"❌ Invalid repair: "
        f"{classifications['invalid']}"
    )

    print()
    print("===== FAILURE DISTRIBUTION =====")

    for failure, count in failures.most_common():
        print(f"{failure}: {count}")

    print()
    print("===== STRATEGY DISTRIBUTION =====")

    for strategy, count in strategies.most_common():
        print(f"{strategy}: {count}")

    print()
    print(
        f"🗑️ Duplicates removed: {duplicates_removed}"
    )

    print(
        f"✅ Clean accepted entries: {len(valid_entries)}"
    )

    os.makedirs("data", exist_ok=True)

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as f:
        json.dump(
            valid_entries,
            f,
            indent=2,
            ensure_ascii=False
        )

    report = {
        "total_entries": len(data),
        "accepted_before_deduplication": before_duplicates,
        "duplicates_removed": duplicates_removed,
        "accepted_entries": len(valid_entries),
        "rejected_entries": (
            len(data) - before_duplicates
        ),
        "quality": dict(classifications),
        "failure_distribution": dict(failures),
        "strategy_distribution": dict(strategies)
    }

    with open(
        REPORT_FILE,
        "w",
        encoding="utf-8"
    ) as f:
        json.dump(
            report,
            f,
            indent=2,
            ensure_ascii=False
        )

    print()
    print(
        f"💾 Clean dataset saved to: "
        f"{OUTPUT_FILE}"
    )

    print(
        f"📊 Validation report saved to: "
        f"{REPORT_FILE}"
    )


if __name__ == "__main__":
    main()
