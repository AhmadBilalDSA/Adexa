import json
import os
import time

from verifier import DVWAVerifier


INPUT_FILE = "data/adexa_dataset_clean.json"
OUTPUT_FILE = "data/adexa_dataset_verified.json"
REPORT_FILE = "data/verification_report.json"

FINAL_FILE = "data/final_training_dataset.json"

DVWA_HOST = "http://192.168.64.7"

PAUSE_BETWEEN_TESTS = 0.3


def load_json_list(path):

    if not os.path.exists(path):
        return []

    try:
        with open(path, "r") as f:
            data = json.load(f)

        return data if isinstance(data, list) else []

    except Exception:
        return []


def load_dataset():

    data = load_json_list(
        INPUT_FILE
    )

    if not data:
        print(
            f"❌ No clean dataset found: "
            f"{INPUT_FILE}"
        )

    return data


def simplify_verification(
    details,
    strategy
):

    if strategy == "SWITCH_TIME":

        return {
            "method": "time",
            "elapsed": round(
                details.get(
                    "elapsed",
                    0
                ),
                3
            ),
            "threshold": details.get(
                "threshold"
            ),
            "status": details.get(
                "status"
            )
        }

    if strategy == "SWITCH_BOOLEAN":

        return {
            "method": "boolean",
            "repaired_length":
                details.get(
                    "repaired_length"
                ),
            "false_length":
                details.get(
                    "false_length"
                ),
            "length_difference":
                details.get(
                    "length_difference"
                ),
            "length_threshold":
                details.get(
                    "length_threshold"
                )
        }

    return {
        "method": "unknown"
    }


def make_training_key(entry):

    return (
        entry.get(
            "broken_payload",
            ""
        ).strip().lower(),

        entry.get(
            "repaired_payload",
            ""
        ).strip().lower(),

        entry.get(
            "failure_type",
            ""
        ).strip().lower(),

        entry.get(
            "strategy",
            ""
        ).strip().lower()
    )


def append_verified_to_final(
    results
):

    verified_rows = [
        entry
        for entry in results
        if entry.get(
            "verified"
        ) is True
    ]

    existing = load_json_list(
        FINAL_FILE
    )

    seen = {
        make_training_key(entry)
        for entry in existing
    }

    added = []
    duplicates = 0

    for entry in verified_rows:

        key = make_training_key(
            entry
        )

        if key in seen:
            duplicates += 1
            continue

        seen.add(key)
        existing.append(entry)
        added.append(entry)

    with open(
        FINAL_FILE,
        "w"
    ) as f:

        json.dump(
            existing,
            f,
            indent=2
        )

    return {
        "verified_this_run":
            len(verified_rows),

        "added":
            len(added),

        "duplicates":
            duplicates,

        "final_total":
            len(existing)
    }


def main():

    dataset = load_dataset()

    if not dataset:
        return

    print(
        f"📦 Clean entries loaded: "
        f"{len(dataset)}"
    )

    verifier = DVWAVerifier(
        base_host=DVWA_HOST,
        username="admin",
        password="password"
    )

    if not verifier.login():

        print(
            "❌ Could not connect/authenticate "
            "to DVWA"
        )

        return

    print(
        "\n🚀 Starting dataset verification...\n"
    )

    results = []

    verified_count = 0
    failed_count = 0
    error_count = 0

    for index, entry in enumerate(
        dataset,
        start=1
    ):

        print(
            f"[{index}/{len(dataset)}] "
            f"{entry.get('failure_type', 'unknown')} "
            f"→ "
            f"{entry.get('strategy', 'unknown')}"
        )

        try:

            verified, details = (
                verifier.verify_repair(
                    entry
                )
            )

            updated_entry = (
                entry.copy()
            )

            updated_entry[
                "verified"
            ] = bool(
                verified
            )

            updated_entry[
                "verification"
            ] = simplify_verification(
                details,
                entry.get(
                    "strategy",
                    ""
                )
            )

            if verified:

                verified_count += 1

                print(
                    "   ✅ VERIFIED"
                )

            else:

                failed_count += 1

                print(
                    "   ❌ FAILED"
                )

            results.append(
                updated_entry
            )

        except Exception as e:

            error_count += 1

            updated_entry = (
                entry.copy()
            )

            updated_entry[
                "verified"
            ] = False

            updated_entry[
                "verification"
            ] = {
                "method": "error",
                "error": str(e)
            }

            results.append(
                updated_entry
            )

            print(
                f"   ⚠️ ERROR: {e}"
            )

        time.sleep(
            PAUSE_BETWEEN_TESTS
        )

    os.makedirs(
        "data",
        exist_ok=True
    )

    with open(
        OUTPUT_FILE,
        "w"
    ) as f:

        json.dump(
            results,
            f,
            indent=2
        )

    total = len(
        results
    )

    verification_rate = (
        verified_count
        /
        total
        *
        100
        if total
        else 0
    )

    report = {
        "total": total,
        "verified":
            verified_count,
        "failed":
            failed_count,
        "errors":
            error_count,
        "verification_rate":
            round(
                verification_rate,
                2
            )
    }

    with open(
        REPORT_FILE,
        "w"
    ) as f:

        json.dump(
            report,
            f,
            indent=2
        )

    final_stats = (
        append_verified_to_final(
            results
        )
    )

    print(
        "\n=============================="
    )

    print(
        "📊 VERIFICATION SUMMARY"
    )

    print(
        "=============================="
    )

    print(
        f"Total:       {total}"
    )

    print(
        f"✅ Verified: {verified_count}"
    )

    print(
        f"❌ Failed:   {failed_count}"
    )

    print(
        f"⚠️ Errors:   {error_count}"
    )

    print(
        f"🎯 Verification rate: "
        f"{verification_rate:.1f}%"
    )

    print(
        "\n=============================="
    )

    print(
        "🏆 FINAL TRAINING DATASET"
    )

    print(
        "=============================="
    )

    print(
        f"Verified this run: "
        f"{final_stats['verified_this_run']}"
    )

    print(
        f"➕ New rows added: "
        f"{final_stats['added']}"
    )

    print(
        f"🔁 Duplicates skipped: "
        f"{final_stats['duplicates']}"
    )

    print(
        f"🏆 Final training rows: "
        f"{final_stats['final_total']}"
    )

    print(
        f"\n💾 Verified dataset: "
        f"{OUTPUT_FILE}"
    )

    print(
        f"📊 Report: "
        f"{REPORT_FILE}"
    )

    print(
        f"🧠 Training dataset: "
        f"{FINAL_FILE}"
    )


if __name__ == "__main__":
    main()
