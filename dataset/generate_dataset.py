import json
import time
import urllib.request
import os
import random

from collections import Counter
from prompts import REPAIR_PROMPT
from corruptions import corrupt_for_failure


OLLAMA_URL = "http://127.0.0.1:11434/api/generate"

REPAIR_MODEL = "qwen2.5:7b"

BASE_PAYLOADS_FILE = "data/base_payloads.json"
OUTPUT_FILE = "data/adexa_dataset.json"

TEMPERATURE = 0.2
NUM_PREDICT = 350

# Keep small while testing stability
TOTAL_BATCHES = 20

# Number of controlled broken payloads per batch
BATCH_SIZE = 5


def extract_json(text):

    text = text.strip()

    text = text.replace("```json", "")
    text = text.replace("```", "")

    start = text.find("[")
    end = text.rfind("]")

    if start == -1 or end == -1:
        return []

    try:

        parsed = json.loads(
            text[start:end + 1]
        )

        if isinstance(parsed, list):
            return parsed

        return []

    except Exception as e:

        print(f"⚠️ JSON parse error: {e}")

        return []


def call_ollama(prompt, model):

    print(f"📡 Calling {model}...")

    data = json.dumps({
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": TEMPERATURE,
            "num_predict": NUM_PREDICT
        }
    }).encode("utf-8")

    req = urllib.request.Request(
        OLLAMA_URL,
        data=data,
        headers={
            "Content-Type": "application/json"
        }
    )

    try:

        with urllib.request.urlopen(
            req,
            timeout=600
        ) as response:

            result = json.loads(
                response.read().decode("utf-8")
            )

        output = result.get(
            "response",
            ""
        ).strip()

        print("✅ Response received")

        print("\n===== RAW MODEL OUTPUT =====")
        print(output[:1000])
        print("===== END OUTPUT =====\n")

        parsed = extract_json(output)

        if not parsed:

            print("⚠️ Failed to parse JSON")

            return []

        print(
            f"✅ Parsed JSON entries: {len(parsed)}"
        )

        return parsed

    except Exception as e:

        print(f"❌ Ollama error: {e}")

        return []


def remove_local_duplicates(data):

    seen = set()
    clean = []

    for entry in data:

        key = json.dumps(
            entry,
            sort_keys=True
        )

        if key not in seen:

            seen.add(key)
            clean.append(entry)

    return clean


def load_base_payloads():

    if not os.path.exists(BASE_PAYLOADS_FILE):

        print(
            f"❌ Base payload file not found: "
            f"{BASE_PAYLOADS_FILE}"
        )

        return []

    try:

        with open(
            BASE_PAYLOADS_FILE,
            "r"
        ) as f:

            payloads = json.load(f)

    except Exception as e:

        print(
            f"❌ Failed to load base payloads: {e}"
        )

        return []

    if not isinstance(payloads, list):

        print(
            "❌ base_payloads.json must contain a JSON list"
        )

        return []

    clean = []

    for entry in payloads:

        if not isinstance(entry, dict):
            continue

        payload = entry.get("payload")
        payload_type = entry.get("type")

        if not payload:
            continue

        if payload_type not in [
            "boolean",
            "time"
        ]:
            continue

        clean.append(entry)

    print(
        f"📦 Loaded {len(clean)} known-good payloads"
    )

    return clean

def get_failure_counts():

    counts = Counter()

    if not os.path.exists(OUTPUT_FILE):
        return counts

    try:
        with open(OUTPUT_FILE, "r") as f:
            data = json.load(f)

    except Exception:
        return counts

    for entry in data:

        if not isinstance(entry, dict):
            continue

        failure_type = entry.get("failure_type")

        if failure_type:
            counts[failure_type] += 1

    return counts


def choose_target_failures(batch_size):

    failure_types = [
        "malformed_syntax",
        "incomplete_statement",
        "logical_error",
        "invalid_time_function",
        "boolean_no_effect"
    ]

    counts = get_failure_counts()

    targets = []

    for _ in range(batch_size):

        # Pick the currently least represented class
        failure_type = min(
            failure_types,
            key=lambda f: counts[f]
        )

        targets.append(failure_type)

        # Pretend we already added one so the
        # next choice also considers balance
        counts[failure_type] += 1

    return targets


def generate_broken_batch(batch_size=BATCH_SIZE):

    base_payloads = load_base_payloads()

    if not base_payloads:
        return []

    target_failures = choose_target_failures(
        batch_size
    )

    print(
        f"🎯 Target failures: {target_failures}"
    )

    broken_entries = []

    used_payloads = set()

    for failure_type in target_failures:

        candidates = base_payloads.copy()

        random.shuffle(candidates)

        found = False

        for entry in candidates:

            payload = entry["payload"]
            payload_type = entry["type"]

            # Prefer different base payloads
            if payload in used_payloads:
                continue

            try:

                corrupted = corrupt_for_failure(
                    payload,
                    payload_type,
                    failure_type
                )

            except Exception as e:

                print(
                    f"⚠️ Corruption error: {e}"
                )

                continue

            if not corrupted:
                continue

            if not isinstance(
                corrupted,
                dict
            ):
                continue

            broken_payload = corrupted.get(
                "broken_payload"
            )

            original_payload = corrupted.get(
                "original_payload"
            )

            actual_failure = corrupted.get(
                "failure_type"
            )

            if not broken_payload:
                continue

            if not original_payload:
                continue

            if actual_failure != failure_type:
                continue

            if (
                broken_payload.strip().lower()
                ==
                original_payload.strip().lower()
            ):
                continue

            broken_entries.append(
                corrupted
            )

            used_payloads.add(
                payload
            )

            found = True

            break

        if not found:

            print(
                f"⚠️ Could not generate: "
                f"{failure_type}"
            )

    return remove_local_duplicates(
        broken_entries
    )
    base_payloads = load_base_payloads()

    if not base_payloads:
        return []

    target_failures = [
        "malformed_syntax",
        "incomplete_statement",
        "logical_error",
        "invalid_time_function",
        "boolean_no_effect"
    ]

    broken_entries = []

    random.shuffle(base_payloads)

    for failure_type in target_failures:

        if len(broken_entries) >= batch_size:
            break

        found = False

        for entry in base_payloads:

            payload = entry["payload"]
            payload_type = entry["type"]

            try:

                corrupted = corrupt_for_failure(
                    payload,
                    payload_type,
                    failure_type
                )

            except Exception as e:

                print(
                    f"⚠️ Corruption error: {e}"
                )

                continue

            if not corrupted:
                continue

            if not isinstance(corrupted, dict):
                continue

            broken_payload = corrupted.get(
                "broken_payload"
            )

            original_payload = corrupted.get(
                "original_payload"
            )

            actual_failure = corrupted.get(
                "failure_type"
            )

            if not broken_payload:
                continue

            if not original_payload:
                continue

            if not actual_failure:
                continue

            if (
                broken_payload.strip().lower()
                ==
                original_payload.strip().lower()
            ):
                continue

            broken_entries.append(
                corrupted
            )

            found = True

            break

        if not found:

            print(
                f"⚠️ Could not create failure type: "
                f"{failure_type}"
            )

    return remove_local_duplicates(
        broken_entries
    )


def repair_payloads(broken):

    if not broken:
        return []

    prompt = (
        REPAIR_PROMPT
        + "\n\nINPUT:\n"
        + json.dumps(
            broken,
            indent=2
        )
    )

    repaired = call_ollama(
        prompt,
        REPAIR_MODEL
    )

    clean = []

    # Build lookup so we can restore
    # original_payload after LLM repair
    original_lookup = {}

    for entry in broken:

        broken_payload = entry.get(
            "broken_payload"
        )

        if broken_payload:

            original_lookup[
                broken_payload.strip().lower()
            ] = entry.get(
                "original_payload"
            )

    for entry in repaired:

        if not isinstance(entry, dict):
            continue

        broken_payload = entry.get(
            "broken_payload",
            ""
        )

        repaired_payload = entry.get(
            "repaired_payload",
            ""
        )

        failure_type = entry.get(
            "failure_type"
        )

        strategy = entry.get(
            "strategy"
        )

        explanation = entry.get(
            "explanation"
        )

        if not broken_payload:
            continue

        if not repaired_payload:
            continue

        if not failure_type:
            continue

        if not strategy:
            continue

        if not explanation:
            continue

        # Reject unchanged repairs
        if (
            broken_payload.strip().lower()
            ==
            repaired_payload.strip().lower()
        ):
            continue

        # Keep repairs short
        if len(repaired_payload) > 40:
            continue

        original_payload = original_lookup.get(
            broken_payload.strip().lower()
        )

        if not original_payload:
            continue

        final_entry = {
            "original_payload": original_payload,
            "broken_payload": broken_payload,
            "failure_type": failure_type,
            "strategy": strategy,
            "repaired_payload": repaired_payload,
            "explanation": explanation,
            "verified": False
        }

        clean.append(
            final_entry
        )

    return remove_local_duplicates(
        clean
    )


def save_data(data):

    os.makedirs(
        "data",
        exist_ok=True
    )

    try:

        with open(
            OUTPUT_FILE,
            "r"
        ) as f:

            existing = json.load(f)

    except Exception:

        existing = []

    existing.extend(
        data
    )

    existing = remove_local_duplicates(
        existing
    )

    with open(
        OUTPUT_FILE,
        "w"
    ) as f:

        json.dump(
            existing,
            f,
            indent=2
        )

    print(
        f"💾 Total saved entries: {len(existing)}"
    )


def run_pipeline():

    print(
        "\n⚡ Creating controlled broken payloads..."
    )

    broken = generate_broken_batch(
        BATCH_SIZE
    )

    if not broken:

        print(
            "❌ Controlled corruption failed"
        )

        return

    print(
        f"✅ Broken payloads generated: {len(broken)}"
    )

    print(
        "\n===== CONTROLLED CORRUPTIONS ====="
    )

    for entry in broken:

        print(
            f"\nOriginal: {entry['original_payload']}"
        )

        print(
            f"Broken:   {entry['broken_payload']}"
        )

        print(
            f"Failure:  {entry['failure_type']}"
        )

    print(
        "===== END CORRUPTIONS =====\n"
    )

    print(
        "🧠 Repairing payloads..."
    )

    repaired = repair_payloads(
        broken
    )

    if not repaired:

        print(
            "❌ Repair failed"
        )

        return

    print(
        f"✅ Repairs generated: {len(repaired)}"
    )

    print(
        "\n💾 Saving dataset..."
    )

    save_data(
        repaired
    )

    print(
        f"✅ Batch complete: {len(repaired)} entries"
    )


if __name__ == "__main__":

    for i in range(
        TOTAL_BATCHES
    ):

        print(
            "\n=============================="
        )

        print(
            f"🔥 BATCH {i + 1}/{TOTAL_BATCHES}"
        )

        print(
            "=============================="
        )

        run_pipeline()

        sleep_time = random.randint(
            3,
            6
        )

        print(
            f"\n⏳ Cooling down for {sleep_time}s...\n"
        )

        time.sleep(
            sleep_time
        )
