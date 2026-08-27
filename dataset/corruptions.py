import random
import re


VALID_FAILURES = [
    "malformed_syntax",
    "incomplete_statement",
    "logical_error",
    "invalid_time_function",
    "boolean_no_effect"
]


def make_result(
    original,
    broken,
    failure_type
):
    return {
        "original_payload": original,
        "broken_payload": broken,
        "failure_type": failure_type
    }


def choose_result(
    payload,
    candidates,
    failure_type
):
    clean = []

    for broken in candidates:
        if not broken:
            continue

        if broken == payload:
            continue

        if broken not in clean:
            clean.append(broken)

    if not clean:
        return None

    return make_result(
        payload,
        random.choice(clean),
        failure_type
    )


# ==========================================================
# MALFORMED SYNTAX
# ==========================================================

def corrupt_malformed_syntax(payload):

    candidates = []

    if " AND " in payload:
        candidates.extend([
            payload.replace(
                " AND ",
                " AN D ",
                1
            ),
            payload.replace(
                " AND ",
                " A ND ",
                1
            ),
            payload.replace(
                " AND ",
                " ANDD ",
                1
            )
        ])

    if " OR " in payload:
        candidates.extend([
            payload.replace(
                " OR ",
                " O R ",
                1
            ),
            payload.replace(
                " OR ",
                " OOR ",
                1
            ),
            payload.replace(
                " OR ",
                " ORR ",
                1
            )
        ])

    if "LENGTH(" in payload:
        candidates.extend([
            payload.replace(
                "LENGTH(",
                "LENGT(",
                1
            ),
            payload.replace(
                "LENGTH(",
                "LENGTHH(",
                1
            )
        ])

    if "ASCII(" in payload:
        candidates.extend([
            payload.replace(
                "ASCII(",
                "ASCI(",
                1
            ),
            payload.replace(
                "ASCII(",
                "ASCII((",
                1
            )
        ])

    return choose_result(
        payload,
        candidates,
        "malformed_syntax"
    )


# ==========================================================
# INCOMPLETE STATEMENT
# ==========================================================

def corrupt_incomplete_statement(payload):

    candidates = []

    if "-- -" in payload:
        candidates.extend([
            payload.replace(
                "-- -",
                "--",
                1
            ),
            payload.replace(
                "-- -",
                "-",
                1
            ),
            payload.replace(
                "-- -",
                "",
                1
            )
        ])

    if ")" in payload:
        index = payload.rfind(")")

        candidates.append(
            payload[:index]
            +
            payload[index + 1:]
        )

    if payload.endswith("-- -"):
        candidates.append(
            payload[:-2]
        )

    return choose_result(
        payload,
        candidates,
        "incomplete_statement"
    )


# ==========================================================
# LOGICAL ERROR
# ==========================================================

def corrupt_logical_error(payload):

    candidates = []

    # Numeric equality
    match = re.search(
        r"(\d+)\s*=\s*(\d+)",
        payload
    )

    if match:

        left = int(match.group(1))
        right = int(match.group(2))

        replacements = [
            f"{left}={right + 1}",
            f"{left}={right + 2}",
            f"{left + 1}={right}"
        ]

        for replacement in replacements:

            candidates.append(
                payload[:match.start()]
                +
                replacement
                +
                payload[match.end():]
            )

    # Greater than
    match = re.search(
        r"(\d+)\s*>\s*(\d+)",
        payload
    )

    if match:

        left = match.group(1)
        right = match.group(2)

        candidates.extend([
            payload[:match.start()]
            + f"{left}<{right}"
            + payload[match.end():],

            payload[:match.start()]
            + f"{left}={right}"
            + payload[match.end():]
        ])

    # Greater or equal
    match = re.search(
        r"(\d+)\s*>=\s*(\d+)",
        payload
    )

    if match:

        left = match.group(1)
        right = match.group(2)

        candidates.extend([
            payload[:match.start()]
            + f"{left}<{right}"
            + payload[match.end():],

            payload[:match.start()]
            + f"{left}={right}"
            + payload[match.end():]
        ])

    # Numeric inequality
    match = re.search(
        r"(\d+)\s*(?:<>|!=)\s*(\d+)",
        payload
    )

    if match:

        left = match.group(1)

        candidates.append(
            payload[:match.start()]
            +
            f"{left}={left}"
            +
            payload[match.end():]
        )

    # String equality
    match = re.search(
        r"'([^']*)'\s*=\s*'([^']*)'",
        payload
    )

    if match:

        left = match.group(1)
        right = match.group(2)

        candidates.extend([
            payload[:match.start()]
            + f"'{left}'='{right}x'"
            + payload[match.end():],

            payload[:match.start()]
            + f"'{left}'='z'"
            + payload[match.end():]
        ])

    # String inequality
    match = re.search(
        r"'([^']*)'\s*(?:<>|!=)\s*'([^']*)'",
        payload
    )

    if match:

        left = match.group(1)

        candidates.append(
            payload[:match.start()]
            +
            f"'{left}'='{left}'"
            +
            payload[match.end():]
        )

    # LENGTH equality
    match = re.search(
        r"LENGTH\('([^']*)'\)\s*=\s*(\d+)",
        payload,
        re.IGNORECASE
    )

    if match:

        text = match.group(1)
        value = int(match.group(2))

        candidates.extend([
            payload[:match.start()]
            + f"LENGTH('{text}')={value + 1}"
            + payload[match.end():],

            payload[:match.start()]
            + f"LENGTH('{text}')={value + 2}"
            + payload[match.end():]
        ])

    # LENGTH >
    match = re.search(
        r"LENGTH\('([^']*)'\)\s*>\s*(\d+)",
        payload,
        re.IGNORECASE
    )

    if match:

        text = match.group(1)
        value = int(match.group(2))

        candidates.extend([
            payload[:match.start()]
            + f"LENGTH('{text}')<{value}"
            + payload[match.end():],

            payload[:match.start()]
            + f"LENGTH('{text}')={value}"
            + payload[match.end():]
        ])

    # ASCII equality
    match = re.search(
        r"ASCII\('([^']+)'\)\s*=\s*(\d+)",
        payload,
        re.IGNORECASE
    )

    if match:

        char = match.group(1)
        value = int(match.group(2))

        candidates.extend([
            payload[:match.start()]
            + f"ASCII('{char}')={value + 1}"
            + payload[match.end():],

            payload[:match.start()]
            + f"ASCII('{char}')={value - 1}"
            + payload[match.end():]
        ])

    # ASCII >
    match = re.search(
        r"ASCII\('([^']+)'\)\s*>\s*(\d+)",
        payload,
        re.IGNORECASE
    )

    if match:

        char = match.group(1)
        value = match.group(2)

        candidates.extend([
            payload[:match.start()]
            + f"ASCII('{char}')<{value}"
            + payload[match.end():],

            payload[:match.start()]
            + f"ASCII('{char}')={value}"
            + payload[match.end():]
        ])

    return choose_result(
        payload,
        candidates,
        "logical_error"
    )


# ==========================================================
# INVALID TIME FUNCTION
# ==========================================================

def corrupt_invalid_time_function(payload):

    if "SLEEP(" not in payload:
        return None

    candidates = [
        payload.replace(
            "SLEEP(",
            "SLEP(",
            1
        ),

        payload.replace(
            "SLEEP(",
            "SLEEPP(",
            1
        ),

        payload.replace(
            "SLEEP(",
            "SLEEP((",
            1
        )
    ]

    match = re.search(
        r"SLEEP\((\d+)\)",
        payload,
        re.IGNORECASE
    )

    if match:

        seconds = match.group(1)

        candidates.extend([
            payload[:match.start()]
            + f"SLEEP({seconds}"
            + payload[match.end():],

            payload[:match.start()]
            + "SLEEP()"
            + payload[match.end():]
        ])

    return choose_result(
        payload,
        candidates,
        "invalid_time_function"
    )


# ==========================================================
# BOOLEAN NO EFFECT
# ==========================================================

def corrupt_boolean_no_effect(payload):

    candidates = []

    # Numeric equality
    match = re.search(
        r"(\d+)\s*=\s*(\d+)",
        payload
    )

    if match:

        left = int(match.group(1))
        right = int(match.group(2))

        candidates.extend([
            payload[:match.start()]
            + f"{left}={right + 1}"
            + payload[match.end():],

            payload[:match.start()]
            + f"{left}=0"
            + payload[match.end():]
        ])

    # Numeric greater than
    match = re.search(
        r"(\d+)\s*>\s*(\d+)",
        payload
    )

    if match:

        left = match.group(1)
        right = match.group(2)

        candidates.extend([
            payload[:match.start()]
            + f"{left}<{right}"
            + payload[match.end():],

            payload[:match.start()]
            + f"{left}={right}"
            + payload[match.end():]
        ])

    # Numeric >=
    match = re.search(
        r"(\d+)\s*>=\s*(\d+)",
        payload
    )

    if match:

        left = match.group(1)
        right = match.group(2)

        candidates.append(
            payload[:match.start()]
            +
            f"{left}<{right}"
            +
            payload[match.end():]
        )

    # String equality
    match = re.search(
        r"'([^']*)'\s*=\s*'([^']*)'",
        payload
    )

    if match:

        left = match.group(1)

        candidates.extend([
            payload[:match.start()]
            + f"'{left}'='different'"
            + payload[match.end():],

            payload[:match.start()]
            + f"'{left}'='z'"
            + payload[match.end():]
        ])

    # String inequality
    match = re.search(
        r"'([^']*)'\s*(?:<>|!=)\s*'([^']*)'",
        payload
    )

    if match:

        left = match.group(1)

        candidates.append(
            payload[:match.start()]
            +
            f"'{left}'='{left}'"
            +
            payload[match.end():]
        )

    # LENGTH equality
    match = re.search(
        r"LENGTH\('([^']*)'\)\s*=\s*(\d+)",
        payload,
        re.IGNORECASE
    )

    if match:

        text = match.group(1)
        value = int(match.group(2))

        candidates.extend([
            payload[:match.start()]
            + f"LENGTH('{text}')={value + 1}"
            + payload[match.end():],

            payload[:match.start()]
            + f"LENGTH('{text}')=0"
            + payload[match.end():]
        ])

    # ASCII equality
    match = re.search(
        r"ASCII\('([^']+)'\)\s*=\s*(\d+)",
        payload,
        re.IGNORECASE
    )

    if match:

        char = match.group(1)
        value = int(match.group(2))

        candidates.extend([
            payload[:match.start()]
            + f"ASCII('{char}')={value + 1}"
            + payload[match.end():],

            payload[:match.start()]
            + f"ASCII('{char}')={value - 1}"
            + payload[match.end():]
        ])

    # ASCII >
    match = re.search(
        r"ASCII\('([^']+)'\)\s*>\s*(\d+)",
        payload,
        re.IGNORECASE
    )

    if match:

        char = match.group(1)
        value = match.group(2)

        candidates.append(
            payload[:match.start()]
            +
            f"ASCII('{char}')<{value}"
            +
            payload[match.end():]
        )

    return choose_result(
        payload,
        candidates,
        "boolean_no_effect"
    )


# ==========================================================
# CONTROLLED FAILURE SELECTION
# ==========================================================

def corrupt_for_failure(
    payload,
    payload_type,
    failure_type
):

    if failure_type == "malformed_syntax":

        return corrupt_malformed_syntax(
            payload
        )

    if failure_type == "incomplete_statement":

        return corrupt_incomplete_statement(
            payload
        )

    if failure_type == "logical_error":

        if payload_type != "boolean":
            return None

        return corrupt_logical_error(
            payload
        )

    if failure_type == "invalid_time_function":

        if payload_type != "time":
            return None

        return corrupt_invalid_time_function(
            payload
        )

    if failure_type == "boolean_no_effect":

        if payload_type != "boolean":
            return None

        return corrupt_boolean_no_effect(
            payload
        )

    return None


# ==========================================================
# RANDOM CORRUPTION
# ==========================================================

def corrupt_payload(
    payload,
    payload_type
):

    possible = []

    for failure_type in VALID_FAILURES:

        result = corrupt_for_failure(
            payload,
            payload_type,
            failure_type
        )

        if result:
            possible.append(result)

    if not possible:
        return None

    return random.choice(
        possible
    )
