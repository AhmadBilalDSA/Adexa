import re
import json
import sys
import os

def parse_gdb_log(log_path):
    with open(log_path, "r", errors="ignore") as f:
        content = f.read()

    result = {
        "file": os.path.basename(log_path),
        "signal": None,
        "crash_address": None,
        "corrupted_registers": [],
        "stack_overflow_pattern": False,
        "registers": {},
        "pc": None
    }

    # 1. Extract signal (SIGBUS, SIGSEGV, etc.)
    signal_match = re.search(r"Program received signal (\w+)", content)
    if signal_match:
        result["signal"] = signal_match.group(1)

    # 2. Extract crash address after signal
    addr_match = re.search(r"0x([0-9A-Fa-f]{8,16}) in", content)
    if addr_match:
        result["crash_address"] = "0x" + addr_match.group(1)

    # 3. Extract registers
    reg_matches = re.findall(r"(x\d{1,2}|pc)\s+0x([0-9A-Fa-f]+)", content)
    for reg, value in reg_matches:
        result["registers"][reg] = "0x" + value
        # Detect corruption (AAAAAA = 0x41)
        if value.lower().startswith("41" * 4):  
            result["corrupted_registers"].append(reg)

    # 4. Extract PC register specifically
    if "pc" in result["registers"]:
        result["pc"] = result["registers"]["pc"]

    # 5. Stack overflow detection (repeated 0x41414141)
    if re.search(r"0x41414141", content):
        result["stack_overflow_pattern"] = True

    return result


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 crash_parser.py <gdb_log_file>")
        sys.exit(1)

    log_path = sys.argv[1]
    parsed = parse_gdb_log(log_path)

    print(json.dumps(parsed, indent=4))
