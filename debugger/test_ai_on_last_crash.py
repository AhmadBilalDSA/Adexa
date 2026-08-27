# ~/ADEXA/debugger/test_ai_on_last_crash.py

import os
import glob
import sys

# Make ADEXA root importable when running from repo root
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from utils.crash_parser import parse_gdb_crash
from ai_engine.crash_ai import analyze_crash
from ai_engine.exploit_scorer import score_exploit


LOG_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "logs"))
EXPLOIT_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "exploit_tests", "exploit1.py"))


def get_latest_log():
    pattern = os.path.join(LOG_DIR, "gdb_crash_*.txt")
    files = sorted(glob.glob(pattern))
    if not files:
        print("[!] No crash logs found.")
        return None
    return files[-1]


def load_exploit_code(path):
    try:
        with open(path, "r") as f:
            return f.read()
    except FileNotFoundError:
        print(f"[!] Exploit file not found: {path}")
        return ""


if __name__ == "__main__":
    log_path = get_latest_log()
    if not log_path:
        sys.exit(1)

    print(f"[+] Using latest crash log: {log_path}\n")

    # Read the GDB output text
    with open(log_path, "r") as f:
        gdb_text = f.read()

    crash_report = parse_gdb_crash(gdb_text, binary_name=None)

    print("=== ADEXA Crash Analysis ===\n")
    print("Binary:    ", crash_report.get("binary"))
    print("Signal:    ", crash_report.get("signal"))
    print("Crash addr:", crash_report.get("crash_address"))
    print("Crash type:", crash_report.get("crash_type"))
    print("Arch:      ", crash_report.get("arch"))

    # AI explanation
    ai_result = analyze_crash(crash_report)

    print("\n--- AI INTERPRETATION ---")
    print(ai_result.get("summary", "No summary"))
    for s in ai_result.get("suggestions", []):
        print(" -", s)

    exploit_code = load_exploit_code(EXPLOIT_PATH)

    # Quality score
    quality = score_exploit(crash_report, exploit_code)

    print("\n=== EXPLOIT QUALITY SCORE ===")
    print(f"Score:   {quality['score']} / 100")
    print(f"Rating:  {quality['rating'].upper()}")

    if quality["issues"]:
        print("\nIssues:")
        for issue in quality["issues"]:
            print(" -", issue)

    if quality["suggestions"]:
        print("\nSuggestions:")
        for s in quality["suggestions"]:
            print(" -", s)

    print("\nDetails:", quality["details"])
