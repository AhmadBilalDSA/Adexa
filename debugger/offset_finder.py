# debugger/offset_finder.py
from __future__ import annotations

import os
import re
import sys
import subprocess
from typing import Optional, Tuple


# ---------- Debug helper ----------
def _debug(msg: str) -> None:
    # Turn on debug by setting: export ADEXA_DEBUG=1
    if os.environ.get("ADEXA_DEBUG", "").strip() in ("1", "true", "yes", "on"):
        print(msg, flush=True)


# ---------- 1) Generate a cyclic pattern ----------
def generate_pattern(length: int = 300) -> str:
    """
    Generate a cyclic pattern (similar concept to pwntools cyclic).
    Format: Aa0Aa1Aa2... across uppercase/lowercase/digits.
    """
    charset1 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    charset2 = "abcdefghijklmnopqrstuvwxyz"
    charset3 = "0123456789"

    out = []
    cur_len = 0
    for c1 in charset1:
        for c2 in charset2:
            for c3 in charset3:
                chunk = c1 + c2 + c3
                out.append(chunk)
                cur_len += 3
                if cur_len >= length:
                    return ("".join(out))[:length]
    return ("".join(out))[:length]


# ---------- 2) Run program with pattern via argv ----------
def run_pattern(binary: str, pattern: str, timeout: int = 25) -> str:
    """
    Run program under gdb with pattern as argv[1] (matches vuln1.c).
    Saves raw output to logs/pattern_debug.txt and returns gdb output text.

    IMPORTANT:
    Adds a timeout so ADEXA never hangs forever if GDB gets stuck.
    """
    log_dir = os.path.join(os.path.dirname(__file__), "../logs")
    os.makedirs(log_dir, exist_ok=True)
    raw_log_path = os.path.join(log_dir, "pattern_debug.txt")

    gdb_cmd = [
        "gdb",
        "-q",
        "-batch",
        "-ex", "set pagination off",
        "-ex", "handle SIGSEGV stop print",
        "-ex", "handle SIGBUS stop print",
        "-ex", "run",
        "-ex", "info registers",
        "-ex", "quit",
        "--args",
        binary,
        pattern,
    ]

    _debug("[DEBUG] GDB command: " + " ".join(gdb_cmd))

    gdb_text = ""
    try:
        output = subprocess.check_output(
            gdb_cmd,
            stderr=subprocess.STDOUT,
            timeout=timeout,
        )
        gdb_text = output.decode(errors="ignore")

    except subprocess.TimeoutExpired as e:
        # Capture partial output if any, and mark timeout
        partial = (e.output or b"").decode(errors="ignore")
        gdb_text = partial + "\n[!] GDB TIMEOUT: run_pattern exceeded timeout.\n"

    except subprocess.CalledProcessError as e:
        # Still capture output if gdb returns non-zero
        gdb_text = (e.output or b"").decode(errors="ignore")
        gdb_text += "\n[!] GDB ERROR: non-zero exit code.\n"

    except Exception as e:
        gdb_text = f"[!] run_pattern unexpected error: {e}\n"

    with open(raw_log_path, "w") as f:
        f.write(gdb_text)

    _debug(f"[DEBUG] Raw GDB output saved to: {raw_log_path}")
    return gdb_text


# ---------- 3) Extract crashed register (prefer x30, then pc) ----------
def extract_crash_register(gdb_output: str) -> Tuple[Optional[str], Optional[str]]:
    """
    For ARM64: x30 is the link register (return address), pc is program counter.
    We try x30 first because it’s often the saved return address in stack smash.
    """
    m = re.search(r"\bx30\s+0x([0-9A-Fa-f]+)\b", gdb_output)
    if m:
        return "x30", m.group(1)

    m = re.search(r"\bpc\s+0x([0-9A-Fa-f]+)\b", gdb_output)
    if m:
        return "pc", m.group(1)

    return None, None


# ---------- 4) Convert little-endian hex register value to ASCII ----------
def hex_to_ascii_little_endian(hex_str: str) -> str:
    """
    Example: 0x3964413864413764 -> bytes little-endian -> 'd7Ad8Ad9'
    """
    hex_str = str(hex_str).strip().lower().replace("0x", "")
    if not hex_str:
        return ""

    if len(hex_str) % 2 != 0:
        hex_str = "0" + hex_str

    try:
        val = int(hex_str, 16)
    except ValueError:
        return ""

    byte_len = len(hex_str) // 2
    b = val.to_bytes(byte_len, byteorder="little", signed=False)
    return b.decode(errors="ignore")


# ---------- 5) Find offset by matching a fragment in the pattern ----------
def find_offset(pattern: str, ascii_from_reg: str, min_frag: int = 3) -> Optional[int]:
    """
    Slide over ascii_from_reg and try to find any substring inside pattern.
    Returns the estimated offset or None.
    """
    if not pattern or not ascii_from_reg:
        return None

    n = len(ascii_from_reg)

    # Try longer fragments first
    for size in range(n, min_frag - 1, -1):
        for i in range(0, n - size + 1):
            frag = ascii_from_reg[i:i + size]
            if not frag.strip():
                continue
            pos = pattern.find(frag)
            if pos != -1:
                offset = pos - i
                if offset >= 0:
                    return offset

    return None


# ---------- 6) Main ----------
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 offset_finder.py <binary_path> [length] [timeout]")
        sys.exit(1)

    binary = sys.argv[1]

    length = 300
    if len(sys.argv) >= 3:
        try:
            length = int(sys.argv[2])
        except ValueError:
            pass

    timeout = 25
    if len(sys.argv) >= 4:
        try:
            timeout = int(sys.argv[3])
        except ValueError:
            pass

    print("[+] Generating cyclic pattern...")
    pattern = generate_pattern(length)

    print("[+] Running binary with pattern...")
    gdb_out = run_pattern(binary, pattern, timeout=timeout)

    print("[+] Extracting crash register...")
    reg_name, reg_hex = extract_crash_register(gdb_out)

    if not reg_name or not reg_hex:
        print("[!] Could not find x30 or pc in registers (no crash?)")
        print("[!] Check logs/pattern_debug.txt for details.")
        sys.exit(1)

    print(f"[+] Crashed register: {reg_name} = 0x{reg_hex}")

    ascii_from_reg = hex_to_ascii_little_endian(reg_hex)
    _debug(f"[DEBUG] ASCII from {reg_name} (little-endian): {repr(ascii_from_reg)}")

    print("[+] Searching for pattern fragment in cyclic pattern...")
    offset = find_offset(pattern, ascii_from_reg)

    if offset is not None:
        print(f"[+] Estimated offset to overwrite {reg_name} = {offset} bytes")
    else:
        print("[!] Could not detect offset from register value.")
        print("[!] Check logs/pattern_debug.txt.")
