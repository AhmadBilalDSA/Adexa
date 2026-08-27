import re

def parse_gdb_crash(gdb_text: str, binary_name=None):
    report = {
        "binary": binary_name,
        "signal": None,
        "crash_address": None,
        "crash_type": None,
        "arch": None,
        "registers": {}
    }

    # --- Detect signal ---
    sig_match = re.search(r"Program received signal ([A-Z0-9]+)", gdb_text)
    if sig_match:
        report["signal"] = sig_match.group(1)

    # --- Extract PC ---
    pc_match = re.search(r"\npc\s+0x([0-9a-fA-F]+)", gdb_text)
    if pc_match:
        pc = pc_match.group(1)
        report["crash_address"] = "0x" + pc

        # Detect PC controlled pattern (AAAA, BBBB, patterns)
        if pc.startswith("41" * 4) or pc.startswith("41" * 8):
            report["crash_type"] = "PC overwrite (controlled input)"
        else:
            report["crash_type"] = "Bad PC / invalid jump"

    # --- Detect architecture ---
    if "x0" in gdb_text and "sp" in gdb_text and "pc" in gdb_text:
        report["arch"] = "arm64"
    elif "eax" in gdb_text or "esp" in gdb_text:
        report["arch"] = "x86"
    elif "rax" in gdb_text or "rip" in gdb_text:
        report["arch"] = "x64"

    # --- Extract registers ---
    reg_matches = re.findall(r"([a-z0-9]+)\s+0x([0-9a-fA-F]+)", gdb_text)
    for reg, value in reg_matches:
        report["registers"][reg] = "0x" + value

    return report
