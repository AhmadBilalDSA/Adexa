# backends/binary_backend.py
from __future__ import annotations

import os
import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from core.models import CrashInfo, Observation, PatchPlan, PatchAction
from utils.crash_parser import parse_gdb_crash
from ai_engine.crash_ai import analyze_crash
from ai_engine.exploit_rewriter import rewrite_exploit

from debugger.offset_finder import (
    generate_pattern,
    run_pattern,
    extract_crash_register,
    hex_to_ascii_little_endian,
    find_offset,
)


def _looks_controlled(val: Optional[str]) -> bool:
    """
    Lab-safe heuristic: overwritten register looks like repeated bytes (AAAA/BBBB)
    which suggests controlled overwrite.
    """
    if not val:
        return False
    s = str(val).lower().replace("0x", "")

    # A = 0x41, B = 0x42
    if ("41" * 4) in s or ("41" * 6) in s:
        return True
    if ("42" * 4) in s or ("42" * 6) in s:
        return True

    # One byte repeated many times (0000..., ffff..., etc.)
    if len(s) >= 12:
        bytes_ = [s[i : i + 2] for i in range(0, len(s), 2) if i + 2 <= len(s)]
        if bytes_ and len(set(bytes_)) == 1:
            return True

    return False


class BinaryBackend:
    name = "binary"

    # -------------------------
    # Required by loop_controller.py
    # -------------------------
    def is_success(self, state: Dict[str, Any], obs: Observation) -> bool:
        """
        ONLY stop when we've verified control after patching.
        This prevents "early stop" just because offset was computed.
        """
        return bool(state.get("verified_offset"))

    # -------------------------
    # 1) Observe (read crash log)
    # -------------------------
    def observe(self, state: Dict[str, Any]) -> Observation:
        crash_log_path = state["crash_log_path"]
        raw = Path(crash_log_path).read_text(errors="replace")

        report = parse_gdb_crash(raw, binary_name=state.get("binary_name"))

        crash = CrashInfo(
            signal=report.get("signal"),
            crash_address=report.get("crash_address"),
            arch=report.get("arch"),
            registers=report.get("registers", {}) or {},
        )

        return Observation(
            mode="binary",
            crash=crash,
            raw_log_path=crash_log_path,
            extra={"report": report},
        )

    # -------------------------
    # 2) Plan (AI or fallback)
    # -------------------------
    def ai_plan(self, obs: Observation, state: Dict[str, Any]) -> Optional[PatchPlan]:
        # If AI is disabled, just do deterministic planning
        if os.environ.get("ADEXA_NO_AI") == "1":
            analysis: Dict[str, Any] = {
                "crash_type": "deterministic",
                "confidence": 1.0,
                "next_step": "inspect_more",
                "offset": None,
                "ip_register": None,
                "ip_value": None,
            }
        else:
            enriched = analyze_crash(obs.extra.get("report", {}))
            analysis = {}
            if isinstance(enriched, dict):
                a = enriched.get("analysis")
                analysis = a if isinstance(a, dict) else enriched

        crash_type = str(analysis.get("crash_type", "unknown"))
        try:
            conf = float(analysis.get("confidence", 0.5))
        except Exception:
            conf = 0.5

        next_step = analysis.get("next_step", "inspect_more")

        # Offset can come from AI OR from state
        offset = analysis.get("offset", None)
        if offset is None:
            offset = state.get("computed_offset")

        # Normalize offset
        try:
            if isinstance(offset, str):
                offset = int(offset.strip())
            elif isinstance(offset, float) and offset.is_integer():
                offset = int(offset)
        except Exception:
            offset = None
        if isinstance(offset, int) and offset < 0:
            offset = None

        # If we already computed an offset, force the next step to apply it
        if state.get("computed_offset") is not None:
            next_step = "have_offset"
            offset = state["computed_offset"]

        # Sanity rule: "have_offset" must include a real offset
        if next_step == "have_offset" and offset is None:
            next_step = "inspect_more"

        # Hard fallback: if registers look controlled and offset unknown => force cyclic
        regs = obs.crash.registers or {}
        pc_val = regs.get("pc") or regs.get("PC")
        x30_val = regs.get("x30") or regs.get("X30") or regs.get("lr") or regs.get("LR")
        controlled = _looks_controlled(pc_val) or _looks_controlled(x30_val)
        if controlled and offset is None:
            next_step = "need_cyclic_pattern"

        actions = []
        if next_step == "need_cyclic_pattern":
            if state.get("computed_offset") is None:
                actions.append(
                    PatchAction(
                        type="mutate_input",
                        value={"strategy": "cyclic_pattern", "length": 1200},
                    )
                )
            actions.append(PatchAction(type="retest", value=None))

        elif next_step == "have_offset":
            actions.append(PatchAction(type="set_offset", value=int(offset)))
            actions.append(PatchAction(type="retest", value=None))

        else:
            actions.append(PatchAction(type="retest", value=None))

        explanation = (
            f"ai_next_step={next_step}, ip={analysis.get('ip_register')}:{analysis.get('ip_value')}, "
            f"offset={offset}"
        )

        return PatchPlan(
            root_cause=crash_type,
            confidence=conf,
            actions=actions,
            explanation=explanation,
        )

    # -------------------------
    # Helper: save logs
    # -------------------------
    def _save_log(self, prefix: str, text: str) -> str:
        os.makedirs("logs", exist_ok=True)
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        path = os.path.join("logs", f"{prefix}_{ts}.txt")
        with open(path, "w") as f:
            f.write(text)
        return path

    # -------------------------
    # Helper: verification (lab-safe marker)
    # -------------------------
    def _verify_control(self, binary_path: str, offset: int) -> bool:
        """
        Lab-safe verification:
        Send A*offset + BBBBBBBB and check if x30/pc contains 0x42.. (BBBB).
        """
        marker = "A" * int(offset) + "B" * 8
        out = run_pattern(binary_path, marker)
        reg_name, reg_hex = extract_crash_register(out)
        if not reg_name or not reg_hex:
            return False
        # reg_hex is hex without 0x in your extractor
        hex_str = reg_hex.lower()
        return ("42" * 4) in hex_str or ("42" * 6) in hex_str

    # -------------------------
    # 3) Apply plan (loop_controller calls apply)
    # -------------------------
    def apply(self, plan: PatchPlan, state: Dict[str, Any]) -> Dict[str, Any]:
        return self.execute(plan, state)

    def execute(self, plan: PatchPlan, state: Dict[str, Any]) -> Dict[str, Any]:
        binary_path = state.get("binary_path")
        exploit_code = state.get("exploit_code", "")

        for act in plan.actions:
            if act.type == "mutate_input":
                strat = (act.value or {}).get("strategy")
                length = int((act.value or {}).get("length", 1200))

                if strat == "cyclic_pattern" and binary_path:
                    print(f"[+] Running cyclic pattern (len={length}) against: {binary_path}")

                    pattern = generate_pattern(length)
                    gdb_out = run_pattern(binary_path, pattern)
                    # store the new log so observe() reads the latest run
                    state["crash_log_path"] = self._save_log("gdb_crash_cyclic", gdb_out)

                    reg_name, reg_hex = extract_crash_register(gdb_out)
                    if not reg_name or not reg_hex:
                        state["computed_offset"] = None
                        continue

                    ascii_from_reg = hex_to_ascii_little_endian(reg_hex)
                    off = find_offset(pattern, ascii_from_reg)

                    if off is not None:
                        state["computed_offset"] = off
                        print(f"[+] Offset found: {off} bytes (from {reg_name})")
                    else:
                        state["computed_offset"] = None

            elif act.type == "set_offset":
                off = int(act.value)
                state["computed_offset"] = off
                exploit_code = rewrite_exploit(exploit_code, offset=off)
                state["exploit_code"] = exploit_code
                print(f"[+] Exploit patched with offset={off}")

            elif act.type == "retest":
                # If we have an offset, verify control and mark success
                off = state.get("computed_offset")
                if binary_path and isinstance(off, int):
                    ok = self._verify_control(binary_path, off)
                    state["verified_offset"] = bool(ok)
                    if ok:
                        print("[+] Verification passed: saw BBBB in control register (PC/x30).")
                    else:
                        print("[!] Verification failed (did not see BBBB in control register).")
                else:
                    state["verified_offset"] = False

        return state
