# backends/binary_backend.py
from __future__ import annotations

import datetime
import os
from pathlib import Path
from typing import Any, Dict, Optional

from core.models import CrashInfo, Observation, PatchPlan, PatchAction
from utils.crash_parser import parse_gdb_crash
from ai_engine.crash_ai import analyze_crash


class BinaryBackend:
    """
    SAFE "binary" backend:
    - Observes a crash log
    - Uses AI as a bounded planner (need_more_info / inspect_more, etc.)
    - Re-tests by generating a fresh crash log each iteration
    - Declares success when we have a stable classification + no more actions needed

    IMPORTANT:
    This backend intentionally does NOT do offset finding, payload crafting,
    exploit rewriting, or control verification.
    """
    name = "binary"

    # -------------------------
    # 1) Observe crash log
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
    # 2) AI plan (brain)
    # -------------------------
    def ai_plan(self, obs: Observation, state: Dict[str, Any]) -> Optional[PatchPlan]:
        enriched = analyze_crash(obs.extra.get("report", {}))

        analysis: Dict[str, Any] = {}
        if isinstance(enriched, dict):
            a = enriched.get("analysis")
            if isinstance(a, dict):
                analysis = a
            else:
                analysis = enriched

        crash_type = str(analysis.get("crash_type", "unknown"))

        try:
            conf = float(analysis.get("confidence", 0.5))
        except Exception:
            conf = 0.5

        next_step = str(analysis.get("next_step", "inspect_more"))

        # SAFE action mapping:
        # - need_cyclic_pattern / have_offset are treated as "collect more evidence"
        #   (we DO NOT actually compute offsets here)
        actions = []

        # Always do at least one retest to ensure the crash is repeatable
        # and that logs are fresh per iteration.
        actions.append(PatchAction(type="retest", value=None))

        explanation = (
            f"ai_next_step={next_step}, "
            f"signal={obs.crash.signal}, addr={obs.crash.crash_address}"
        )

        return PatchPlan(
            root_cause=crash_type,
            confidence=conf,
            actions=actions,
            explanation=explanation,
        )

    # -------------------------
    # 3) Success condition
    # -------------------------
    def is_success(self, state: Dict[str, Any], obs: Observation) -> bool:
        """
        SAFE success rule for a crash triage tool:

        Success means:
        - We got a valid crash classification (root_cause not "unknown"), AND
        - We've retested at least once (repeatable), AND
        - The planner isn't asking for "inspect_more" anymore.

        This makes the loop "intentional": it stops when it has enough evidence,
        not by accident.
        """
        if not state.get("_retested_once"):
            return False

        last_plan = state.get("last_plan") or {}
        if isinstance(last_plan, dict):
            nxt = str(last_plan.get("ai_next_step", "inspect_more"))
        else:
            nxt = "inspect_more"

        # If still unsure, keep looping
        if nxt == "inspect_more":
            return False

        # If we have a meaningful crash type, we consider triage "done"
        crash_type = state.get("last_crash_type")
        if crash_type and crash_type != "unknown":
            return True

        return False

    # -------------------------
    # Helper: save log text
    # -------------------------
    def _save_text_log(self, prefix: str, text: str) -> str:
        os.makedirs("logs", exist_ok=True)
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        path = os.path.join("logs", f"{prefix}_{ts}.txt")
        with open(path, "w") as f:
            f.write(text)
        return path

    # -------------------------
    # 4) Execute plan actions
    # -------------------------
    def execute(self, plan: PatchPlan, state: Dict[str, Any]) -> Dict[str, Any]:
        """
        SAFE execute:
        - retest: regenerate a fresh crash log by re-running your existing initial crash method.
          We do NOT do exploit mutation or offsets here.

        IMPORTANT: This assumes main.py already created an initial crash log.
        For retest, we simply re-run the same mechanism your main.py uses:
        it generates a fresh crash log path and updates state["crash_log_path"].
        """

        # Store plan hints for is_success()
        # (we keep it small and explicit)
        state["last_crash_type"] = plan.root_cause
        state["last_plan"] = {
            "ai_next_step": plan.explanation.split(",")[0].replace("ai_next_step=", "").strip()
            if isinstance(plan.explanation, str) and "ai_next_step=" in plan.explanation
            else "inspect_more"
        }

        # Execute actions
        for act in plan.actions:
            if act.type == "retest":
                # Reuse your existing crash log generator by importing it from main
                # This avoids duplicating GDB logic here.
                from main import _fresh_initial_crash_log  # local import to avoid circulars

                binary_path = state.get("binary_path")
                if binary_path:
                    new_log = _fresh_initial_crash_log(binary_path)
                    state["crash_log_path"] = new_log
                    state["_retested_once"] = True

        return state
