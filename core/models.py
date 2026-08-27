# core/models.py
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal, Optional
import json
import hashlib

Status = Literal["success", "fail", "crash", "timeout", "error"]

@dataclass
class CrashInfo:
    signal: Optional[str] = None
    crash_address: Optional[str] = None
    arch: Optional[str] = None
    registers: Dict[str, str] = field(default_factory=dict)

    def fingerprint(self) -> str:
        payload = {
            "signal": self.signal,
            "crash_address": self.crash_address,
            "arch": self.arch,
            "regs": {k: self.registers.get(k) for k in ("eip", "rip", "pc", "esp", "rsp")},
        }
        raw = json.dumps(payload, sort_keys=True).encode()
        return hashlib.sha256(raw).hexdigest()[:16]

@dataclass
class Observation:
    mode: Literal["binary", "web"]
    crash: Optional[CrashInfo] = None
    raw_log_path: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)

PatchActionType = Literal[
    "set_offset",
    "mutate_input",
    "change_payload_strategy",
    "retest",
    "advance_step",
    "goto_step_id",
    "mutate_step_query_param",
]

@dataclass
class PatchAction:
    type: PatchActionType
    value: Any = None

@dataclass
class PatchPlan:
    root_cause: str
    confidence: float
    actions: List[PatchAction]
    explanation: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

def validate_patch_plan(plan: PatchPlan) -> None:
    if not (0.0 <= float(plan.confidence) <= 1.0):
        raise ValueError("confidence must be between 0 and 1")
    if not plan.actions:
        raise ValueError("PatchPlan must have at least one action")
