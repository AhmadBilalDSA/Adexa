# ai_engine/crash_ai.py
from __future__ import annotations

import json
import os
import re
import urllib.request
from typing import Any, Dict, Optional


OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "qwen2.5:1.5b")

# Keep this small so the loop can't "freeze" for too long
OLLAMA_TIMEOUT = float(os.environ.get("OLLAMA_TIMEOUT", "30"))

# Optional: disable AI completely (demo-safe)
ADEXA_NO_AI = os.environ.get("ADEXA_NO_AI", "").strip() in ("1", "true", "yes")


def _post_json(url: str, payload: Dict[str, Any], timeout: float) -> Dict[str, Any]:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", errors="ignore"))


def _summarize_report(report: Dict[str, Any]) -> Dict[str, Any]:
    regs = report.get("registers") or {}

    # normalize keys to lowercase (pc vs PC issues)
    regs_norm: Dict[str, Any] = {}
    for k, v in regs.items():
        regs_norm[str(k).lower()] = v

    keep: Dict[str, Any] = {}
    for k in ("pc", "rip", "eip", "x30", "lr", "sp"):
        if k in regs_norm:
            keep[k] = regs_norm[k]

    return {
        "signal": report.get("signal"),
        "arch": report.get("arch"),
        "crash_address": report.get("crash_address"),
        "crash_type": report.get("crash_type"),
        "registers_subset": keep,
    }


def _looks_controlled(ip_value: Optional[str]) -> bool:
    """
    Very cheap heuristic: AAAA/BBBB-like overwrite often shows up as 0x414141.. or 0x424242..
    """
    if not ip_value:
        return False
    v = ip_value.lower()
    return ("414141" in v) or ("424242" in v) or ("616161" in v) or ("626262" in v)


def _fallback_plan(report: Dict[str, Any]) -> Dict[str, Any]:
    """
    If AI is disabled or slow, return a safe rule-based decision.
    """
    summary = _summarize_report(report)
    regs = summary.get("registers_subset") or {}

    # pick best "IP register" for messaging only
    ip_reg = None
    ip_val = None
    for k in ("pc", "rip", "eip", "x30", "lr"):
        if k in regs:
            ip_reg = k
            ip_val = str(regs.get(k))
            break

    if _looks_controlled(ip_val):
        return {
            "analysis": {
                "crash_type": str(summary.get("crash_type", "crash")),
                "confidence": 0.95,
                "next_step": "need_cyclic_pattern",
                "offset": None,
                "ip_register": ip_reg,
                "ip_value": ip_val,
                "explanation": "IP looks overwritten (AAAA/BBBB-like). Run cyclic pattern to calculate offset.",
            }
        }

    return {
        "analysis": {
            "crash_type": str(summary.get("crash_type", "crash")),
            "confidence": 0.6,
            "next_step": "inspect_more",
            "offset": None,
            "ip_register": ip_reg,
            "ip_value": ip_val,
            "explanation": "Not clearly controlled. Need more signal (different input or better crash context).",
        }
    }


def analyze_crash(report: Dict[str, Any]) -> Dict[str, Any]:
    """
    AI planner output (bounded + safe).
    If AI fails or is disabled, uses fallback rules.
    """
    if ADEXA_NO_AI:
        return _fallback_plan(report)

    summary = _summarize_report(report)
    regs = summary.get("registers_subset") or {}

    # tiny hint for model: what register looks like IP?
    ip_reg = None
    ip_val = None
    for k in ("pc", "rip", "eip", "x30", "lr"):
        if k in regs:
            ip_reg = k
            ip_val = str(regs.get(k))
            break

    payload = {
        "model": OLLAMA_MODEL,
        "prompt": (
            "Return ONLY valid JSON with this exact shape:\n"
            "{"
            "\"analysis\":{"
            "\"crash_type\":\"<string>\","
            "\"confidence\":<number 0..1>,"
            "\"next_step\":\"need_cyclic_pattern|have_offset|inspect_more\","
            "\"offset\":<integer or null>,"
            "\"ip_register\":\"<string or null>\","
            "\"ip_value\":\"<string or null>\","
            "\"explanation\":\"<short string>\""
            "}"
            "}\n"
            f"\nCrash report summary:\n{json.dumps(summary)}\n"
            f"\nHint: ip_register={ip_reg}, ip_value={ip_val}\n"
        ),
        "stream": False,
        "format": "json",
        "options": {
            "temperature": 0.0,
            "num_predict": 90,
        },
    }

    try:
        resp = _post_json(f"{OLLAMA_URL}/api/generate", payload, timeout=OLLAMA_TIMEOUT)

        # ollama returns JSON string in "response" (even with format=json)
        text = resp.get("response", "").strip()
        obj = json.loads(text) if text else {}

        analysis = obj.get("analysis", {})
        if not isinstance(analysis, dict):
            return _fallback_plan(report)

        next_step = analysis.get("next_step")
        if next_step not in ("need_cyclic_pattern", "have_offset", "inspect_more"):
            next_step = "inspect_more"

        # normalize confidence
        try:
            conf = float(analysis.get("confidence", 0.5))
        except Exception:
            conf = 0.5
        conf = max(0.0, min(1.0, conf))

        offset_val = analysis.get("offset", None)
        if isinstance(offset_val, str):
            try:
                offset_val = int(offset_val.strip())
            except Exception:
                offset_val = None
        if isinstance(offset_val, float):
            offset_val = int(offset_val) if offset_val.is_integer() else None
        if isinstance(offset_val, int) and offset_val < 0:
            offset_val = None

        # sanity rule
        if next_step == "have_offset" and offset_val is None:
            next_step = "inspect_more"

        return {
            "analysis": {
                "crash_type": str(analysis.get("crash_type", summary.get("crash_type", "crash"))),
                "confidence": conf,
                "next_step": next_step,
                "offset": offset_val,
                "ip_register": analysis.get("ip_register", ip_reg),
                "ip_value": analysis.get("ip_value", ip_val),
                "explanation": str(analysis.get("explanation", "AI-driven plan from crash observation.")),
            }
        }

    except Exception:
        # if AI stalls/fails: do NOT break the loop
        return _fallback_plan(report)


