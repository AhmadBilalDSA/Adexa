from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import unquote_plus


def _decode_payload(payload: str) -> str:
    return unquote_plus(str(payload or "")).strip()


def _normalize_payload(payload: str) -> str:
    p = _decode_payload(payload).lower()
    p = re.sub(r"\s+", " ", p).strip()
    return p


def _tokenize(payload: str) -> set[str]:
    p = _normalize_payload(payload)
    return set(re.findall(r"[a-zA-Z_]+|\d+|'.+?'|--|#|=|\(|\)", p))


def _detect_intent(payload: str) -> str:
    p = _normalize_payload(payload)

    if "sleep(" in p or "benchmark(" in p or "if(" in p:
        return "time_based"

    if "union" in p and "select" in p:
        return "union_based"

    if re.search(r"\b(and|or)\b", p) and re.search(r"(=|!=|<>|<|>)", p):
        return "boolean_based"

    return "unknown"


def _score_case(current_payload: str, current_intent: str, case: Dict[str, Any]) -> float:
    score = 0.0

    case_payload = str(case.get("payload") or "")
    case_intent = str(case.get("intent") or "unknown")

    cur_norm = _normalize_payload(current_payload)
    case_norm = _normalize_payload(case_payload)

    if not cur_norm or not case_norm:
        return 0.0

    if cur_norm == case_norm:
        score += 6.0

    cur_tokens = _tokenize(current_payload)
    case_tokens = _tokenize(case_payload)

    if cur_tokens and case_tokens:
        overlap = len(cur_tokens & case_tokens)
        score += overlap * 0.5

    if current_intent != "unknown" and case_intent == current_intent:
        score += 2.5

    if "if(" in cur_norm and "if(" in case_norm:
        score += 2.0

    if "sleep(" in cur_norm and "sleep(" in case_norm:
        score += 1.5

    cur_has_or = bool(re.search(r"\bor\b", cur_norm))
    cur_has_and = bool(re.search(r"\band\b", cur_norm))
    case_has_or = bool(re.search(r"\bor\b", case_norm))
    case_has_and = bool(re.search(r"\band\b", case_norm))

    if cur_has_or and case_has_or:
        score += 0.8
    if cur_has_and and case_has_and:
        score += 0.8

    if "'" in cur_norm and "'" in case_norm:
        score += 0.8
    if "'" not in cur_norm and "'" not in case_norm:
        score += 0.8

    return score


def _extract_verified_payload(data: Dict[str, Any]) -> str:
    state = data.get("state") or {}
    return str(state.get("verified_exploit_payload") or "").strip()


def _extract_strategy(data: Dict[str, Any]) -> str:
    state = data.get("state") or {}
    return str(state.get("strategy_used") or "").strip()


def load_repair_memory(
    current_payload: str,
    current_intent: str,
    runs_dir: str = "runs",
    limit: int = 3,
) -> List[Dict[str, Any]]:
    runs_path = Path(runs_dir)
    if not runs_path.exists():
        return []

    cases: List[Dict[str, Any]] = []

    for iter_file in runs_path.glob("*/iter_*.json"):
        try:
            data = json.loads(iter_file.read_text(encoding="utf-8"))
        except Exception:
            continue

        if not isinstance(data, dict):
            continue

        if data.get("event") != "stop":
            continue

        if data.get("reason") != "success":
            continue

        if data.get("verified") is not True:
            continue

        payload = _extract_verified_payload(data)
        if not payload:
            continue

        payload = _decode_payload(payload)
        if not payload:
            continue

        intent = _detect_intent(payload)

        case = {
            "payload": payload,
            "intent": intent,
            "strategy_used": _extract_strategy(data),
            "reason": str(data.get("reason") or ""),
            "verified": bool(data.get("verified")),
            "source_file": str(iter_file),
        }

        case["score"] = _score_case(current_payload, current_intent, case)
        cases.append(case)

    cases.sort(key=lambda x: x.get("score", 0.0), reverse=True)

    filtered: List[Dict[str, Any]] = []
    seen = set()

    for case in cases:
        score = float(case.get("score", 0.0) or 0.0)
        payload_norm = _normalize_payload(case.get("payload", ""))

        if score <= 0:
            continue
        if not payload_norm or payload_norm in seen:
            continue

        seen.add(payload_norm)
        filtered.append(case)

        if len(filtered) >= limit:
            break

    result: List[Dict[str, Any]] = []
    for c in filtered:
        result.append({
            "payload": c["payload"],
            "intent": c["intent"],
            "strategy_used": c["strategy_used"],
            "score": c["score"],
        })

    return result
