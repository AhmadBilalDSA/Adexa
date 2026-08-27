
# backends/web_backend.py
from __future__ import annotations

import datetime
import os
import re
import urllib.request
from http.cookies import SimpleCookie
from typing import Any, Dict, Optional, Tuple

from core.models import Observation, PatchPlan, PatchAction
from ai_engine.poc_ai import analyze_poc


def _join_url(base: str, path: str) -> str:
    base = (base or "").rstrip("/")
    if not path.startswith("/"):
        path = "/" + path
    return base + path


def _parse_set_cookies(resp) -> Dict[str, str]:
    """
    Collect cookies from Set-Cookie headers into a dict.
    Works even if multiple Set-Cookie headers exist.
    """
    out: Dict[str, str] = {}
    try:
        all_sc = resp.headers.get_all("Set-Cookie") or []
    except Exception:
        all_sc = []
        one = resp.headers.get("Set-Cookie")
        if one:
            all_sc = [one]

    for sc in all_sc:
        try:
            c = SimpleCookie()
            c.load(sc)
            for k, morsel in c.items():
                out[k] = morsel.value
        except Exception:
            pass
    return out


def _cookie_header(cookie_jar: Dict[str, str]) -> str:
    return "; ".join([f"{k}={v}" for k, v in cookie_jar.items() if k and v])


def _http_request(
    method: str,
    url: str,
    headers: Dict[str, str],
    body: Optional[str],
    cookie_jar: Optional[Dict[str, str]] = None,
) -> Tuple[int, Dict[str, str], str, Dict[str, str]]:
    """
    Returns: (status, response_headers_lower, response_text, updated_cookie_jar)
    """
    data = body.encode("utf-8") if body is not None else None
    hdrs_in = dict(headers or {})
    jar = dict(cookie_jar or {})

    # Attach Cookie header from jar unless caller already set one
    if jar and not any(k.lower() == "cookie" for k in hdrs_in.keys()):
        hdrs_in["Cookie"] = _cookie_header(jar)

    req = urllib.request.Request(url, data=data, method=method.upper())
    for k, v in hdrs_in.items():
        req.add_header(k, v)

    with urllib.request.urlopen(req, timeout=20) as resp:
        status = resp.getcode()
        resp_headers = {k.lower(): v for (k, v) in resp.headers.items()}
        text = resp.read().decode("utf-8", errors="ignore")
        new_cookies = _parse_set_cookies(resp)

    updated = dict(jar)
    updated.update(new_cookies)
    return status, resp_headers, text, updated


class WebBackend:
    name = "web"

    def observe(self, state: Dict[str, Any]) -> Observation:
        spec = state["poc_spec"]
        base_url = spec["base_url"]
        steps = spec.get("steps", [])

        # choose current step
        step_i = state.get("step_index", 0)
        if step_i >= len(steps):
            step_i = 0
        step = steps[step_i]

        method = step.get("method", "GET")
        path = step.get("path", "/")
        headers = step.get("headers", {}) or {}
        body = step.get("body", None)

        # cookie jar persistence
        cookie_jar = state.get("cookie_jar", {}) or {}

        # apply forced cookies (DVWA security level etc.)
        force_cookies = spec.get("force_cookies", {}) or {}
        for k, v in force_cookies.items():
            cookie_jar[str(k)] = str(v)

        # token substitution
        if isinstance(body, str) and "{{user_token}}" in body:
            tok = state.get("dvwa_user_token") or state.get("user_token") or ""
            body = body.replace("{{user_token}}", tok)

        url = _join_url(base_url, path)

        status = 0
        resp_headers: Dict[str, str] = {}
        resp_text = ""
        error = None

        try:
            status, resp_headers, resp_text, new_jar = _http_request(
                method=method,
                url=url,
                headers=headers,
                body=body,
                cookie_jar=cookie_jar,
            )

            # re-apply forced cookies even if server overwrites
            for k, v in force_cookies.items():
                new_jar[str(k)] = str(v)

            state["cookie_jar"] = new_jar

        except Exception as e:
            error = str(e)
            state["cookie_jar"] = cookie_jar

        # ✅ FIXED: more robust DVWA user_token extraction
        if step.get("id") == "get_login" and resp_text:
            # First find the input tag that contains name="user_token"
            m = re.search(
                r"<input[^>]*name\s*=\s*['\"]user_token['\"][^>]*>",
                resp_text,
                flags=re.IGNORECASE,
            )
            if m:
                tag = m.group(0)
                mv = re.search(
                    r"value\s*=\s*['\"]([^'\"]+)['\"]",
                    tag,
                    flags=re.IGNORECASE,
                )
                if mv:
                    state["user_token"] = mv.group(1)

        # Save raw response snippet (unique filename)
        os.makedirs("logs", exist_ok=True)
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        raw_path = f"logs/web_obs_{ts}.txt"
        with open(raw_path, "w") as f:
            f.write(resp_text[:8000])

        obs_payload = {
            "step_id": step.get("id"),
            "step_name": step.get("name"),
            "method": method,
            "path": path,
            "url": url,
            "status": status,
            "error": error,
            "cookie_jar": state.get("cookie_jar", {}),
            "user_token": state.get("user_token", None),
            "response_headers_subset": {
                k: resp_headers.get(k) for k in ("set-cookie", "location", "content-type")
            },
            "response_snippet": resp_text[:300],
        }

        # store last response for apply()/debug
        state["last_web_observation"] = obs_payload
        state["last_web_response_text"] = resp_text
        state["crash_log_path"] = raw_path

        return Observation(
            mode="web",
            crash=None,
            raw_log_path=raw_path,
            extra={"web": obs_payload},
        )

    def ai_plan(self, obs: Observation, state: Dict[str, Any]) -> Optional[PatchPlan]:
        """
        Never block the loop waiting for AI:
        - If ADEXA_NO_AI is on -> deterministic plan
        - If AI fails/slow -> deterministic fallback plan
        """
        if (os.environ.get("ADEXA_NO_AI", "") or "").strip().lower() in {"1", "true", "yes", "on"}:
            return PatchPlan(
                root_cause="ai_disabled",
                confidence=0.5,
                actions=[PatchAction(type="retest", value=None)],
                explanation="ADEXA_NO_AI is enabled; skipping Ollama.",
            )

        web_obs = (obs.extra or {}).get("web", {}) or {}

        # Try Ollama; if anything goes wrong, fallback without crashing/hanging the loop
        try:
            enriched = analyze_poc(web_obs)
            analysis = enriched.get("analysis", {}) if isinstance(enriched, dict) else {}
        except Exception as e:
            analysis = {
                "issue": "ai_exception",
                "confidence": 0.2,
                "next_step": "inspect_more",
                "key": None,
                "value": None,
                "explanation": f"AI failed: {e}",
            }

        next_step = (analysis.get("next_step") or "inspect_more")
        issue = analysis.get("issue", "unknown")

        try:
            conf = float(analysis.get("confidence", 0.5))
        except Exception:
            conf = 0.5
        conf = max(0.0, min(1.0, conf))

        actions: list[PatchAction] = []

        if next_step == "retry":
            actions.append(PatchAction(type="retest", value=None))

        elif next_step == "add_header":
            actions.append(
                PatchAction(
                    type="set_header",
                    value={"key": analysis.get("key"), "value": analysis.get("value")},
                )
            )
            actions.append(PatchAction(type="retest", value=None))

        elif next_step == "set_cookie":
            actions.append(PatchAction(type="set_cookie", value={"cookie": analysis.get("value")}))
            actions.append(PatchAction(type="retest", value=None))

        elif next_step == "set_method":
            actions.append(PatchAction(type="set_method", value={"method": analysis.get("value")}))
            actions.append(PatchAction(type="retest", value=None))

        elif next_step == "set_path":
            actions.append(PatchAction(type="set_path", value={"path": analysis.get("value")}))
            actions.append(PatchAction(type="retest", value=None))

        elif next_step == "set_body":
            actions.append(PatchAction(type="set_body", value={"body": analysis.get("value")}))
            actions.append(PatchAction(type="retest", value=None))

        elif next_step == "extract_token":
            actions.append(PatchAction(type="extract_token", value={"key": analysis.get("key")}))
            actions.append(PatchAction(type="retest", value=None))

        else:
            actions.append(PatchAction(type="retest", value=None))

        return PatchPlan(
            root_cause=str(issue),
            confidence=conf,
            actions=actions,
            explanation=f"web_ai_next_step={next_step} issue={issue}",
        )

    def apply(self, plan: PatchPlan, state: Dict[str, Any]) -> Dict[str, Any]:
        spec = state["poc_spec"]
        step_i = state.get("step_index", 0)
        step = spec["steps"][step_i]

        # apply safe edits to the current step
        for a in plan.actions:
            if a.type == "set_header":
                kv = a.value or {}
                k = kv.get("key")
                v = kv.get("value")
                if k and v:
                    step.setdefault("headers", {})
                    step["headers"][str(k)] = str(v)

            elif a.type == "set_cookie":
                kv = a.value or {}
                cookie = kv.get("cookie")
                if cookie:
                    step.setdefault("headers", {})
                    step["headers"]["Cookie"] = str(cookie)

            elif a.type == "set_method":
                kv = a.value or {}
                m = kv.get("method")
                if m:
                    step["method"] = str(m).upper()

            elif a.type == "set_path":
                kv = a.value or {}
                p = kv.get("path")
                if p:
                    step["path"] = str(p)

            elif a.type == "set_body":
                kv = a.value or {}
                b = kv.get("body")
                step["body"] = None if b is None else str(b)

            elif a.type == "extract_token":
                # Token extraction is handled in observe() for DVWA login step.
                state["extracted_token_note"] = "token_extraction_placeholder"

            elif a.type == "retest":
                pass

        state["poc_spec"] = spec
        state["last_plan"] = plan

        # advance step index
        steps = spec.get("steps", [])
        if steps:
            state["step_index"] = (state.get("step_index", 0) + 1) % len(steps)

        return state

    def is_success(self, state: Dict[str, Any], obs: Observation) -> bool:
        spec = state["poc_spec"]
        web_obs = (obs.extra or {}).get("web", {}) or {}
        snippet = (web_obs.get("response_snippet") or "").lower()

        success = spec.get("success", {}) or {}
        any_contains = success.get("any_step_contains", []) or []

        for needle in any_contains:
            if str(needle).lower() in snippet:
                return True

        return False
