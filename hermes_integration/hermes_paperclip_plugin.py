"""Native Hermes plugin adapter for an approved, comment-only Paperclip test (issues configured via PAPERCLIP_APPROVED_ISSUES)."""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
from pathlib import Path
from typing import Any, Dict, Optional

from . import connector as _connector
from .paperclip import (
    check_base_url,
    urllib_transport,
    PaperclipRestSink,
    PaperclipWritebackTool,
    SYNTHETIC_TEST_APPROVAL,
    SYNTHETIC_TEST_ISSUE,
    SYNTHETIC_TEST_ISSUES,
    register_paperclip_writeback_tool,
)

# The multiplex gateway process does not load a profile's .env into os.environ, so read the two values
# this plugin needs from the profile's own .env into a LOCAL dict (never os.environ, never logged).
_PROFILE_ENV_KEYS = ("PAPERCLIP_API_URL", "PAPERCLIP_API_KEY")  # allowlist: nothing else is ever read
_PROFILE_ENV_PATH: Any = None  # tests override; None = derive from this file's location


def _profile_env_path() -> Optional[Path]:
    """<profile>/.env when deployed as <profile>/plugins/<plugin>/hermes_integration/<this file>, else None."""
    if _PROFILE_ENV_PATH is not None:
        return Path(_PROFILE_ENV_PATH)
    parents = Path(__file__).resolve().parents
    if len(parents) > 3 and parents[2].name == "plugins":
        return parents[3] / ".env"
    return None


def _config_env() -> Dict[str, str]:
    """A fresh dict: process environment, with missing PAPERCLIP_API_URL/KEY filled from the profile .env."""
    env = dict(os.environ)
    path = _profile_env_path()
    if path is None:
        return env
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return env
    for line in lines:
        key, sep, value = line.partition("=")
        key = key.strip()
        if sep and key in _PROFILE_ENV_KEYS and not env.get(key):
            env[key] = value.strip().strip("'\"")
    return env


RUN_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")
PLUGIN_NAME = "selaeron_paperclip_sel9_comment"
APPROVED_ISSUE = SYNTHETIC_TEST_ISSUE          # default / fallback label
APPROVED_ISSUES = SYNTHETIC_TEST_ISSUES        # every operator-approved comment-only test issue
_RUN_ID_MARKER = re.compile(r"(?mi)^\s*-\s*Run ID:\s*([A-Za-z0-9_-]{1,64})\s*$")


def _valid_run_id(value: Any) -> Optional[str]:
    if isinstance(value, str):
        value = value.strip()
        if value and RUN_ID_RE.fullmatch(value):
            return value
    return None


def _extract_run_id_from_text(text: Any) -> Optional[str]:
    if not isinstance(text, str) or not text.strip():
        return None
    match = _RUN_ID_MARKER.search(text)
    if not match:
        return None
    return _valid_run_id(match.group(1))


def _nested_run_id(value: Any, *, seen: Optional[set] = None) -> Optional[str]:
    if seen is None:
        seen = set()
    if id(value) in seen:
        return None
    seen.add(id(value))

    if isinstance(value, str):
        return _extract_run_id_from_text(value)
    if isinstance(value, dict):
        for key in ("paperclip_run_id", "paperclipRunId", "run_id", "runId",
                    "paperclip_run", "paperclipRun"):
            result = _valid_run_id(value.get(key))
            if result:
                return result
        for nested in value.values():
            result = _nested_run_id(nested, seen=seen)
            if result:
                return result
    if isinstance(value, (list, tuple)):
        for nested in value:
            result = _nested_run_id(nested, seen=seen)
            if result:
                return result
    return None


def _resolve_run_id(tool_context: Any, **runtime: Any) -> Optional[str]:
    explicit = _nested_run_id(tool_context)
    if explicit:
        return explicit

    for key in ("paperclip_run_id", "paperclipRunId", "paperclip_run", "paperclipRun"):
        result = _valid_run_id(runtime.get(key))
        if result:
            return result

    for key in ("user_task", "prompt", "task"):
        result = _extract_run_id_from_text(runtime.get(key))
        if result:
            return result
    return None


def _run_id(tool_context: Any = None, **runtime: Any) -> Optional[str]:
    return _resolve_run_id(tool_context, **runtime)


def _dedup_key(run_id: str, issue: str, summary: str) -> str:
    return hashlib.sha256(f"{run_id}\x00{issue}\x00{summary}".encode("utf-8")).hexdigest()


_SEEN: set = set()
_SEEN_LOCK = threading.Lock()


def _is_duplicate(key: str) -> bool:
    with _SEEN_LOCK:
        if key in _SEEN:
            return True
        _SEEN.add(key)
        return False


def _release_duplicate(key: str) -> None:
    with _SEEN_LOCK:
        _SEEN.discard(key)


def post_sel9_comment(*args: Any, tool_context: Any = None, issue: str = APPROVED_ISSUE,
                      **runtime: Any) -> Dict[str, Any]:
    """Post exactly one approved test comment and return a compact status."""

    # Hermes calls handlers as ``handler(args_dict, task_id=..., **context)``;
    # direct callers in tests may pass the summary as a positional string.
    # Accept both shapes without ever inventing a run ID.
    if args:
        if isinstance(args[0], dict):
            tool_context = tool_context if tool_context is not None else args[0]
            summary = args[0].get("summary")
        else:
            summary = args[0]
            if tool_context is None and len(args) > 1:
                tool_context = args[1]
    else:
        summary = runtime.pop("summary", None)

    if issue not in APPROVED_ISSUES:
        return {"status": "REJECTED", "code": "ISSUE_NOT_APPROVED"}
    if not (isinstance(summary, str) and summary.strip()):
        return {"status": "REJECTED", "code": "INVALID_SUMMARY"}

    run_id = _resolve_run_id(tool_context, summary=summary, **runtime)
    if not run_id:
        return {"status": "REJECTED", "code": "RUN_ID_MISSING"}

    env = _config_env()
    env["PAPERCLIP_SYNTHETIC_TEST_APPROVAL"] = SYNTHETIC_TEST_APPROVAL
    env["PAPERCLIP_RUN_ID"] = run_id
    key = _dedup_key(run_id, issue, summary.strip())
    if _is_duplicate(key):
        return {"status": "DUPLICATE", "code": "RUN_ID_REUSED", "issue": issue,
                "run_id": run_id, "comment_count": 0}

    try:
        tool = register_paperclip_writeback_tool(env=env, run_id=run_id)
    except Exception:
        _release_duplicate(key)
        return {"status": "REJECTED", "code": "AUTH_REJECTED_OR_CONFIG_ERROR",
                "issue": issue, "run_id": run_id, "comment_count": 0}

    sink = tool._sink
    if not isinstance(sink, PaperclipRestSink) or not sink._synthetic_test:
        _release_duplicate(key)
        return {"status": "REJECTED", "code": "SYNTHETIC_TEST_NOT_APPROVED",
                "issue": issue, "run_id": run_id, "comment_count": 0}

    try:
        tool.post_comment(issue, {"mock": False, "reasons": [summary.strip()[:240]]})
    except Exception:
        _release_duplicate(key)
        return {"status": "REJECTED", "code": "PUBLICATION_REJECTED",
                "issue": issue, "run_id": run_id, "comment_count": 0}
    return {"status": "ACCEPTED", "issue": issue, "run_id": run_id,
            "comment_count": 1}


def register(ctx: Any) -> None:
    """Register the native Hermes tool. ``ctx`` must provide ``register_tool``."""

    register_method = getattr(ctx, "register_tool", None)
    if not callable(register_method):
        raise _connector.ConnectorConfigError("Hermes tool registration context is unavailable")
    register_method(
        name=PLUGIN_NAME,
        toolset="selaeron_paperclip_sel9",
        description="Post one approved Paperclip test comment on the approved test issue that has the live run.",
        # Hermes schema shape: the registry adds "name"; "parameters" is the JSON schema.
        schema={
            "description": "Post one approved Paperclip test comment on the approved test issue that has the live run.",
            "parameters": {
                "type": "object",
                "properties": {
                    "summary": {
                        "type": "string",
                        "description": "Harmless synthetic result summary, at most 240 characters.",
                    },
                },
                "required": ["summary"],
                "additionalProperties": False,
            },
        },
        handler=hermes_handler,
        is_async=False,
    )


_LIVE_STATES = {"queued", "running"}
_lookup_transport = None  # tests inject a fake; None = real urllib transport


def lookup_live_run(env: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Read-only: ask Paperclip for the live run(s) of every approved test issue. Fail closed.

    Returns {"run_id": id, "issue": issue} only when exactly ONE live run exists across all approved issues,
    else {"code": ...}: RUN_ID_MISSING (none), RUN_ID_AMBIGUOUS (several, on one issue or across issues),
    LOOKUP_UNAVAILABLE (config/network/shape problem on any of the reads).
    """
    env = _config_env() if env is None else env
    try:
        base = check_base_url(env.get("PAPERCLIP_API_URL") or "", synthetic_test=True)
        token = env.get("PAPERCLIP_API_KEY") or ""
        if len(token) < 16:
            return {"code": "LOOKUP_UNAVAILABLE"}
        live = []
        for issue in APPROVED_ISSUES:
            status, _, raw = (_lookup_transport or urllib_transport)(
                "GET", f"{base}/api/issues/{issue}/live-runs", None,
                {"Authorization": "Bearer " + token, "Accept": "application/json"}, 5.0, 65536)
            runs = json.loads(raw)
            if status != 200 or not isinstance(runs, list):
                return {"code": "LOOKUP_UNAVAILABLE"}
            live += [(issue, r) for r in runs
                     if isinstance(r, dict) and str(r.get("status", "running")).lower() in _LIVE_STATES]
    except Exception:
        return {"code": "LOOKUP_UNAVAILABLE"}
    if not live:
        return {"code": "RUN_ID_MISSING"}
    if len(live) > 1:
        return {"code": "RUN_ID_AMBIGUOUS"}
    issue, run = live[0]
    run_id = _valid_run_id(run.get("id"))
    return {"run_id": run_id, "issue": issue} if run_id else {"code": "LOOKUP_UNAVAILABLE"}


def hermes_handler(args: Any, **_ignored: Any) -> str:
    """Hermes calls ``handler(args, task_id=, session_id=, user_task=)`` and needs a JSON *string*.

    Hermes does not forward the Paperclip run ID, so it is looked up read-only from Paperclip's live
    runs of the approved test issues. It NEVER comes from the model-controlled ``args``, the prompt or Hermes's ids.
    """
    summary = args.get("summary") if isinstance(args, dict) else None
    if not isinstance(summary, str):
        return json.dumps({"status": "REJECTED", "code": "INVALID_SUMMARY"})
    found = lookup_live_run()
    if "run_id" not in found:
        return json.dumps({"status": "REJECTED", "code": found["code"], "issue": APPROVED_ISSUE,
                           "comment_count": 0})
    return json.dumps(post_sel9_comment(summary, tool_context={"paperclip_run_id": found["run_id"]},
                                        issue=found["issue"]))