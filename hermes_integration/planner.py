"""Planner-output validation and deterministic task identity.

LABEL: PROPOSED CONTRACT. The real Planner and the real Paperclip work-item format are UNKNOWN (never inspected, no
endpoint is assumed). This module defines the *minimum* shape the Builder side needs, so that whatever the real planner
emits can be checked and mapped to a Builder request, and so that the same Paperclip work item always yields the same
Builder task id (stable identity -> idempotent resubmission without a database on the Hermes side).

Identity rule (deterministic, stdlib only):
    task_id        = first 32 hex chars of SHA-256("selaeron-labs/v1|" + work_item_id + "|" + str(attempt))
    correlation_id = "wi-" + work_item_id + "-a" + str(attempt)        (<= 64 chars, header-safe)
`attempt` only changes by an explicit human decision (a failed paid task is never re-run under the same attempt).
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, Tuple

from .client import (
    CAPABILITIES, BuilderClientError, build_task,
)

PLAN_SCHEMA_VERSION = "1"
NAMESPACE = "selaeron-labs/v1"
WORK_ITEM_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,47}$")
PLAN_KEYS = {"schema_version", "work_item_id", "attempt", "task_description", "workspace_reference", "mission_id",
             "execution_timeout", "requested_capabilities"}
REQUIRED = ("schema_version", "work_item_id", "attempt", "task_description", "workspace_reference")


def _bad(code: str, message: str):
    raise BuilderClientError("REQUEST_REJECTED", code, message)


def derive_task_id(work_item_id: str, attempt: int) -> str:
    if not isinstance(work_item_id, str) or not WORK_ITEM_RE.fullmatch(work_item_id):
        _bad("INVALID_PLAN_WORK_ITEM", "work_item_id must match [A-Za-z0-9][A-Za-z0-9._-]{0,47}")
    if isinstance(attempt, bool) or not isinstance(attempt, int) or not 1 <= attempt <= 99:
        _bad("INVALID_PLAN_ATTEMPT", "attempt must be an integer 1..99")
    return hashlib.sha256(f"{NAMESPACE}|{work_item_id}|{attempt}".encode("ascii")).hexdigest()[:32]


def correlation_id_for(work_item_id: str, attempt: int) -> str:
    derive_task_id(work_item_id, attempt)          # validates both
    return f"wi-{work_item_id}-a{attempt}"


def validate_plan(plan: Any) -> Dict[str, Any]:
    """Strict check of one planner output. Unknown keys, wrong types and executable-looking extras are refused."""
    if not isinstance(plan, dict):
        _bad("INVALID_PLAN", "planner output must be a JSON object")
    extra = sorted(set(plan) - PLAN_KEYS)
    if extra:
        _bad("INVALID_PLAN_UNKNOWN_FIELD", "planner output has fields the contract does not define: "
             + ", ".join(str(k)[:30] for k in extra))
    missing = [k for k in REQUIRED if k not in plan]
    if missing:
        _bad("INVALID_PLAN_MISSING_FIELD", "planner output is missing: " + ", ".join(missing))
    if plan["schema_version"] != PLAN_SCHEMA_VERSION:
        _bad("INVALID_PLAN_VERSION", f"unsupported plan schema_version (expected {PLAN_SCHEMA_VERSION})")
    derive_task_id(plan["work_item_id"], plan["attempt"])
    caps = plan.get("requested_capabilities", ["write_files"])
    if not isinstance(caps, list) or any(c not in CAPABILITIES for c in caps):
        _bad("INVALID_PLAN_CAPABILITIES", "requested_capabilities must be a list drawn from the Builder allow-list")
    return plan


def plan_to_task(plan: Any) -> Tuple[Dict[str, Any], Dict[str, str]]:
    """-> (Builder request, metadata kept on the Hermes side). The Builder never sees the work item id as a field."""
    plan = validate_plan(plan)
    task = build_task(
        task_description=plan["task_description"], workspace_reference=plan["workspace_reference"],
        task_id=derive_task_id(plan["work_item_id"], plan["attempt"]), mission_id=plan.get("mission_id"),
        execution_timeout=plan.get("execution_timeout"),
        requested_capabilities=tuple(plan.get("requested_capabilities", ["write_files"])))
    meta = {"work_item_id": plan["work_item_id"], "attempt": str(plan["attempt"]),
            "correlation_id": correlation_id_for(plan["work_item_id"], plan["attempt"])}
    return task, meta
