"""Hermes-side adapter + Paperclip boundary mocks.

LABEL: COMPATIBILITY INTERFACE - UNVERIFIED against the real Hermes and the real Paperclip.
Neither system was inspected. No Paperclip endpoint, callback, webhook, schema or Hermes plugin API is assumed here:
`WorkSource` and `StatusSink` are *our* minimal Protocols, to be implemented against whatever the real systems expose
once that is verified (see docs/stage6-hermes-adapter.md and docs/stage6-paperclip-boundary.md).
Only the in-memory MOCK implementations below exist, and everything they produce is labelled MOCK.

Roles: Paperclip = work source / system of record, Hermes = orchestrator (this adapter), Builder = executor.
This module keeps no registry of its own: identity is derived (planner.derive_task_id) and state is re-read from the
Builder (reconcile). It never retries a paid execution.
"""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, List, Optional, Protocol

from .client import BuilderClient, BuilderClientError, _clean, request_fingerprint
from .gates import FounderDecision, SafeReviewer, apply_founder_gate
from .lifecycle import run_task
from .planner import plan_to_task

_SECRET = re.compile(r"sk-ant-[A-Za-z0-9_-]+|(?i:bearer)\s+\S+|(?i:api_key|token)=\S+")


def _safe(text: Any, limit: int = 200) -> str:
    return _clean(_SECRET.sub("[redacted]", str(text)), limit)


STATUS_FIELDS = ("work_item_id", "attempt", "task_id", "correlation_id", "pipeline_state", "mission_status", "outcome",
                 "provenance", "mock", "submission", "real_mission_completed", "deployment_authorized",
                 "founder_authorization_required", "failure", "reasons")


class WorkSource(Protocol):
    def get_plan(self, work_item_id: str) -> Any: ...


class StatusSink(Protocol):
    def report(self, update: Dict[str, Any]) -> None: ...


def status_update(result: Dict[str, Any], meta: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """The only thing sent back towards Paperclip: a small, sanitized, whitelisted status record (no artifact bytes,
    no headers, no tokens, no host names)."""
    merged = dict(result)
    merged.update(meta or {})
    out = {k: merged.get(k) for k in STATUS_FIELDS}
    f = out.get("failure")
    if isinstance(f, dict):
        out["failure"] = {"class": _safe(f.get("class"), 60), "code": _safe(f.get("code"), 80),
                          "message": _safe(f.get("message"), 120), "http_status": f.get("http_status")}
    out["reasons"] = [_safe(r) for r in (out.get("reasons") or [])][:10]
    out["label"] = "MOCK" if out.get("mock") else "REAL"
    return out


class MockPaperclip:
    """In-memory stand-in for Paperclip: holds work items and receives status updates. NOT a model of the real API."""

    label = "MOCK"

    def __init__(self, plans: Optional[Dict[str, Any]] = None):
        self.plans: Dict[str, Any] = dict(plans or {})
        self.updates: List[Dict[str, Any]] = []

    def get_plan(self, work_item_id: str) -> Any:
        if work_item_id not in self.plans:
            raise KeyError("unknown work item")
        return self.plans[work_item_id]

    def report(self, update: Dict[str, Any]) -> None:
        self.updates.append(dict(update))


def mock_plan(work_item_id: str, attempt: int, workspace: str, mode: str = "ok", **extra: Any) -> Dict[str, Any]:
    """A valid MOCK planner output (the MOCKMODE marker only means something to tests/mock_claude.py)."""
    plan: Dict[str, Any] = {"schema_version": "1", "work_item_id": work_item_id, "attempt": attempt,
                            "task_description": f"Build a tiny synthetic CSV schema checker. MOCKMODE:{mode}",
                            "workspace_reference": workspace}
    plan.update(extra)
    return plan


class HermesBuilderAdapter:
    """process(work_item_id): plan -> validate -> submit once -> track -> verify -> review -> operator gate -> status."""

    def __init__(self, client: BuilderClient, source: WorkSource, sink: Optional[StatusSink] = None,
                 acceptance: Optional[Callable[[Dict[str, bytes]], Dict[str, Any]]] = None,
                 reviewer: Optional[Any] = None):
        self.client, self.source, self.sink = client, source, sink
        self.acceptance, self.reviewer = acceptance, SafeReviewer(reviewer)

    def _emit(self, result: Dict[str, Any], meta: Dict[str, str]) -> Dict[str, Any]:
        if self.sink is not None:
            self.sink.report(status_update(result, meta))
        return result

    def _rejected(self, work_item_id: str, exc: BuilderClientError) -> Dict[str, Any]:
        res = {"task_id": None, "correlation_id": None, "submission": "NOT_SUBMITTED", "provenance": "UNVERIFIED",
               "mock": True, "pipeline_state": "BLOCKED", "outcome": "BLOCKED", "reasons": [exc.message],
               "failure": exc.as_failure(), "founder_authorization_required": True}
        return self._emit(apply_founder_gate(res), {"work_item_id": _clean(work_item_id, 48)})

    def process(self, work_item_id: str, founder: Optional[FounderDecision] = None) -> Dict[str, Any]:
        try:
            plan = self.source.get_plan(work_item_id)
        except Exception:   # noqa: BLE001 - the source is unverified; never leak its error text
            return self._rejected(work_item_id, BuilderClientError(
                "INFRASTRUCTURE", "WORK_ITEM_UNAVAILABLE", "the work item could not be read"))
        try:
            task, meta = plan_to_task(plan)
        except BuilderClientError as exc:
            return self._rejected(work_item_id, exc)
        res = run_task(self.client, task, meta["correlation_id"], self.acceptance, self.reviewer)
        return self._emit(apply_founder_gate(res, founder), meta)

    def reconcile(self, work_item_id: str) -> Dict[str, Any]:
        """After an ambiguous submission: ask the Builder what it knows about the derived task id (read-only)."""
        task, _ = plan_to_task(self.source.get_plan(work_item_id))
        return self.client.reconcile(task["task_id"], request_fingerprint(task))
