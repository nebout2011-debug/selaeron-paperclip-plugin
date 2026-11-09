"""Lifecycle mapping, review gates and the end-to-end orchestration helper (stdlib only).

Builder states (actual, from app/models.py): QUEUED, RUNNING, TESTING, COMPLETED, FAILED, TIMED_OUT,
BLOCKED_SECURITY. The Builder never says IN_REVIEW or READY_FOR_FOUNDER; Hermes derives those here.

Hermes pipeline states: QUEUED, RUNNING, TESTING, IN_REVIEW, READY_FOR_FOUNDER, FAILED, BLOCKED, plus
REVIEW_BLOCKED (reviewer unavailable) and MOCK_READY_FOR_FOUNDER (a fully simulated run reached the end).

Hard rules:
  * Builder success is NOT approval: COMPLETED only opens the independent-acceptance and review gates.
  * READY_FOR_FOUNDER needs: builder provenance REAL + independent acceptance PASS + SHA-256 verified +
    a reviewer APPROVAL whose provenance is REAL. A mock reviewer approval never counts as real approval.
  * A simulated (MOCK) run can only ever end in MOCK_READY_FOR_FOUNDER, never READY_FOR_FOUNDER.
  * READY_FOR_FOUNDER means "waiting for the operator". Nothing here promotes, deploys or approves anything.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional, Tuple

from .client import (
    BLOCKING_CLASSES, SCHEMA_VERSION, TERMINAL, BuilderClient, BuilderClientError, _clean, provenance_of,
    request_fingerprint, safe_artifacts_to_list, validate_task,
)

HERMES_STATES = (
    "QUEUED", "RUNNING", "TESTING", "IN_REVIEW", "READY_FOR_FOUNDER", "FAILED", "BLOCKED",
    "REVIEW_BLOCKED", "MOCK_READY_FOR_FOUNDER",
)
OUTCOMES = ("PASS", "MOCK_PASS", "FAIL", "BLOCKED", "PENDING")
BUILDER_TO_HERMES = {
    "QUEUED": "QUEUED", "RUNNING": "RUNNING", "TESTING": "TESTING",
    "COMPLETED": "TESTING",          # build finished; independent acceptance still has to pass
    "FAILED": "FAILED", "TIMED_OUT": "FAILED", "BLOCKED_SECURITY": "BLOCKED",
}


def map_builder_state(state: str) -> str:
    """Unknown states fail closed to BLOCKED (never silently treated as progress)."""
    return BUILDER_TO_HERMES.get(state, "BLOCKED")


# ---- reviewers -------------------------------------------------------------------------------
@dataclass
class ReviewVerdict:
    decision: str                 # APPROVED | REJECTED | UNAVAILABLE
    provenance: str               # REAL | MOCK | NONE
    reviewer: str = "unspecified"
    reasons: Tuple[str, ...] = ()


class MockReviewer:
    """Test double. Its approval is labelled MOCK and can never produce READY_FOR_FOUNDER."""

    def __init__(self, decision: str = "APPROVED"):
        assert decision in ("APPROVED", "REJECTED")
        self.decision = decision

    def review(self, context: Dict[str, Any]) -> ReviewVerdict:
        return ReviewVerdict(self.decision, "MOCK", "mock-reviewer", ("simulated review",))


class UnavailableReviewer:
    """No real reviewer is connected (no Ollama or other reviewer has been integrated or verified)."""

    def review(self, context: Dict[str, Any]) -> ReviewVerdict:
        return ReviewVerdict("UNAVAILABLE", "NONE", "none", ("no reviewer is connected",))


# ---- gate evaluation -------------------------------------------------------------------------
def _res(state: str, outcome: str, failure_class: Optional[str] = None, reasons: Tuple[str, ...] = ()) -> Dict[str, Any]:
    assert state in HERMES_STATES and outcome in OUTCOMES
    return {"pipeline_state": state, "outcome": outcome, "failure_class": failure_class, "reasons": list(reasons)}


def evaluate_pipeline(builder: Dict[str, Any], verification: Optional[Dict[str, Any]] = None,
                      review: Optional[ReviewVerdict] = None) -> Dict[str, Any]:
    """Pure function: Builder record + independent verification + review verdict -> Hermes pipeline state."""
    state, prov = builder.get("state"), provenance_of(builder)
    if state not in BUILDER_TO_HERMES:
        return _res("BLOCKED", "BLOCKED", "INFRASTRUCTURE", ("unknown Builder state",))
    if state in ("QUEUED", "RUNNING", "TESTING"):
        return _res(map_builder_state(state), "PENDING")
    if state == "FAILED":
        return _res("FAILED", "FAIL", "BUILDER", ("the Builder reported FAILED",))
    if state == "TIMED_OUT":
        return _res("FAILED", "FAIL", "TIMEOUT", ("the Builder reported TIMED_OUT",))
    if state == "BLOCKED_SECURITY":
        return _res("BLOCKED", "BLOCKED", "SECURITY_BLOCKED", ("the Builder blocked the task by policy",))
    # COMPLETED: the build finished, nothing more is implied
    if not verification or not verification.get("performed"):
        return _res("TESTING", "PENDING", None, ("independent acceptance has not been performed",))
    if not verification.get("sha256_verified"):
        return _res("BLOCKED", "BLOCKED", "INFRASTRUCTURE", ("artifact integrity was not verified",))
    if not verification.get("passed"):
        return _res("FAILED", "FAIL", "TEST_FAILURE", ("independent acceptance did not pass",))
    if review is None:
        return _res("IN_REVIEW", "PENDING", None, ("awaiting reviewer",))
    if review.decision == "UNAVAILABLE":
        return _res("REVIEW_BLOCKED", "BLOCKED", "REVIEWER_FAILURE", ("no reviewer is available",))
    if review.decision == "REJECTED":
        return _res("FAILED", "FAIL", "REVIEWER_FAILURE", ("the reviewer rejected the result",))
    if review.decision != "APPROVED":
        return _res("BLOCKED", "BLOCKED", "REVIEWER_FAILURE", ("unrecognised reviewer decision",))
    if prov == "REAL" and review.provenance == "REAL":
        return _res("READY_FOR_FOUNDER", "PASS", None, ("founder authorization is still required to promote or deploy",))
    if prov == "REAL":
        return _res("IN_REVIEW", "PENDING", None, ("a mock reviewer approval does not count as real approval",))
    if prov == "MOCK":
        return _res("MOCK_READY_FOR_FOUNDER", "MOCK_PASS", None, ("simulation only: nothing here is real",))
    return _res("IN_REVIEW", "PENDING", None, ("Builder provenance is unverified; READY_FOR_FOUNDER is not reachable",))


# ---- orchestration ---------------------------------------------------------------------------
def _builder_view(rec: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not rec:
        return None
    claude = rec.get("claude") or {}
    return {
        "state": rec.get("state"), "error_category": rec.get("error_category"),
        "diagnostic_category": rec.get("diagnostic_category"), "diagnostic_evidence": rec.get("diagnostic_evidence"),
        "exit_code": rec.get("exit_code"), "duration_seconds": rec.get("duration_seconds"),
        "timeout_seconds": rec.get("timeout_seconds"), "artifact_count": rec.get("artifact_count"),
        "num_turns": claude.get("num_turns"),
        "cli_cost_estimate_usd": claude.get("cost_usd"),   # client-side estimate, never a bill
    }


Acceptance = Callable[[Dict[str, bytes]], Dict[str, Any]]


def run_task(client: BuilderClient, task: Dict[str, Any], correlation_id: Optional[str] = None,
             acceptance: Optional[Acceptance] = None, reviewer: Optional[Any] = None,
             download: bool = True) -> Dict[str, Any]:
    """Submit once, track, verify, review. Always returns a deterministic result dict; never auto-retries."""
    corr = client._corr(correlation_id)
    out: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION, "correlation_id": corr, "task_id": task.get("task_id"),
        "mission_id": task.get("mission_id"), "request_sha256": None, "provenance": "UNVERIFIED", "mock": True,
        "submission": "NOT_SUBMITTED", "builder": None, "artifacts": [], "verification": None, "review": None,
        "founder_authorization_required": True,
    }
    record: Optional[Dict[str, Any]] = None
    try:
        validate_task(task)
        out["request_sha256"] = request_fingerprint(task)
        sub = client.submit(task, corr)
        record = sub["record"]
        out["submission"] = "REPLAYED" if sub["replayed"] else "ACCEPTED"
        out["provenance"] = provenance_of(record)
        want = client.cfg.expect_provenance
        if want and provenance_of(record) != want:
            raise BuilderClientError("SECURITY_BLOCKED", "PROVENANCE_MISMATCH",
                                     f"expected {want} but the Builder reports {provenance_of(record)}",
                                     submission=out["submission"])
        if record["state"] not in TERMINAL:
            record = client.wait(task["task_id"], int(record.get("timeout_seconds") or 600), corr)
        out["builder"] = _builder_view(record)
        out["provenance"] = provenance_of(record)
        verification: Optional[Dict[str, Any]] = None
        review: Optional[ReviewVerdict] = None
        if record["state"] == "COMPLETED" and download:
            manifest = client.manifest(task["task_id"], corr)
            files = {e["path"]: client.download(task["task_id"], e, corr) for e in manifest["artifacts"]}
            out["artifacts"] = safe_artifacts_to_list(manifest["artifacts"], True)
            verification = {"performed": acceptance is not None, "sha256_verified": True, "passed": None, "detail": ""}
            if acceptance is not None:
                r = acceptance(files)
                verification["passed"], verification["detail"] = bool(r.get("passed")), _clean(r.get("detail", ""))
            out["verification"] = verification
            if verification["passed"] and reviewer is not None:
                review = reviewer.review({"task_id": task["task_id"], "provenance": out["provenance"],
                                          "paths": sorted(files), "files": files})
                out["review"] = {"decision": review.decision, "provenance": review.provenance,
                                 "reviewer": _clean(review.reviewer, 60), "reasons": [_clean(x) for x in review.reasons]}
        verdict = evaluate_pipeline(record, verification, review)
        out.update(pipeline_state=verdict["pipeline_state"], outcome=verdict["outcome"], reasons=verdict["reasons"],
                   failure=None if not verdict["failure_class"] else {
                       "class": verdict["failure_class"],
                       "code": _clean((record.get("diagnostic_category") or record.get("error_category") or "NONE")
                                      if verdict["failure_class"] == "BUILDER" else verdict["failure_class"]),
                       "message": _clean("; ".join(verdict["reasons"])), "http_status": None})
    except BuilderClientError as exc:
        out["builder"] = out["builder"] or _builder_view(record)
        if out["submission"] == "NOT_SUBMITTED":
            out["submission"] = exc.submission
        blocking = exc.failure_class in BLOCKING_CLASSES
        out.update(pipeline_state="BLOCKED" if blocking else "FAILED", outcome="BLOCKED" if blocking else "FAIL",
                   failure=exc.as_failure(), reasons=[exc.message])
    out["mock"] = out["provenance"] != "REAL"
    cls = (out.get("failure") or {}).get("class")
    out["retry"] = {"automatic": False, "safe_to_resubmit_same_id": cls == "BUSY" and out["submission"] == "NOT_SUBMITTED",
                    "note": "reconcile with GET before any resubmission" if out["submission"] == "UNKNOWN"
                    else "never retried automatically; a paid execution needs an explicit new decision"}
    return out
