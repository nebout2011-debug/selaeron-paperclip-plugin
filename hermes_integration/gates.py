"""Reviewer contract (fail closed) and the operator gate (explicit, never implicit, never deploys anything).

Separation kept by construction:  Builder execution  ->  independent tests  ->  reviewer  ->  operator.
  * A successful build is not approval; passing tests do not replace review.
  * A reviewer that is missing, crashes, hangs or returns something malformed yields UNAVAILABLE -> REVIEW_BLOCKED.
  * A MOCK reviewer or MOCK operator decision can never produce a REAL mission status.
  * The operator gate only *records* a decision. It has no deploy, merge or promote capability at all
    (`deployment_authorized` is always False in what it returns).

LIMIT (honest): this code cannot authenticate a human. A decision whose provenance is "REAL" must come from a channel
Hermes can attribute to the operator; how Hermes would do that is UNKNOWN (see docs/stage6-reviewer-gates.md).
"""

from __future__ import annotations

import hmac
import os
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Protocol

from . import _security_core as core
from .client import _clean
from .lifecycle import ReviewVerdict

DECISIONS = ("APPROVED", "REJECTED", "UNAVAILABLE")
PROVENANCES = ("REAL", "MOCK", "NONE")
FOUNDER_DECISIONS = ("APPROVED", "REJECTED")


class Reviewer(Protocol):
    """Contract for any reviewer (mock now; a real one is BLOCKED/UNVERIFIED): review(context) -> ReviewVerdict.

    context = {"task_id", "provenance", "paths": [...], "files": {path: bytes}}  (artifacts are untrusted data)
    """

    def review(self, context: Dict[str, Any]) -> ReviewVerdict: ...


def validate_verdict(v: Any) -> ReviewVerdict:
    """Strict check of a reviewer's answer; raises ValueError for anything outside the contract."""
    if not isinstance(v, ReviewVerdict):
        raise ValueError("reviewer returned something that is not a ReviewVerdict")
    if v.decision not in DECISIONS or v.provenance not in PROVENANCES:
        raise ValueError("reviewer decision or provenance outside the contract")
    if v.decision == "UNAVAILABLE" and v.provenance != "NONE":
        raise ValueError("an unavailable reviewer cannot claim a provenance")
    if v.decision in ("APPROVED", "REJECTED") and v.provenance == "NONE":
        raise ValueError("a decision needs a provenance (REAL or MOCK)")
    if not isinstance(v.reasons, (tuple, list)) or len(v.reasons) > 20:
        raise ValueError("reasons must be a short list")
    return ReviewVerdict(v.decision, v.provenance, _clean(v.reviewer, 60), tuple(_clean(r) for r in v.reasons))


class SafeReviewer:
    """Wraps any reviewer so the pipeline can never be crashed, bypassed or misled by it (fail closed)."""

    def __init__(self, inner: Optional[Any]):
        self.inner = inner

    def review(self, context: Dict[str, Any]) -> ReviewVerdict:
        if self.inner is None:
            return ReviewVerdict("UNAVAILABLE", "NONE", "none", ("no reviewer is configured",))
        try:
            return validate_verdict(self.inner.review(context))
        except Exception:   # noqa: BLE001 - crash, hang-timeout wrapper, malformed verdict: all become UNAVAILABLE
            return ReviewVerdict("UNAVAILABLE", "NONE", "none", ("the reviewer failed or answered outside its contract",))


@dataclass(frozen=True)
class FounderDecision:
    decision: str            # APPROVED | REJECTED
    provenance: str          # REAL | MOCK
    actor: str = "unspecified"
    note: str = ""


def mock_founder(decision: str = "APPROVED") -> FounderDecision:
    """Test double. Always MOCK; it can never complete a real mission."""
    return FounderDecision(decision, "MOCK", "mock-founder", "simulated")


# ---- Stage 7J-B: the final decision must be cryptographically verified AT this boundary ---------------------------------
def result_digest(result: Dict[str, Any]) -> str:
    """Digest of exactly what a operator approves: identity, provenance, state and every artifact's path, size and SHA-256.
    Gate fields (mission_status, operator, status_update, connector) and volatile fields (durations, cost) are excluded, so the
    digest is the same before and after the decision. Raises ValueError for a result that cannot be canonicalized."""
    ver, builder = result.get("verification") or {}, result.get("builder") or {}
    arts = sorted(({"path": a.get("path"), "size": a.get("size"), "sha256": a.get("sha256")}
                   for a in (result.get("artifacts") or [])), key=lambda a: str(a["path"]))
    content = {"task_id": result.get("task_id"), "correlation_id": result.get("correlation_id"),
               "request_sha256": result.get("request_sha256"), "mission_id": result.get("mission_id"),
               "provenance": result.get("provenance"), "mock": result.get("mock") is True,
               "pipeline_state": result.get("pipeline_state"), "outcome": result.get("outcome"),
               "submission": result.get("submission"), "artifacts": arts,
               "verification": {"performed": ver.get("performed") is True, "sha256_verified": ver.get("sha256_verified") is True,
                                "passed": ver.get("passed") is True},
               "builder_state": builder.get("state"), "reasons": [str(r) for r in (result.get("reasons") or [])]}
    return core.sha256_hex(b"SELAERON-RESULT/1\n" + core.canonical(content))


def reviewer_digest(review: Dict[str, Any]) -> str:
    """Digest of the reviewer's verdict, so a decision binds the exact review the operator was shown."""
    content = {"decision": review.get("decision"), "provenance": review.get("provenance"), "reviewer": review.get("reviewer"),
               "reasons": [str(r) for r in (review.get("reasons") or [])]}
    return core.sha256_hex(b"SELAERON-REVIEW/1\n" + core.canonical(content))


_SEAL_KEY = os.urandom(32)      # per process, never stored or logged


def _seal(decision: str, provenance: str, actor: str, decision_id: str, task_id: str, digest: str) -> str:
    return hmac.new(_SEAL_KEY, core.canonical([decision, provenance, actor, decision_id, task_id, digest]), "sha256").hexdigest()


@dataclass(frozen=True)
class VerifiedFounderDecision(FounderDecision):
    """A operator decision whose signature, scope and freshness were verified by the final gate. Its seal is an HMAC over
    every decision field under a per-process key, so a caller-built object, or a copy with any field changed (e.g.
    dataclasses.replace flipping REJECTED to APPROVED), fails construction. (Honest limit: code running in the same process
    could still call _make_verified; the real boundary is that agents never hold a operator signing key.)"""
    decision_id: str = ""
    task_id: str = ""
    result_digest: str = ""
    seal: str = field(default="", repr=False, compare=False)

    def __post_init__(self) -> None:
        expected = _seal(self.decision, self.provenance, self.actor, self.decision_id, self.task_id, self.result_digest)
        if not isinstance(self.seal, str) or not hmac.compare_digest(self.seal, expected):
            raise ValueError("a verified founder decision can only be created by the final gate")


def _make_verified(decision: str, provenance: str, actor: str, decision_id: str, task_id: str,
                   digest: str) -> VerifiedFounderDecision:
    return VerifiedFounderDecision(decision, provenance, actor, "", decision_id, task_id, digest,
                                   _seal(decision, provenance, actor, decision_id, task_id, digest))


def _seal_valid(d: Any) -> bool:
    """Re-checked at the gate itself: exact type, and the seal recomputed from the fields as they are NOW (so a subclass that
    skips __post_init__, or an object edited after construction, is not mistaken for a verified decision)."""
    try:
        return (type(d) is VerifiedFounderDecision and isinstance(d.seal, str) and hmac.compare_digest(
            d.seal, _seal(d.decision, d.provenance, d.actor, d.decision_id, d.task_id, d.result_digest)))
    except (ValueError, TypeError):
        return False


def _bound_to(decision: VerifiedFounderDecision, result: Dict[str, Any]) -> bool:
    try:
        return decision.task_id == result.get("task_id") and decision.result_digest == result_digest(result)
    except ValueError:
        return False


def apply_founder_gate(result: Dict[str, Any], decision: Optional[FounderDecision] = None) -> Dict[str, Any]:
    """Return `result` plus the operator-gate outcome. Never raises, never deploys, never approves implicitly."""
    out = dict(result)
    state = result.get("pipeline_state")
    real_chain = state == "READY_FOR_FOUNDER" and result.get("provenance") == "REAL" and result.get("mock") is False
    mock_chain = state == "MOCK_READY_FOR_FOUNDER"
    gate: Dict[str, Any] = {"decision": None, "provenance": None, "actor": None}
    status = "NOT_AT_FOUNDER_GATE"
    verified = _seal_valid(decision)
    if decision is not None:
        if decision.decision not in FOUNDER_DECISIONS or decision.provenance not in ("REAL", "MOCK"):
            decision, status = None, "INVALID_FOUNDER_DECISION"
        else:
            gate = {"decision": decision.decision, "provenance": decision.provenance, "actor": _clean(decision.actor, 60)}
            if verified:
                gate["decision_id"] = decision.decision_id
    if status == "INVALID_FOUNDER_DECISION":
        pass
    elif verified and not _bound_to(decision, result):
        status = "DECISION_RESULT_MISMATCH"    # re-checked HERE: a decision for one result never decides another
    elif real_chain:
        if decision is None:
            status = "AWAITING_FOUNDER"
        elif decision.provenance != "REAL":
            status = "BLOCKED_PROVENANCE"      # a mock decision cannot stand in for the operator on a real chain
        elif not verified:
            status = "UNVERIFIED_FOUNDER_DECISION"   # a REAL decision without a verified signature establishes nothing
        else:
            status = "FOUNDER_APPROVED" if decision.decision == "APPROVED" else "FOUNDER_REJECTED"
    elif mock_chain:
        if decision is None:
            status = "MOCK_AWAITING_FOUNDER"
        elif decision.provenance == "REAL":
            status = "BLOCKED_PROVENANCE"      # a real decision cannot be attached to a simulated run
        else:
            status = "MOCK_ONLY_APPROVED" if decision.decision == "APPROVED" else "MOCK_ONLY_REJECTED"
    out.update(founder=gate, mission_status=status, deployment_authorized=False,
               real_mission_completed=(status == "FOUNDER_APPROVED" and not result.get("mock", True)))
    return out
