"""Stage 7G: Hermes -> Builder REAL-MODE CONNECTOR (stdlib only). REAL mode is DISABLED by default.

One structured plan + one explicit execution authorization in, one deterministic status object out.
It reuses the existing pieces (plan_to_task, BuilderClient, run_task, SafeReviewer, apply_founder_gate) and only adds
the boundary checks that were missing:

  * six separate permissions (inspect, prepare, execute, spend, deploy, approve_final) are never interchangeable; the
    connector needs `execute` AND `spend`, and `deploy` / `approve_final` can never be granted to it (they stay with the
    operator gate, which this module never calls with a decision);
  * the Builder endpoint must be on an explicit approved list; the token comes only from a token file (never from the
    plan, the config, the URL or an argument) and must not be group/world readable on POSIX;
  * MOCK mode needs an injected transport and can never open a connection; REAL mode needs `real_mode_enabled=true`,
    a REAL authorization and `expect_provenance="REAL"`. The mode is fixed at construction and is never inferred;
  * identity is derived (planner.derive_task_id: work item + explicit attempt, never a Paperclip run id). A read-only
    lookup runs before any POST: a known id is never POSTed again, a conflicting one is refused, a failed lookup sends
    nothing;
  * budget: the authorization carries a ceiling-checked budget and a timeout that must bound the plan's own
    `execution_timeout`; a Builder cost estimate above the authorized budget turns the result into BLOCKED. The Builder's
    own `--max-budget-usd` stays the real enforcement (its configured value is not visible through the API: UNKNOWN_REMOTE).

Everything here is IMPLEMENTED_LOCAL; nothing was run against a real Builder, Hermes or Paperclip.
"""

from __future__ import annotations

import json
import os
import re
import stat
import time
import urllib.parse
from dataclasses import dataclass, fields
from typing import Any, Callable, Dict, Optional, Tuple

from .adapter import _SECRET, status_update
from .client import (
    MAX_TIMEOUT, BuilderClient, BuilderClientError, ClientConfig, ConfigError, Transport, _clean, request_fingerprint,
    validate_config,
)
from .gates import SafeReviewer, apply_founder_gate
from .lifecycle import run_task
from .planner import plan_to_task

MODES = ("MOCK", "REAL")
# Stage 7J-A: REAL mode is locked in the code itself, in addition to `real_mode_enabled` being false by default. The secure
# construction path exists (guarded https transport + operator authorization + request signing), but nothing may use it until a
# separate, explicit operator-approved change flips this constant. Tests flip it only to prove the construction path.
REAL_MODE_LOCKED = True
PERMISSIONS = ("inspect", "prepare", "execute", "spend", "deploy", "approve_final")
NEVER_GRANTABLE = ("deploy", "approve_final")
BUDGET_CEILING_USD = 2.0            # equals the Builder's default BUILDER_MAX_BUDGET_USD; raising it is a operator decision
MAX_AUTH_TTL_SECONDS = 24 * 3600
AUTH_KEYS = {"schema_version", "work_item_id", "attempt", "request_sha256", "provenance", "permissions",
             "max_budget_usd", "max_execution_seconds", "approved_by", "expires_at"}
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class ConnectorConfigError(ConfigError):
    """Unsafe or inconsistent connector configuration: nothing is constructed, nothing is sent."""


class RealModeLocked(ConnectorConfigError):
    """REAL mode was requested while the code-level lock is closed."""


def _reject(code: str, message: str):
    raise BuilderClientError("REQUEST_REJECTED", code, message)


def _origin(url: str) -> str:
    u = urllib.parse.urlsplit(url)
    try:
        port = u.port
    except ValueError:
        raise ConnectorConfigError("endpoint has an invalid port") from None
    if (u.scheme not in ("http", "https") or not u.hostname or u.username or u.password or u.query or u.fragment
            or u.path not in ("", "/")):
        raise ConnectorConfigError("endpoint must be exactly scheme://host[:port]")
    return f"{u.scheme}://{u.hostname.lower()}" + (f":{port}" if port else "")


def _check_token_file(path: str) -> None:
    try:
        st = os.lstat(path)
    except OSError:
        raise ConnectorConfigError("token file is not readable") from None
    if not stat.S_ISREG(st.st_mode) or not 0 < st.st_size <= 512:
        raise ConnectorConfigError("token file must be a small regular file (no link, not empty)")
    if os.name == "posix" and st.st_mode & 0o077:
        raise ConnectorConfigError("token file permissions are too open (needs 0600)")


@dataclass(frozen=True)
class ConnectorConfig:
    client: ClientConfig
    mode: str = "MOCK"
    real_mode_enabled: bool = False
    approved_endpoints: Tuple[str, ...] = ()
    private_transport: Optional[Dict[str, Any]] = None      # {"enabled": bool, "allowed_origins": [https origins]}
    security: Optional[Dict[str, Any]] = None               # file paths and ids only; never a secret value


_SECURITY_KEYS = {"founder_registry_file", "request_hmac_file", "request_hmac_key_id", "founder_authorization_file",
                  "environment", "expected_builder_cap_usd"}


def _optional_sections(raw: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    pt, sec = raw.get("private_transport"), raw.get("security")
    if pt is not None:
        if (not isinstance(pt, dict) or set(pt) - {"enabled", "allowed_origins"} or not isinstance(pt.get("enabled", False), bool)
                or not isinstance(pt.get("allowed_origins", []), list)
                or not all(isinstance(o, str) for o in pt.get("allowed_origins", []))):
            raise ConnectorConfigError("private_transport must be {enabled: bool, allowed_origins: [https origins]}")
    if sec is not None:
        if (not isinstance(sec, dict) or set(sec) != _SECURITY_KEYS
                or not all(isinstance(sec[k], str) and sec[k] for k in _SECURITY_KEYS - {"expected_builder_cap_usd"})
                or isinstance(sec["expected_builder_cap_usd"], bool)
                or not isinstance(sec["expected_builder_cap_usd"], (int, float)) or not 0 < sec["expected_builder_cap_usd"] <= 2
                or sec["environment"] not in ("MOCK", "STAGING", "PRODUCTION")):
            raise ConnectorConfigError("security must name its files, key id, environment and builder cap exactly (no secrets)")
    return pt, sec


def load_connector_config(path: str) -> ConnectorConfig:
    """Strict JSON loader: unknown keys, a literal token and token_env are refused."""
    with open(path, "r", encoding="utf-8") as fh:
        raw = json.load(fh)
    top = {"mode", "real_mode_enabled", "approved_endpoints", "client", "private_transport", "security"}
    if not isinstance(raw, dict) or set(raw) - top or not isinstance(raw.get("client"), dict):
        raise ConnectorConfigError("connector config must be an object with mode, real_mode_enabled, "
                                   "approved_endpoints and client only")
    allowed = {f.name for f in fields(ClientConfig)} - {"token_env"}
    extra = sorted(set(raw["client"]) - allowed)
    if extra:
        raise ConnectorConfigError("unknown or forbidden client keys: " + ", ".join(_clean(k, 40) for k in extra))
    ends = raw.get("approved_endpoints", [])
    if not isinstance(ends, list) or not all(isinstance(e, str) for e in ends):
        raise ConnectorConfigError("approved_endpoints must be a list of strings")
    if "base_url" not in raw["client"]:
        raise ConnectorConfigError("client.base_url is required")
    pt, sec = _optional_sections(raw)
    return ConnectorConfig(client=ClientConfig(**raw["client"]), mode=raw.get("mode", "MOCK"),
                           real_mode_enabled=raw.get("real_mode_enabled", False) is True,
                           approved_endpoints=tuple(ends), private_transport=pt, security=sec)


def check_authorization(auth: Any, meta: Dict[str, str], fingerprint: str, mode: str, now: float) -> Dict[str, Any]:
    """Validate one execution authorization against the exact plan; raises BuilderClientError (REQUEST_REJECTED)."""
    if auth is None:
        _reject("AUTHORIZATION_MISSING", "no execution authorization was supplied")
    if not isinstance(auth, dict) or set(auth) != AUTH_KEYS:
        _reject("AUTHORIZATION_INVALID", "authorization must contain exactly the documented fields")
    perms = auth["permissions"]

    def num(v: Any) -> bool:
        return isinstance(v, (int, float)) and not isinstance(v, bool)

    def integer(v: Any) -> bool:
        return isinstance(v, int) and not isinstance(v, bool)

    if (auth["schema_version"] != "1" or not isinstance(auth["work_item_id"], str) or not integer(auth["attempt"])
            or not isinstance(auth["request_sha256"], str) or not isinstance(auth["provenance"], str)
            or not isinstance(perms, dict) or set(perms) != set(PERMISSIONS)
            or not all(isinstance(v, bool) for v in perms.values()) or not num(auth["max_budget_usd"])
            or not integer(auth["max_execution_seconds"]) or not isinstance(auth["approved_by"], str)
            or not integer(auth["expires_at"])):
        _reject("AUTHORIZATION_INVALID", "authorization has a wrong type or an unsupported schema_version")
    if (auth["work_item_id"] != meta["work_item_id"] or auth["attempt"] != int(meta["attempt"])
            or auth["request_sha256"] != fingerprint):
        _reject("AUTHORIZATION_MISMATCH", "authorization does not cover this exact work item, attempt and request")
    if auth["provenance"] != mode:
        _reject("AUTHORIZATION_PROVENANCE_MISMATCH",
                f"a {_clean(auth['provenance'], 8)} authorization cannot drive a {mode} run")
    if any(perms[p] for p in NEVER_GRANTABLE):
        _reject("AUTHORIZATION_UNSUPPORTED_PERMISSION", "deploy and final approval are never granted to the connector")
    if not perms["execute"]:
        _reject("EXECUTE_NOT_AUTHORIZED", "permission to execute was not granted")
    if not perms["spend"]:
        _reject("SPEND_NOT_AUTHORIZED", "permission to spend was not granted")
    if auth["max_budget_usd"] <= 0:
        _reject("BUDGET_INVALID", "max_budget_usd must be positive")
    if auth["max_budget_usd"] > BUDGET_CEILING_USD:
        _reject("BUDGET_EXCEEDS_CEILING", f"max_budget_usd exceeds the connector ceiling of {BUDGET_CEILING_USD:g}")
    if not 1 <= auth["max_execution_seconds"] <= MAX_TIMEOUT:
        _reject("TIMEOUT_INVALID", f"max_execution_seconds must be 1..{MAX_TIMEOUT}")
    if not auth["approved_by"] or _clean(auth["approved_by"], 60) != auth["approved_by"]:
        _reject("AUTHORIZATION_INVALID", "approved_by must be short printable text")
    if auth["expires_at"] <= now:
        _reject("AUTHORIZATION_EXPIRED", "the authorization has expired")
    if auth["expires_at"] > now + MAX_AUTH_TTL_SECONDS:
        _reject("AUTHORIZATION_TTL_TOO_LONG", "an authorization may be valid for at most 24 hours")
    return {"approved_by": auth["approved_by"], "work_item_id": auth["work_item_id"], "attempt": auth["attempt"],
            "max_budget_usd": float(auth["max_budget_usd"]), "max_execution_seconds": auth["max_execution_seconds"],
            "permissions_used": ["execute", "spend"]}


class _KnownTaskClient:
    """Delegates to the real client, but answers submit() from a record that already exists: no POST for a known id."""

    def __init__(self, client: BuilderClient, record: Dict[str, Any], fingerprint: str):
        self._c, self._record, self._fp = client, record, fingerprint

    def submit(self, task: Dict[str, Any], correlation_id: Optional[str] = None) -> Dict[str, Any]:
        return {"record": self._record, "replayed": True, "correlation_id": self._c._corr(correlation_id),
                "request_sha256": self._fp}

    def __getattr__(self, name: str) -> Any:
        return getattr(self._c, name)


def _safe_acceptance(fn: Optional[Callable[[Dict[str, bytes]], Dict[str, Any]]]):
    if fn is None:
        return None

    def wrapped(files: Dict[str, bytes]) -> Dict[str, Any]:
        try:
            r = fn(files)
            return r if isinstance(r, dict) else {"passed": False, "detail": "acceptance answered outside its contract"}
        except Exception:   # noqa: BLE001 - a crashing acceptance check must fail closed, never pass
            return {"passed": False, "detail": "the acceptance check failed to run"}
    return wrapped


class Connector:
    def __init__(self, config: ConnectorConfig, transport: Optional[Transport] = None, reviewer: Optional[Any] = None,
                 acceptance: Optional[Callable[[Dict[str, bytes]], Dict[str, Any]]] = None,
                 now: Callable[[], float] = time.time, sleep: Callable[[float], None] = time.sleep,
                 security: Optional[Any] = None):
        c = config.client
        if config.mode not in MODES:
            raise ConnectorConfigError("mode must be MOCK or REAL")
        if not config.approved_endpoints:
            raise ConnectorConfigError("no approved Builder endpoint is configured")
        approved = {_origin(e) for e in config.approved_endpoints}
        validate_config(c)
        if _origin(c.base_url) not in approved:
            raise ConnectorConfigError("the Builder endpoint is not on the approved list")
        if c.token_env or not c.token_file:
            raise ConnectorConfigError("a token file is required; token_env is not accepted")
        _check_token_file(c.token_file)
        if config.mode == "MOCK":
            if config.real_mode_enabled:
                raise ConnectorConfigError("MOCK mode cannot be combined with real_mode_enabled")
            if transport is None:
                raise ConnectorConfigError("MOCK mode needs an injected transport and never opens a connection")
            if c.expect_provenance != "MOCK":
                raise ConnectorConfigError("MOCK mode requires expect_provenance MOCK")
        else:
            if REAL_MODE_LOCKED:
                raise RealModeLocked("REAL mode is operationally disabled: it is locked in this build (Stage 7J-A)")
            if not config.real_mode_enabled:
                raise ConnectorConfigError("REAL mode is disabled (real_mode_enabled is false)")
            if c.expect_provenance != "REAL":
                raise ConnectorConfigError("REAL mode requires expect_provenance REAL")
            if urllib.parse.urlsplit(c.base_url).scheme != "https":
                raise ConnectorConfigError("REAL mode requires an https Builder endpoint (no plain HTTP, no loopback exception)")
            # No default transport is ever built for REAL: the caller must inject the guarded private https transport.
            if getattr(transport, "guarded", False) is not True or getattr(transport, "https_only", False) is not True:
                raise ConnectorConfigError("REAL mode requires the guarded private https transport; "
                                           "an unguarded or non-https transport is refused")
            if security is None:
                raise ConnectorConfigError("REAL mode requires a founder-authorization and request-signing security context")
        self.security = security
        self.cfg, self._now, self._injected = config, now, transport is not None
        self.client = BuilderClient(c, transport=transport, sleep=sleep)
        self.reviewer, self.acceptance = SafeReviewer(reviewer), _safe_acceptance(acceptance)

    # -- public ----------------------------------------------------------------------------------
    def run(self, plan: Any, authorization: Any) -> Dict[str, Any]:
        """Never raises. There is deliberately no operator-decision parameter: approval is a separate human step."""
        meta: Dict[str, str] = {}
        auth: Optional[Dict[str, Any]] = None
        task_id: Optional[str] = None
        submitting = False
        try:
            task, meta = plan_to_task(plan)
            task_id = task["task_id"]
            if _CTRL.search(task["task_description"]) or _SECRET.search(task["task_description"]):
                _reject("INVALID_DESCRIPTION", "task_description has control characters or credential-like text")
            fp = request_fingerprint(task)
            auth = check_authorization(authorization, meta, fp, self.cfg.mode, self._now())
            t = task.get("execution_timeout")
            if t is None:
                _reject("TIMEOUT_NOT_BOUNDED", "the plan must set execution_timeout so the spend window is bounded")
            if t > auth["max_execution_seconds"]:
                _reject("TIMEOUT_EXCEEDS_AUTHORIZATION", "execution_timeout is longer than the authorization allows")
            if self.cfg.mode == "REAL":                # operator authorization is verified BEFORE any request, lookups included
                self.security.preflight(task, fp, meta["correlation_id"], self._now())
            self.client._token()                       # token file readable and well-formed, before any request
            known = self._lookup(task_id, fp)
            client = _KnownTaskClient(self.client, known, fp) if known else self.client
            submitting = True
            res = run_task(client, task, meta["correlation_id"], self.acceptance, self.reviewer)
            res = self._post_checks(res, auth)
        except BuilderClientError as exc:
            res = self._rejected(task_id, meta, exc)
        except ConfigError:
            res = self._rejected(task_id, meta, BuilderClientError(
                "AUTHENTICATION", "TOKEN_UNAVAILABLE", "the integration token file is missing or malformed"))
        except Exception:   # noqa: BLE001 - fail closed on anything unexpected; no exception text is ever forwarded
            res = self._rejected(task_id, meta, BuilderClientError(
                "INFRASTRUCTURE", "UNEXPECTED_ERROR", "unexpected connector error"),
                submission="UNKNOWN" if submitting else "NOT_SUBMITTED")
        return self._wrap(res, meta, auth)

    # -- internals -------------------------------------------------------------------------------
    def _lookup(self, task_id: str, fingerprint: str) -> Optional[Dict[str, Any]]:
        """Read-only GET before any POST. A failure here propagates: nothing is sent when existence is unknown."""
        r = self.client.reconcile(task_id, fingerprint)
        if not r["known"]:
            return None
        if not r["same_request"]:
            raise BuilderClientError(
                "ID_CONFLICT", "TASK_ID_REUSED_WITH_DIFFERENT_REQUEST",
                "this task id already exists for a different request; a new attempt is a human decision")
        return r["record"]

    @staticmethod
    def _block(res: Dict[str, Any], failure_class: str, code: str, message: str) -> Dict[str, Any]:
        out = dict(res)
        out.update(pipeline_state="BLOCKED", outcome="BLOCKED", reasons=[message], founder_authorization_required=True,
                   failure={"class": failure_class, "code": code, "message": message, "http_status": None})
        return out

    def _post_checks(self, res: Dict[str, Any], auth: Dict[str, Any]) -> Dict[str, Any]:
        if self.cfg.mode == "MOCK" and res.get("provenance") == "REAL":
            return self._block(res, "SECURITY_BLOCKED", "MODE_MISMATCH", "a MOCK run reported REAL provenance")
        cost = (res.get("builder") or {}).get("cli_cost_estimate_usd")
        if isinstance(cost, (int, float)) and not isinstance(cost, bool) and cost > auth["max_budget_usd"]:
            return self._block(res, "SECURITY_BLOCKED", "BUDGET_EXCEEDED_ESTIMATE",
                               "the Builder's cost estimate is above the authorized budget")
        return res

    def _rejected(self, task_id: Optional[str], meta: Dict[str, str], exc: BuilderClientError,
                  submission: str = "NOT_SUBMITTED") -> Dict[str, Any]:
        return {"task_id": task_id, "correlation_id": meta.get("correlation_id"), "submission": submission,
                "provenance": "UNVERIFIED", "mock": True, "pipeline_state": "BLOCKED", "outcome": "BLOCKED",
                "reasons": [exc.message], "failure": exc.as_failure(), "founder_authorization_required": True,
                "retry": {"automatic": False, "safe_to_resubmit_same_id": False,
                          "note": "reconcile with GET before any resubmission" if submission == "UNKNOWN"
                          else "nothing was sent; fix the cause and ask again"}}

    def _wrap(self, res: Dict[str, Any], meta: Dict[str, str], auth: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        out = apply_founder_gate(res)               # no decision is ever passed: AWAITING_FOUNDER at best
        out["connector"] = {"mode": self.cfg.mode, "real_mode": self.cfg.mode == "REAL",
                            "transport": "INJECTED" if self._injected else "URLLIB", "authorization": auth}
        out["status_update"] = status_update(out, meta)
        return out
