"""Standalone Hermes-side client for the SELAERON Labs Builder (Python standard library only).

Responsibilities (Hermes orchestrates, the Builder executes):
  build_task -> submit (idempotent) -> poll status -> fetch manifest -> download + SHA-256 verify -> result.

Safety rules enforced here:
  * the bearer token is read at call time from an environment variable or a file; it is never part of the
    configuration file, a log line, an exception message or a result;
  * plain HTTP is accepted only for loopback hosts; redirects are never followed; ambient proxy variables are
    ignored; responses are size-bounded;
  * a paid execution is NEVER retried or resubmitted automatically. Only read-only GETs are retried.
    If a submission's outcome is unknown (network error), the result says so and the caller must reconcile
    with a GET before any resubmission;
  * results carry provenance REAL / MOCK / UNVERIFIED taken from the Builder's own task record. A MOCK run can
    never be reported as REAL.
"""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import logging
import os
import re
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass, fields
from typing import Any, Callable, Dict, List, Optional, Tuple

SCHEMA_VERSION = "1"
TASK_ID_RE = re.compile(r"^[0-9a-f]{32}$")
WORKSPACE_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
MISSION_RE = re.compile(r"^[A-Z0-9][A-Z0-9-]{0,63}$")
CORRELATION_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
SEGMENT_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_. -]{0,100}$")
CAPABILITIES = ("write_files", "run_tests")
MAX_DESCRIPTION = 8000
MAX_TIMEOUT = 1800
BUILDER_STATES = ("QUEUED", "RUNNING", "TESTING", "COMPLETED", "FAILED", "TIMED_OUT", "BLOCKED_SECURITY")
TERMINAL = ("COMPLETED", "FAILED", "TIMED_OUT", "BLOCKED_SECURITY")
FAILURE_CLASSES = (
    "INFRASTRUCTURE", "AUTHENTICATION", "REQUEST_REJECTED", "SECURITY_BLOCKED", "BUSY", "ID_CONFLICT",
    "BUILDER", "TEST_FAILURE", "REVIEWER_FAILURE", "TIMEOUT",
)
# failure classes that mean "stopped by configuration/environment/policy", not "the build failed"
BLOCKING_CLASSES = ("INFRASTRUCTURE", "AUTHENTICATION", "REQUEST_REJECTED", "SECURITY_BLOCKED", "BUSY", "ID_CONFLICT")

LOG = logging.getLogger("hermes_integration")


class ConfigError(Exception):
    """Invalid or unsafe client configuration (fail closed: nothing is sent)."""


class TransportError(Exception):
    """kind: CONNECT | TIMEOUT | TLS | TOO_LARGE | PROTOCOL"""

    def __init__(self, kind: str):
        super().__init__(kind)
        self.kind = kind


class BuilderClientError(Exception):
    def __init__(self, failure_class: str, code: str, message: str, http_status: Optional[int] = None,
                 submission: str = "NOT_SUBMITTED"):
        super().__init__(f"{failure_class}/{code}")
        assert failure_class in FAILURE_CLASSES
        self.failure_class, self.code = failure_class, code
        self.message, self.http_status, self.submission = _clean(message), http_status, submission

    def as_failure(self) -> Dict[str, Any]:
        return {"class": self.failure_class, "code": self.code, "message": self.message,
                "http_status": self.http_status}


def _clean(text: Any, limit: int = 200) -> str:
    """Printable ASCII only, bounded: nothing a hostile server sends can inject control characters."""
    return "".join(c if 32 <= ord(c) < 127 else "?" for c in str(text))[:limit]


# ---- configuration ---------------------------------------------------------------------------
@dataclass
class ClientConfig:
    base_url: str
    token_env: Optional[str] = None      # name of the environment variable holding the bearer token
    token_file: Optional[str] = None     # or a file holding it (one line)
    request_timeout: float = 15.0
    poll_interval: float = 5.0
    max_wait_seconds: Optional[float] = None   # default: task timeout + 120 s
    read_retries: int = 2                # GET only; never POST
    retry_backoff: float = 0.5
    max_response_bytes: int = 1024 * 1024
    max_artifact_bytes: int = 5 * 1024 * 1024
    expect_provenance: Optional[str] = None    # "MOCK" or "REAL": a different record is BLOCKED
    ca_bundle: Optional[str] = None


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def validate_config(cfg: ClientConfig) -> ClientConfig:
    u = urllib.parse.urlsplit(cfg.base_url)
    if u.scheme not in ("http", "https") or not u.hostname:
        raise ConfigError("base_url must be an http(s) URL with a host")
    if u.username or u.password or u.query or u.fragment or u.path not in ("", "/"):
        raise ConfigError("base_url must not contain credentials, a path, a query or a fragment")
    if u.hostname.endswith(".invalid"):
        raise ConfigError("base_url is still the placeholder; set the real private endpoint")
    if u.scheme == "http" and not _is_loopback(u.hostname):
        raise ConfigError("plain HTTP is allowed only for loopback; use HTTPS or a private tunnel")
    if bool(cfg.token_env) == bool(cfg.token_file):
        raise ConfigError("set exactly one of token_env and token_file")
    if cfg.expect_provenance not in (None, "MOCK", "REAL"):
        raise ConfigError("expect_provenance must be MOCK, REAL or null")
    if not (0 < cfg.request_timeout <= 120) or cfg.poll_interval <= 0 or not (0 <= cfg.read_retries <= 5):
        raise ConfigError("timeout, poll interval or retry count out of range")
    return cfg


def load_config(path: str) -> ClientConfig:
    """Load a JSON config. A literal token (or any key that is not a ClientConfig field) is refused."""
    with open(path, "r", encoding="utf-8") as fh:
        raw = json.load(fh)
    if not isinstance(raw, dict):
        raise ConfigError("config must be a JSON object")
    allowed = {f.name for f in fields(ClientConfig)}
    extra = sorted(set(raw) - allowed)
    if extra:
        raise ConfigError("unknown or forbidden config keys: " + ", ".join(_clean(k, 40) for k in extra))
    if "base_url" not in raw:
        raise ConfigError("base_url is required")
    return validate_config(ClientConfig(**raw))


# ---- request building ------------------------------------------------------------------------
def new_task_id() -> str:
    return uuid.uuid4().hex


def request_fingerprint(task: Dict[str, Any]) -> str:
    """Same canonical form as app.models.request_fingerprint (a test asserts they agree)."""
    canon = json.dumps(
        {"mission_id": task.get("mission_id"), "task_description": task["task_description"],
         "workspace_reference": task["workspace_reference"], "execution_timeout": task.get("execution_timeout"),
         "requested_capabilities": sorted(set(task.get("requested_capabilities") or ["write_files"]))},
        sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canon.encode("ascii")).hexdigest()


def build_task(task_description: str, workspace_reference: str, task_id: Optional[str] = None,
               mission_id: Optional[str] = None, execution_timeout: Optional[int] = None,
               requested_capabilities: Tuple[str, ...] = ("write_files",)) -> Dict[str, Any]:
    """Build and validate a Builder request. Only the documented fields can exist: nothing executable."""
    task: Dict[str, Any] = {
        "task_id": task_id or new_task_id(), "task_description": task_description,
        "workspace_reference": workspace_reference,
        "requested_capabilities": list(requested_capabilities),
    }
    if mission_id is not None:
        task["mission_id"] = mission_id
    if execution_timeout is not None:
        task["execution_timeout"] = execution_timeout
    validate_task(task)
    return task


def validate_task(task: Dict[str, Any]) -> None:
    def bad(code: str, msg: str):
        raise BuilderClientError("REQUEST_REJECTED", code, msg)

    allowed = {"task_id", "mission_id", "task_description", "workspace_reference", "execution_timeout",
               "requested_capabilities"}
    if not isinstance(task, dict) or set(task) - allowed:
        bad("UNKNOWN_FIELD", "request has fields the Builder does not accept")
    if not isinstance(task.get("task_id"), str) or not TASK_ID_RE.fullmatch(task["task_id"]):
        bad("INVALID_TASK_ID", "task_id must be 32 lowercase hex characters")
    desc = task.get("task_description")
    if not isinstance(desc, str) or not (1 <= len(desc) <= MAX_DESCRIPTION):
        bad("INVALID_DESCRIPTION", f"task_description must be 1..{MAX_DESCRIPTION} characters")
    if not isinstance(task.get("workspace_reference"), str) or not WORKSPACE_RE.fullmatch(task["workspace_reference"]):
        bad("INVALID_WORKSPACE_REFERENCE", "workspace_reference must be a short approved name, not a path")
    mid = task.get("mission_id")
    if mid is not None and (not isinstance(mid, str) or not MISSION_RE.fullmatch(mid)):
        bad("INVALID_MISSION_ID", "mission_id must match [A-Z0-9][A-Z0-9-]{0,63}")
    t = task.get("execution_timeout")
    if t is not None and (isinstance(t, bool) or not isinstance(t, int) or not (1 <= t <= MAX_TIMEOUT)):
        bad("INVALID_TIMEOUT", f"execution_timeout must be an integer 1..{MAX_TIMEOUT}")
    caps = task.get("requested_capabilities", ["write_files"])
    if (not isinstance(caps, list) or "write_files" not in caps
            or any(c not in CAPABILITIES for c in caps)):
        bad("INVALID_CAPABILITIES", "capabilities must be a subset of write_files, run_tests including write_files")


def validate_artifact_path(path: Any) -> str:
    """Reject anything that is not a plain relative path of safe segments (no traversal, no drives, no links)."""
    ok = isinstance(path, str) and 0 < len(path) <= 240 and not path.startswith("/")
    if ok:
        for seg in path.split("/"):
            if not SEGMENT_RE.fullmatch(seg) or seg in (".", "..") or seg.endswith((" ", ".")):
                ok = False
                break
    if not ok:
        raise BuilderClientError("REQUEST_REJECTED", "INVALID_ARTIFACT_PATH", "artifact path is not a safe relative path")
    return path


# ---- transport -------------------------------------------------------------------------------
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # never follow: the token must not travel
        return None


Transport = Callable[[str, str, Optional[bytes], Dict[str, str], float, int], Tuple[int, Dict[str, str], bytes]]


class UrllibTransport:
    def __init__(self, cfg: ClientConfig):
        ctx = ssl.create_default_context(cafile=cfg.ca_bundle) if cfg.ca_bundle else ssl.create_default_context()
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _NoRedirect, urllib.request.HTTPSHandler(context=ctx))

    def __call__(self, method, url, body, headers, timeout, max_bytes):
        req = urllib.request.Request(url, data=body, method=method, headers=headers)
        try:
            resp = self._opener.open(req, timeout=timeout)
        except urllib.error.HTTPError as exc:      # non-2xx and 3xx (redirects are not followed)
            resp = exc
        except (socket.timeout, TimeoutError):
            raise TransportError("TIMEOUT") from None
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, (socket.timeout, TimeoutError)):
                raise TransportError("TIMEOUT") from None
            raise TransportError("TLS" if isinstance(exc.reason, ssl.SSLError) else "CONNECT") from None
        except ssl.SSLError:
            raise TransportError("TLS") from None
        except (ConnectionError, OSError, http.client.HTTPException):
            raise TransportError("CONNECT") from None
        try:
            data = resp.read(max_bytes + 1)
            status = getattr(resp, "status", None) or resp.code
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
        except (socket.timeout, TimeoutError):
            raise TransportError("TIMEOUT") from None
        except (ConnectionError, OSError, http.client.HTTPException):
            raise TransportError("PROTOCOL") from None
        finally:
            resp.close()
        if len(data) > max_bytes:
            raise TransportError("TOO_LARGE")
        return status, hdrs, data


def _log(event: str, **kv: Any) -> None:
    """Structured, allow-listed, sanitized log line. Never receives tokens, descriptions or file contents."""
    keys = ("correlation_id", "task_id", "http_status", "failure_class", "code", "attempt", "state", "kind")
    LOG.info(json.dumps({"event": event, **{k: _clean(kv[k], 80) for k in keys if k in kv}}, sort_keys=True))


# ---- client ----------------------------------------------------------------------------------
class BuilderClient:
    def __init__(self, config: ClientConfig, transport: Optional[Transport] = None,
                 sleep: Callable[[float], None] = time.sleep, now: Callable[[], float] = time.monotonic):
        self.cfg = validate_config(config)
        self._transport = transport or UrllibTransport(config)
        self._sleep, self._now = sleep, now

    # -- plumbing
    def _token(self) -> str:
        try:
            if self.cfg.token_env:
                tok = os.environ.get(self.cfg.token_env, "")
            else:
                with open(self.cfg.token_file, "r", encoding="utf-8") as fh:
                    tok = fh.read()
        except OSError:
            tok = ""
        tok = tok.strip()
        if len(tok) < 20 or any(c.isspace() for c in tok):
            raise ConfigError("integration token is missing or malformed (never logged)")
        return tok

    @staticmethod
    def _corr(correlation_id: Optional[str]) -> str:
        if correlation_id is None:
            return "hb-" + uuid.uuid4().hex[:24]
        if not CORRELATION_RE.fullmatch(correlation_id):
            raise BuilderClientError("REQUEST_REJECTED", "INVALID_CORRELATION_ID", "correlation id has unsafe characters")
        return correlation_id

    def _call(self, method: str, path: str, body: Optional[bytes], corr: str, auth: bool = True,
              max_bytes: Optional[int] = None, extra: Optional[Dict[str, str]] = None) -> Tuple[int, Dict[str, str], bytes]:
        headers = {"Accept": "application/json", "X-Correlation-ID": corr, "User-Agent": "hermes-builder-client/0.1"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        if extra:
            headers.update(extra)
        if auth:
            headers["Authorization"] = "Bearer " + self._token()
        url = self.cfg.base_url.rstrip("/") + path
        attempts = 1 + (self.cfg.read_retries if method == "GET" else 0)   # POST is NEVER retried
        last: Optional[TransportError] = None
        for attempt in range(1, attempts + 1):
            try:
                status, hdrs, data = self._transport(method, url, body, headers, self.cfg.request_timeout,
                                                     max_bytes or self.cfg.max_response_bytes)
                if method == "GET" and status in (502, 503, 504) and attempt < attempts:
                    _log("retry_get", correlation_id=corr, http_status=status, attempt=attempt)
                    self._sleep(self.cfg.retry_backoff * attempt)
                    continue
                return status, hdrs, data
            except TransportError as exc:
                last = exc
                _log("transport_error", correlation_id=corr, kind=exc.kind, attempt=attempt)
                if attempt < attempts and exc.kind in ("CONNECT", "TIMEOUT", "PROTOCOL"):
                    self._sleep(self.cfg.retry_backoff * attempt)
                    continue
                raise
        raise last or TransportError("CONNECT")

    @staticmethod
    def _json(data: bytes) -> Dict[str, Any]:
        try:
            obj = json.loads(data.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise BuilderClientError("INFRASTRUCTURE", "MALFORMED_RESPONSE", "Builder response was not valid JSON") from None
        if not isinstance(obj, dict):
            raise BuilderClientError("INFRASTRUCTURE", "MALFORMED_RESPONSE", "Builder response was not a JSON object")
        return obj

    def _payload(self, status: int, data: bytes) -> Dict[str, Any]:
        """2xx bodies must be a JSON object; error bodies may be empty/HTML (a 302 or 502) and are then {}."""
        if status in (200, 202):
            return self._json(data)
        try:
            obj = json.loads(data.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return {}
        return obj if isinstance(obj, dict) else {}

    def _http_error(self, status: int, payload: Dict[str, Any], submission: str = "NOT_SUBMITTED") -> BuilderClientError:
        err = payload.get("error") if isinstance(payload.get("error"), dict) else {}
        cat, msg = _clean(err.get("category", "")), err.get("message", "")
        table = {
            (401, "AUTH"): ("AUTHENTICATION", "AUTH"),
            (403, "WORKSPACE_DENIED"): ("REQUEST_REJECTED", "WORKSPACE_DENIED"),
            (403, "BLOCKED_SECURITY"): ("SECURITY_BLOCKED", "SPEC_POLICY"),
            (404, "NOT_FOUND"): ("REQUEST_REJECTED", "NOT_FOUND"),
            (409, "CONFLICT"): ("ID_CONFLICT", "TASK_ID_EXISTS"),
            (409, "NOT_READY"): ("REQUEST_REJECTED", "NOT_READY"),
            (413, "PAYLOAD_TOO_LARGE"): ("REQUEST_REJECTED", "PAYLOAD_TOO_LARGE"),
            (422, "VALIDATION"): ("REQUEST_REJECTED", "VALIDATION"),
            (412, "PROVENANCE_MISMATCH"): ("SECURITY_BLOCKED", "PROVENANCE_MISMATCH"),
            (429, "BUSY"): ("BUSY", "BUILDER_BUSY"),
            (403, "FOUNDER_AUTHORIZATION"): ("SECURITY_BLOCKED", "FOUNDER_AUTHORIZATION_REFUSED"),
            (409, "REQUEST_CONFLICT"): ("ID_CONFLICT", "REQUEST_ID_CONFLICT"),
            (503, "REPLAY_STATE"): ("INFRASTRUCTURE", "REPLAY_STATE_UNAVAILABLE"),
        }
        cls, code = table.get((status, cat), ("INFRASTRUCTURE", f"HTTP_{status}"))
        if status >= 500 or 300 <= status < 400:
            cls, code = "INFRASTRUCTURE", ("UNEXPECTED_REDIRECT" if status < 400 else f"HTTP_{status}")
        if cls == "BUSY":
            submission = "NOT_SUBMITTED"        # a 429 never creates a record: safe to resubmit the same id later
        return BuilderClientError(cls, code, msg or cat or f"HTTP {status}", status, submission)

    # -- operations
    def submit(self, task: Dict[str, Any], correlation_id: Optional[str] = None) -> Dict[str, Any]:
        validate_task(task)
        corr, fp = self._corr(correlation_id), request_fingerprint(task)
        body = json.dumps(task, separators=(",", ":")).encode("utf-8")
        try:
            # Pre-submission precondition: the Builder refuses (412, no record, nothing runs) if its provenance differs.
            pre = {"X-Expected-Provenance": self.cfg.expect_provenance} if self.cfg.expect_provenance else None
            status, _, data = self._call("POST", "/execute", body, corr, extra=pre)
        except TransportError as exc:
            raise BuilderClientError(
                "INFRASTRUCTURE", "SUBMISSION_UNKNOWN_" + exc.kind,
                "the Builder may or may not have accepted the task; reconcile with a GET before any resubmission",
                submission="UNKNOWN") from None
        try:
            payload = self._payload(status, data)
            if status == 202:
                self._check_record(payload, task["task_id"])
        except BuilderClientError as exc:     # a 2xx that cannot be understood: the Builder may have accepted the task
            raise BuilderClientError(exc.failure_class, exc.code, exc.message, status, submission="UNKNOWN") from None
        if status == 202:
            _log("submitted", correlation_id=corr, task_id=task["task_id"], http_status=202)
            return {"record": payload, "replayed": False, "correlation_id": corr, "request_sha256": fp}
        if status == 409 and (payload.get("error") or {}).get("category") == "CONFLICT":
            rec = self.status(task["task_id"], corr)               # idempotent replay check (read-only)
            if rec.get("request_sha256") == fp:
                _log("replayed", correlation_id=corr, task_id=task["task_id"])
                return {"record": rec, "replayed": True, "correlation_id": corr, "request_sha256": fp}
            raise BuilderClientError(
                "ID_CONFLICT",
                "TASK_ID_REUSED_WITH_DIFFERENT_REQUEST" if rec.get("request_sha256") else "IDEMPOTENCY_UNVERIFIABLE",
                "this task_id already exists for a different (or unverifiable) request; use a new task_id",
                409, submission="REJECTED")
        raise self._http_error(status, payload, submission="REJECTED")

    def _check_record(self, rec: Dict[str, Any], task_id: str) -> None:
        if rec.get("task_id") != task_id or rec.get("state") not in BUILDER_STATES:
            raise BuilderClientError("INFRASTRUCTURE", "MISMATCHED_RESPONSE", "Builder returned an unexpected task record")

    def health(self, correlation_id: Optional[str] = None) -> Dict[str, Any]:
        """Unauthenticated liveness check (GET /health). Reveals only status and version."""
        corr = self._corr(correlation_id)
        try:
            status, _, data = self._call("GET", "/health", None, corr, auth=False)
        except TransportError as exc:
            raise BuilderClientError("INFRASTRUCTURE", "UNREACHABLE_" + exc.kind, "Builder could not be reached") from None
        payload = self._payload(status, data)
        if status != 200:
            raise self._http_error(status, payload)
        if payload.get("status") != "ok":
            raise BuilderClientError("INFRASTRUCTURE", "UNHEALTHY", "Builder did not report ok")
        return {"status": "ok", "version": _clean(payload.get("version", ""), 40)}

    def status(self, task_id: str, correlation_id: Optional[str] = None) -> Dict[str, Any]:
        if not TASK_ID_RE.fullmatch(task_id or ""):
            raise BuilderClientError("REQUEST_REJECTED", "INVALID_TASK_ID", "task_id must be 32 lowercase hex characters")
        corr = self._corr(correlation_id)
        try:
            status, _, data = self._call("GET", f"/tasks/{task_id}", None, corr)
        except TransportError as exc:
            raise BuilderClientError("INFRASTRUCTURE", "UNREACHABLE_" + exc.kind, "Builder could not be reached") from None
        payload = self._payload(status, data)
        if status != 200:
            raise self._http_error(status, payload)
        self._check_record(payload, task_id)
        return payload

    def wait(self, task_id: str, timeout_seconds: int, correlation_id: Optional[str] = None) -> Dict[str, Any]:
        deadline = self._now() + (self.cfg.max_wait_seconds or (timeout_seconds + 120))
        while True:
            rec = self.status(task_id, correlation_id)
            if rec["state"] in TERMINAL:
                return rec
            if self._now() >= deadline:
                raise BuilderClientError("TIMEOUT", "CLIENT_WAIT_EXPIRED",
                                         "gave up waiting; the task may still be running (no cancel, no resubmit)",
                                         submission="ACCEPTED")
            self._sleep(self.cfg.poll_interval)

    def manifest(self, task_id: str, correlation_id: Optional[str] = None) -> Dict[str, Any]:
        corr = self._corr(correlation_id)
        try:
            status, _, data = self._call("GET", f"/tasks/{task_id}/artifacts", None, corr)
        except TransportError as exc:
            raise BuilderClientError("INFRASTRUCTURE", "UNREACHABLE_" + exc.kind, "Builder could not be reached") from None
        payload = self._payload(status, data)
        if status != 200:
            raise self._http_error(status, payload)
        entries = payload.get("artifacts")
        if not isinstance(entries, list) or len(entries) > 200:
            raise BuilderClientError("INFRASTRUCTURE", "INVALID_MANIFEST", "manifest is malformed or too large")
        for e in entries:
            if not (isinstance(e, dict) and isinstance(e.get("size"), int) and isinstance(e.get("sha256"), str)
                    and re.fullmatch(r"[0-9a-f]{64}", e["sha256"])):
                raise BuilderClientError("INFRASTRUCTURE", "INVALID_MANIFEST", "manifest entry is malformed")
            validate_artifact_path(e.get("path"))
        return payload

    def download(self, task_id: str, entry: Dict[str, Any], correlation_id: Optional[str] = None) -> bytes:
        """Fetch ONE file named in a validated manifest and verify size and SHA-256. Arbitrary paths are impossible."""
        path = validate_artifact_path(entry.get("path"))
        corr = self._corr(correlation_id)
        if entry["size"] > self.cfg.max_artifact_bytes:
            raise BuilderClientError("REQUEST_REJECTED", "ARTIFACT_TOO_LARGE", "artifact exceeds the client limit")
        quoted = urllib.parse.quote(path, safe="/")
        try:
            status, _, data = self._call("GET", f"/tasks/{task_id}/artifacts/{quoted}", None, corr,
                                         max_bytes=self.cfg.max_artifact_bytes)
        except TransportError as exc:
            raise BuilderClientError("INFRASTRUCTURE", "ARTIFACT_" + exc.kind, "artifact download failed") from None
        if status != 200:
            raise self._http_error(status, self._payload(status, data))
        if len(data) != entry["size"] or hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise BuilderClientError("INFRASTRUCTURE", "ARTIFACT_INTEGRITY_FAILURE",
                                     "downloaded bytes do not match the manifest size/SHA-256")
        return data

    def reconcile(self, task_id: str, expected_fingerprint: Optional[str] = None) -> Dict[str, Any]:
        """After SUBMISSION_UNKNOWN_*: ask the Builder what it knows. 404 => never arrived (safe to resend)."""
        try:
            rec = self.status(task_id)
        except BuilderClientError as exc:
            if exc.code == "NOT_FOUND":
                return {"known": False, "safe_to_resubmit_same_id": True}
            raise
        same = expected_fingerprint is None or rec.get("request_sha256") == expected_fingerprint
        return {"known": True, "record": rec, "same_request": same, "safe_to_resubmit_same_id": False}


def to_json(result: Dict[str, Any]) -> str:
    """Deterministic serialisation for Hermes (sorted keys, compact separators)."""
    return json.dumps(result, sort_keys=True, separators=(",", ":"))


def provenance_of(record: Optional[Dict[str, Any]]) -> str:
    p = (record or {}).get("provenance")
    return p if p in ("REAL", "MOCK") else "UNVERIFIED"


def safe_artifacts_to_list(entries: List[Dict[str, Any]], verified: bool) -> List[Dict[str, Any]]:
    return [{"path": e["path"], "size": e["size"], "sha256": e["sha256"], "verified": verified} for e in entries]
