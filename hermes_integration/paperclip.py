"""Stage 7R: Paperclip status-writeback adapter (REST). LOCALLY TESTED AGAINST A MOCK SERVER ONLY.

LABEL: the routes below follow the PUBLIC Paperclip documentation read in Stage 7B (`POST /api/issues/{id}/comments`,
`PATCH /api/issues/{id}`, bearer agent key, optional `X-Paperclip-Run-Id`). They are UNVERIFIED against the installed Paperclip
(2026.1012.0) and a `checkout` step that the docs mention is NOT implemented. Nothing here was ever sent to the real Paperclip.

`PaperclipRestSink` implements the existing `StatusSink` protocol (`hermes_integration.adapter`), so the Stage 7I pipeline uses it
unchanged: `Pipeline` already turns a failed delivery into `STATUS_UPDATE_FAILED` without touching the task state.

Safety properties (tested):
* only a sanitized, whitelisted `status_update` record is rendered (no artifact bytes, headers, tokens, host names);
* the issue status is only ever `in_review` (waiting for the operator) or `blocked`; it is never `done`/`closed`/`cancelled`;
* the base URL must be loopback `http://` (tests) or an exact `https://` origin. Non-loopback writes remain refused while
  `connector.REAL_MODE_LOCKED` is true except an explicitly opted-in, comment-only test on a configured issue at the exact configured origin;
* no proxy, no redirect following, bounded reply size and timeout; errors carry a stable code, never a URL, header or token.

This module does not install itself into the actual Hermes tool registry, inject an active Paperclip run ID,
or provision credentials. Do not deploy it until those runtime integrations have been verified.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, Optional, Tuple

from . import connector as _connector
from .adapter import STATUS_FIELDS, _safe

Transport = Callable[[str, str, Optional[bytes], Dict[str, str], float, int], Tuple[int, Dict[str, str], bytes]]

ROUTES = {"comment": "/api/issues/{issue}/comments", "status": "/api/issues/{issue}"}
ROUTE_NAMES = ("comment", "status")
DEFAULT_ROUTES = dict(ROUTES)


def _validate_routes(routes: Optional[Dict[str, str]]) -> Dict[str, str]:
    if routes is None:
        routes = DEFAULT_ROUTES
    if not isinstance(routes, dict) or set(routes) != set(ROUTE_NAMES):
        raise _connector.ConnectorConfigError("routes must contain exactly comment and status templates")
    out: Dict[str, str] = {}
    for name in ROUTE_NAMES:
        templ = routes[name]
        if not isinstance(templ, str) or not templ.startswith("/") or "{issue}" not in templ:
            raise _connector.ConnectorConfigError(f"invalid route template for {name}")
        if not templ.format(issue="A").startswith("/"):
            raise _connector.ConnectorConfigError(f"invalid route template for {name}")
        out[name] = templ
    return out
ISSUE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")
RUN_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")
LOOPBACK_HOSTS = ("127.0.0.1", "::1", "localhost")
MAX_REPLY = 64 * 1024
MAX_COMMENT = 2000
READY_STATES = ("MOCK_READY_FOR_FOUNDER", "READY_FOR_FOUNDER", "IN_REVIEW")

BLOCKED_STATES = ("BLOCKED", "REVIEW_BLOCKED", "FAILED", "TIMED_OUT")
NEVER_SET = ("done", "closed", "cancelled", "completed", "resolved")      # only the operator closes an issue
# Comment-only test mode is FAIL-CLOSED: with no configuration no origin and no issue is approved. Configure both through the
# PROCESS environment (read once, at import time):
#   PAPERCLIP_APPROVED_ORIGIN  the exact https origin allowed to receive comments, e.g. https://paperclip.example.com
#   PAPERCLIP_APPROVED_ISSUES  comma-separated issue ids allowed to receive a comment, e.g. TEST-1,TEST-2
SYNTHETIC_TEST_ORIGIN = os.environ.get("PAPERCLIP_APPROVED_ORIGIN", "").strip().rstrip("/")
SYNTHETIC_TEST_ISSUES = tuple(dict.fromkeys(
    i.strip() for i in os.environ.get("PAPERCLIP_APPROVED_ISSUES", "").split(",") if ISSUE_RE.fullmatch(i.strip())))
SYNTHETIC_TEST_ISSUE = SYNTHETIC_TEST_ISSUES[0] if SYNTHETIC_TEST_ISSUES else ""      # default / fallback label
SYNTHETIC_TEST_APPROVAL = "PAPERCLIP_COMMENT_ONLY_APPROVED"


class PaperclipWriteError(Exception):
    """A status write failed. `code` is stable and safe to log; the text never contains a URL, header or token."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any):
        return None


_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())      # no proxy, no redirects


def urllib_transport(method: str, url: str, body: Optional[bytes], headers: Dict[str, str], timeout: float, max_bytes: int):
    """Default network transport. The scheme/host were validated by `PaperclipRestSink.__init__` before this can run."""
    request = urllib.request.Request(url, data=body, method=method, headers=headers)  # noqa: S310
    try:
        with _OPENER.open(request, timeout=timeout) as resp:  # noqa: S310
            return resp.status, dict(resp.headers), resp.read(max_bytes)
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read(max_bytes)


def check_base_url(base_url: str, *, synthetic_test: bool = False) -> str:
    """Return the normalized origin or raise. Non-loopback origins are refused while REAL mode is locked."""
    parts = urllib.parse.urlsplit(base_url)
    host = parts.hostname or ""
    if parts.username or parts.password or parts.query or parts.fragment or parts.path not in ("", "/") or not host:
        raise _connector.ConnectorConfigError("the Paperclip base URL must be a bare origin")
    loopback = host in LOOPBACK_HOSTS
    if parts.scheme == "http" and not loopback:
        raise _connector.ConnectorConfigError("plain http is allowed only for loopback")
    if parts.scheme not in ("http", "https"):
        raise _connector.ConnectorConfigError("unsupported scheme")
    if synthetic_test and (not SYNTHETIC_TEST_ORIGIN or base_url.rstrip("/") != SYNTHETIC_TEST_ORIGIN):
        raise _connector.RealModeLocked("synthetic test origin is not approved")
    if not loopback and _connector.REAL_MODE_LOCKED and not synthetic_test:
        raise _connector.RealModeLocked("writing to a non-loopback Paperclip is locked in this build (REAL_MODE_LOCKED)")
    return f"{parts.scheme}://{parts.netloc}"


def paperclip_sink_from_environment(env: Optional[Dict[str, str]] = None, transport: Optional[Transport] = None,
                                    timeout: float = 5.0) -> PaperclipRestSink:
    """Build a REST sink from approved runtime configuration.

    The credential and run ID must already be present in the supplied mapping (normally the process environment) because
    Hermes does not mint Paperclip identity. Nothing in this function creates, persists or displays a secret; it only
    validates that Paperclip's required separately scoped values were supplied.
    """
    source = os.environ if env is None else env
    base_url = source.get("PAPERCLIP_API_URL")
    token = source.get("PAPERCLIP_API_KEY")
    run_id = source.get("PAPERCLIP_RUN_ID")
    synthetic_test = source.get("PAPERCLIP_SYNTHETIC_TEST_APPROVAL") == SYNTHETIC_TEST_APPROVAL
    if not all(isinstance(value, str) and value for value in (base_url, token, run_id)):
        raise _connector.ConnectorConfigError("PAPERCLIP_API_URL, PAPERCLIP_API_KEY and PAPERCLIP_RUN_ID are all required")
    return PaperclipRestSink(base_url, token, run_id=run_id, transport=transport, timeout=timeout,
                             synthetic_test=synthetic_test)


class PaperclipWritebackTool:
    """Callable Hermes-side writeback tool over the existing REST sink."""

    def __init__(self, sink: Optional[PaperclipRestSink] = None,
                 env: Optional[Dict[str, str]] = None,
                 transport: Optional[Transport] = None,
                 name: str = "paperclip_comment",
                 run_id_override: Optional[str] = None):
        self._sink = sink if sink is not None else paperclip_sink_from_environment(env, transport=transport)
        if run_id_override is not None and not RUN_ID_RE.fullmatch(run_id_override):
            raise _connector.ConnectorConfigError("invalid run id")
        if run_id_override is not None:
            # The active Paperclip heartbeat run ID may be supplied at registration time or by the runtime invocation.
            self._sink = PaperclipRestSink(self._sink._base, self._sink._token, run_id=run_id_override,
                                           transport=self._sink._transport, timeout=self._sink._timeout,
                                           synthetic_test=self._sink._synthetic_test)
        self.name = name

    def post_comment(self, issue_id: Any, update: Dict[str, Any]) -> None:
        self._sink.report(dict(update or {}, work_item_id=issue_id))

    handle = post_comment

    def run_id(self) -> Optional[str]:
        return getattr(self._sink, "_run_id", None)


def register_paperclip_writeback_tool(*, env: Optional[Dict[str, str]] = None, sink: Optional[PaperclipRestSink] = None,
                                     run_id: Optional[str] = None, name: str = "paperclip_comment") -> PaperclipWritebackTool:
    """Register and return the callable writeback tool. Fails closed when runtime config is incomplete."""
    tool = PaperclipWritebackTool(sink=sink, env=env, run_id_override=run_id, name=name)
    if not tool.run_id():
        raise _connector.ConnectorConfigError("PAPERCLIP_RUN_ID is required")
    return tool


def target_status(update: Dict[str, Any]) -> Optional[str]:
    """The only statuses this adapter ever requests: `in_review` (operator next) or `blocked`; None = comment only."""
    if update.get("failure"):
        return "blocked"
    state = update.get("pipeline_state")
    if state in READY_STATES:
        return "in_review"
    if state in BLOCKED_STATES:
        return "blocked"
    return None


def render_comment(update: Dict[str, Any]) -> str:
    label = "MOCK" if update.get("mock") else "REAL"
    lines = [f"[{label}] Builder status (sanitized; the operator decides the next step)"]
    for key in STATUS_FIELDS:
        value = update.get(key)
        if value is None or key in ("failure", "reasons"):
            continue
        lines.append(f"- {key}: {_safe(value, 80)}")
    failure = update.get("failure")
    if isinstance(failure, dict):
        lines.append(f"- failure: {_safe(failure.get('class'), 40)} / {_safe(failure.get('code'), 60)}")
    for reason in (update.get("reasons") or [])[:5]:
        lines.append(f"- reason: {_safe(reason, 120)}")
    lines.append("- deployment_authorized: false; operator approval is still required")
    return "\n".join(lines)[:MAX_COMMENT]


class PaperclipRestSink:
    """StatusSink: comment first, then (maybe) a status change. A redelivery repeats the comment (accepted, documented risk)."""

    label = "MOCK-TESTED"

    def __init__(self, base_url: str, token: str, run_id: Optional[str] = None, transport: Optional[Transport] = None,
                 timeout: float = 5.0, routes: Optional[Dict[str, str]] = None,
                 synthetic_test: bool = False):
        self._base = check_base_url(base_url, synthetic_test=synthetic_test)
        if not isinstance(token, str) or len(token) < 16 or any(c.isspace() or not c.isprintable() for c in token):
            raise _connector.ConnectorConfigError("an agent token of at least 16 printable characters is required")
        if run_id is not None and not RUN_ID_RE.fullmatch(run_id):
            raise _connector.ConnectorConfigError("invalid run id")
        if synthetic_test and not run_id:
            raise _connector.ConnectorConfigError("active run id required for synthetic test")
        if synthetic_test and routes is not None:
            raise _connector.ConnectorConfigError("custom routes forbidden for synthetic test")
        self._synthetic_test = synthetic_test
        self._routes = _validate_routes(routes)
        self._token, self._run_id, self._transport, self._timeout = token, run_id, transport or urllib_transport, timeout

    def __repr__(self) -> str:                      # never show the token
        return f"PaperclipRestSink(base={self._base!r}, run_id={self._run_id!r})"

    def _call(self, method: str, route: str, issue: str, payload: Dict[str, Any]) -> None:
        url = self._base + self._routes[route].format(issue=urllib.parse.quote(issue, safe=""))
        headers = {"Authorization": "Bearer " + self._token, "Content-Type": "application/json", "Accept": "application/json"}
        if self._run_id:
            headers["X-Paperclip-Run-Id"] = self._run_id
        try:
            status, _, raw = self._transport(method, url, json.dumps(payload).encode("utf-8"), headers, self._timeout, MAX_REPLY)
        except TimeoutError:
            raise PaperclipWriteError("TIMEOUT") from None
        except (OSError, urllib.error.URLError):
            raise PaperclipWriteError("UNREACHABLE") from None
        if status in (401, 403):
            raise PaperclipWriteError("AUTH_REJECTED")
        if status == 409:
            raise PaperclipWriteError("CONFLICT")
        if not 200 <= status < 300:
            raise PaperclipWriteError(f"HTTP_{status}" if 100 <= status < 600 else "HTTP_INVALID")
        if len(raw) >= MAX_REPLY:
            raise PaperclipWriteError("REPLY_TOO_LARGE")

    def report(self, update: Dict[str, Any]) -> None:
        issue = update.get("work_item_id")
        if not isinstance(issue, str) or not ISSUE_RE.fullmatch(issue):
            raise PaperclipWriteError("INVALID_ISSUE_ID")
        if self._synthetic_test:
            if issue not in SYNTHETIC_TEST_ISSUES:
                raise PaperclipWriteError("SYNTHETIC_ISSUE_NOT_APPROVED")
            # The operator approved only a comment on the test issues, never task-state mutation.
            self._call("POST", "comment", issue, {"body": render_comment(update)})
            return
        status = target_status(update)
        if status is not None and status in NEVER_SET:          # defensive: the mapping above can never produce these
            raise PaperclipWriteError("FORBIDDEN_STATUS")
        self._call("POST", "comment", issue, {"body": render_comment(update)})
        if status is not None:
            self._call("PATCH", "status", issue, {"status": status})
