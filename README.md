# Paperclip comment-only plugin for Hermes

A Hermes tool plugin (`selaeron_paperclip_sel9_comment`) that posts **one comment** on an approved Paperclip issue, bound to the
issue's current live Paperclip run. It never changes issue status.

Status: tested against a mock only (see `tests/`); not verified against a production Paperclip. Licensed under the MIT License (see `LICENSE`).

## Configuration (fail-closed)

Nothing is approved unless you configure it. Both values are read once, at import time, from the **process environment**:

| Variable | Meaning |
|---|---|
| `PAPERCLIP_APPROVED_ORIGIN` | exact `https` origin allowed to receive comments, e.g. `https://paperclip.example.com` |
| `PAPERCLIP_APPROVED_ISSUES` | comma-separated issue ids allowed to receive a comment, e.g. `TEST-1,TEST-2` |

The plugin also needs `PAPERCLIP_API_URL` and `PAPERCLIP_API_KEY`. They are resolved through Hermes
(`agent.secret_scope.get_secret`, which honours the active profile); the plugin never reads `.env` files. Outside Hermes
(tests, standalone) `get_secret` is simply the process environment. The run id is not configured: it comes from a read-only
live-run lookup. Real-mode writes elsewhere stay locked (`REAL_MODE_LOCKED`).

Requires Hermes `>=0.21.6` (the oldest SemVer release verified to ship `agent.secret_scope`).

## Layout

* `plugin.yaml`, `__init__.py`, `plugin.py` (repository root) - the Hermes plugin entry point; the repository root is the plugin
  directory, so a catalog entry needs no `subdir`
* `hermes_integration/` - the package it imports (`paperclip`, `hermes_paperclip_plugin`, `connector`, `adapter`, `client`,
  `gates`, `lifecycle`, `planner`, `_security_core`); standard library only, plus `cryptography` for the signature verification path
* `tests/` - `python -m pytest`

Note: identifiers such as `FounderDecision`, `apply_founder_gate` and the `FOUNDER_*` protocol constants name the human approver
role of the gate; they are API and wire-format names and were intentionally not renamed.
