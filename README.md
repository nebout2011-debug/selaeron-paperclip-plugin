# Paperclip comment-only plugin for Hermes

A Hermes tool plugin (`selaeron_paperclip_sel9_comment`) that posts **one comment** on an approved Paperclip issue, bound to the
issue's current live Paperclip run. It never changes issue status.

Status: tested against a mock only (see `tests/`); not verified against a production Paperclip. No license has been chosen yet.

## Configuration (fail-closed)

Nothing is approved unless you configure it. Both values are read once, at import time, from the **process environment**:

| Variable | Meaning |
|---|---|
| `PAPERCLIP_APPROVED_ORIGIN` | exact `https` origin allowed to receive comments, e.g. `https://paperclip.example.com` |
| `PAPERCLIP_APPROVED_ISSUES` | comma-separated issue ids allowed to receive a comment, e.g. `TEST-1,TEST-2` |

The plugin itself needs `PAPERCLIP_API_URL` and `PAPERCLIP_API_KEY` (read from the Hermes profile `.env`); the run id comes from
the live-run lookup. Real-mode writes elsewhere stay locked (`REAL_MODE_LOCKED`).

## Layout

* `examples/hermes_plugins/selaeron_paperclip_sel9/` - the Hermes plugin entry point (`plugin.yaml`, `plugin.py`)
* `hermes_integration/` - the package it imports (`paperclip`, `hermes_paperclip_plugin`, `connector`, `adapter`, `client`,
  `gates`, `lifecycle`, `planner`, `_security_core`); standard library only, plus `cryptography` for the signature verification path
* `tests/` - `python -m pytest`

Note: identifiers such as `FounderDecision`, `apply_founder_gate` and the `FOUNDER_*` protocol constants name the human approver
role of the gate; they are API and wire-format names and were intentionally not renamed.
