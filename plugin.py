"""Hermes plugin entry point."""

from __future__ import annotations

import sys
from pathlib import Path

# Deployed layout vendors hermes_integration/ beside this file; in the repo it is already importable.
_here = Path(__file__).resolve().parent
if (_here / "hermes_integration").is_dir() and str(_here) not in sys.path:
    sys.path.insert(0, str(_here))

from hermes_integration.hermes_paperclip_plugin import post_sel9_comment, register  # noqa: E402

__all__ = ["register", "post_sel9_comment"]
