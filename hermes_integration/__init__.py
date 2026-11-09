"""Hermes <-> Builder integration adapter (stdlib only). See docs/hermes-builder-integration.md."""

from .client import (  # noqa: F401
    FAILURE_CLASSES, BuilderClient, BuilderClientError, ClientConfig, ConfigError, build_task, load_config,
    request_fingerprint, to_json,
)
from .lifecycle import (  # noqa: F401
    HERMES_STATES, MockReviewer, ReviewVerdict, UnavailableReviewer, evaluate_pipeline, map_builder_state,
    run_task,
)

__version__ = "0.1.0"

# Stage 6 (PROPOSED contracts / COMPATIBILITY interfaces, UNVERIFIED against real Hermes and Paperclip)
from .adapter import HermesBuilderAdapter, MockPaperclip, mock_plan, status_update  # noqa: E402,F401
from .gates import FounderDecision, SafeReviewer, apply_founder_gate, mock_founder  # noqa: E402,F401
from .planner import derive_task_id, plan_to_task, validate_plan  # noqa: E402,F401
