"""Native Hermes plugin package for an approved, comment-only writeback."""

try:
    from .plugin import register
except ImportError:  # imported as a top-level module (e.g. pytest collecting the repository root), not as a package
    from plugin import register

__all__ = ["register"]
