"""Test configuration: the plugin approves nothing unless configured (fail-closed), so set the synthetic test values
BEFORE any plugin module is imported."""
import os

os.environ.setdefault("PAPERCLIP_APPROVED_ORIGIN", "https://paperclip.example.test")
os.environ.setdefault("PAPERCLIP_APPROVED_ISSUES", "TEST-9,TEST-21,TEST-22,TEST-23")
