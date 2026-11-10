import os
import threading

import pytest

from hermes_integration.hermes_paperclip_plugin import _run_id, post_sel9_comment


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    monkeypatch.setattr("hermes_integration.paperclip.PaperclipRestSink._call",
                        lambda self, method, route, issue, payload: None)
from hermes_integration.paperclip import PaperclipRestSink, register_paperclip_writeback_tool


def _set_env():
    os.environ["PAPERCLIP_API_URL"] = "https://paperclip.example.test"
    os.environ["PAPERCLIP_API_KEY"] = "a" * 32
    os.environ.pop("PAPERCLIP_RUN_ID", None)


def test_valid_run_id_from_tool_context(monkeypatch):
    _set_env()
    result = post_sel9_comment("approved summary", {"paperclip_run_id": "run-alpha01"})
    assert result["status"] == "ACCEPTED"
    assert result["run_id"] == "run-alpha01"


def test_missing_run_id_rejected(monkeypatch):
    _set_env()
    assert _run_id(None) is None
    result = post_sel9_comment("approved summary")
    assert result["status"] == "REJECTED"
    assert result["code"] == "RUN_ID_MISSING"


def test_valid_run_id_from_prompt():
    _set_env()
    prompt = "Paperclip runtime identity:\n- Agent ID: a\n- Run ID: run-prompt42\n"
    result = post_sel9_comment("approved", user_task=prompt)
    assert result["status"] == "ACCEPTED"
    assert result["run_id"] == "run-prompt42"


def test_concurrent_runs_do_not_leak():
    _set_env()
    monkeypatch = None

    def work(run_id, result):
        r = post_sel9_comment(f"summary for {run_id}", {"paperclip_run_id": run_id})
        result.append(r)

    threads = []
    results = {}
    for i in range(5):
        rid = f"concurrent-run-{i}"
        results[rid] = []
        t = threading.Thread(target=work, args=(rid, results[rid]))
        threads.append(t)
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    for rid in results:
        assert results[rid][0]["status"] == "ACCEPTED"
        assert results[rid][0]["run_id"] == rid


def test_duplicate_rejected():
    _set_env()
    first = post_sel9_comment("same summary", {"paperclip_run_id": "run-dup"})
    second = post_sel9_comment("same summary", {"paperclip_run_id": "run-dup"})
    assert first["status"] == "ACCEPTED"
    assert second["status"] == "DUPLICATE"
    assert second["code"] == "RUN_ID_REUSED"


def test_unauthorized_publication_rejected(monkeypatch):
    _set_env()
    monkeypatch.setattr("hermes_integration.paperclip.PaperclipRestSink._call",
                        lambda self, method, route, issue, payload: (_ for _ in ()).throw(Exception("403")))
    result = post_sel9_comment("summary", {"paperclip_run_id": "run-403"})
    assert result["status"] == "REJECTED"
    assert result["code"] == "PUBLICATION_REJECTED"


def test_no_env_fallback_does_not_mix():
    os.environ["PAPERCLIP_RUN_ID"] = "GLOBAL-SECRET-RUN"
    try:
        result = post_sel9_comment("summary", {})
        assert result["status"] == "REJECTED"
        assert result["code"] == "RUN_ID_MISSING"
    finally:
        os.environ.pop("PAPERCLIP_RUN_ID", None)

# ---- run id comes from a read-only Paperclip live-run lookup (never model args / prompt / session_id) ----
import json

import hermes_integration.hermes_paperclip_plugin as plug


def _fake_lookup(monkeypatch, status=200, body=None, raises=None, calls=None, by_issue=None):
    answers = {"TEST-9": body if body is not None else [], **(by_issue or {})}
    def transport(method, url, data, headers, timeout, max_bytes):
        if calls is not None:
            calls.append((method, url, data))
        if raises:
            raise raises
        issue = url.split("/api/issues/")[1].split("/")[0]
        return status, {}, json.dumps(answers.get(issue, [])).encode()
    monkeypatch.setattr(plug, "_lookup_transport", transport)


def _call(**kw):
    _set_env()
    return json.loads(plug.hermes_handler({"summary": "s", **kw.pop("args", {})}, task_id="t",
                                          session_id="run_hermes", user_task="- Run ID: prompt-id", **kw))


def test_single_live_run_id_is_used(monkeypatch):
    calls = []
    _fake_lookup(monkeypatch, body=[{"id": "pc-run-0001", "status": "running"}], calls=calls)
    out = _call()
    assert out["status"] == "ACCEPTED" and out["run_id"] == "pc-run-0001"
    assert calls == [("GET", f"https://paperclip.example.test/api/issues/{i}/live-runs", None) for i in plug.APPROVED_ISSUES]  # read-only, one GET per approved issue


def test_finished_runs_are_ignored(monkeypatch):
    _fake_lookup(monkeypatch, body=[{"id": "old-1", "status": "succeeded"}, {"id": "pc-run-0002", "status": "queued"}])
    assert _call()["run_id"] == "pc-run-0002"


def test_zero_live_runs_refused(monkeypatch):
    _fake_lookup(monkeypatch, body=[{"id": "old-1", "status": "failed"}])
    assert _call() == {"status": "REJECTED", "code": "RUN_ID_MISSING", "issue": "TEST-9", "comment_count": 0}
    _fake_lookup(monkeypatch, body=[])
    assert _call()["code"] == "RUN_ID_MISSING"


def test_multiple_live_runs_refused(monkeypatch):
    _fake_lookup(monkeypatch, body=[{"id": "a-1", "status": "running"}, {"id": "b-2", "status": "queued"}])
    out = _call()
    assert out["code"] == "RUN_ID_AMBIGUOUS" and out["comment_count"] == 0


@pytest.mark.parametrize("kw", [dict(status=500, body=[]), dict(status=200, body={"x": 1}),
                                dict(raises=OSError("down")), dict(body=[{"id": "../bad", "status": "running"}])])
def test_lookup_failures_refused(monkeypatch, kw):
    _fake_lookup(monkeypatch, **kw)
    assert _call()["code"] == "LOOKUP_UNAVAILABLE"


def test_model_args_prompt_and_session_never_supply_run_id(monkeypatch):
    _fake_lookup(monkeypatch, body=[])
    out = _call(args={"run_id": "evil-1", "paperclip_run_id": "evil-2"})
    assert out["code"] == "RUN_ID_MISSING"          # prompt "- Run ID: prompt-id" and session_id also ignored


def test_handler_returns_json_string_and_invalid_summary():
    assert isinstance(plug.hermes_handler({"summary": 1}), str)
    assert json.loads(plug.hermes_handler({}))["code"] == "INVALID_SUMMARY"


def test_register_uses_hermes_schema_shape():
    seen = {}
    class Ctx:
        def register_tool(self, **kw): seen.update(kw)
    plug.register(Ctx())
    assert seen["handler"] is plug.hermes_handler
    assert seen["schema"]["parameters"]["required"] == ["summary"] and seen["schema"]["description"]


# ---- credentials come through Hermes's get_secret (profile-scoped), never from a .env file ----
SECRET = "k" * 12 + "SECRET-TOKEN-" + "z" * 12


def _profile_secrets(monkeypatch, values=None):
    """Stand in for agent.secret_scope.get_secret: a profile scope that is NOT os.environ."""
    values = {"PAPERCLIP_API_URL": "https://paperclip.example.test", "PAPERCLIP_API_KEY": SECRET} if values is None else values
    monkeypatch.setattr(plug, "_get_secret", lambda name, default=None: values.get(name, default))
    monkeypatch.delenv("PAPERCLIP_API_URL", raising=False)
    monkeypatch.delenv("PAPERCLIP_API_KEY", raising=False)


def test_secrets_resolved_through_get_secret_and_not_in_os_environ(monkeypatch):
    _profile_secrets(monkeypatch)
    env = plug._config_env()
    assert env["PAPERCLIP_API_URL"] == "https://paperclip.example.test" and env["PAPERCLIP_API_KEY"] == SECRET
    assert "PAPERCLIP_API_KEY" not in os.environ and "PAPERCLIP_API_URL" not in os.environ


def test_process_wide_value_not_used_when_get_secret_has_none(monkeypatch):
    """Multiplexing: another profile's os.environ key must never be picked up when get_secret has no value."""
    _profile_secrets(monkeypatch, values={})
    monkeypatch.setenv("PAPERCLIP_API_KEY", "p" * 32)
    assert "PAPERCLIP_API_KEY" not in plug._config_env()


def test_get_secret_failure_fails_closed(monkeypatch):
    def boom(name, default=None):
        raise RuntimeError("no profile secret scope")
    monkeypatch.setattr(plug, "_get_secret", boom)
    monkeypatch.setattr(plug, "_lookup_transport", lambda *a: (_ for _ in ()).throw(AssertionError("no call")))
    assert "PAPERCLIP_API_KEY" not in plug._config_env()
    assert json.loads(plug.hermes_handler({"summary": "s"}))["code"] == "LOOKUP_UNAVAILABLE"


def test_standalone_fallback_reads_os_environ(monkeypatch):
    monkeypatch.setenv("PAPERCLIP_API_KEY", "p" * 32)
    assert plug._config_env()["PAPERCLIP_API_KEY"] == "p" * 32   # outside Hermes, get_secret is os.environ


def test_lookup_and_write_use_get_secret_never_leak(monkeypatch, caplog, capsys):
    _profile_secrets(monkeypatch)
    seen = {}
    def transport(method, url, data, headers, timeout, max_bytes):
        seen.setdefault("urls", []).append(url)
        seen["auth"] = headers["Authorization"]
        live = [{"id": "pc-run-0009", "status": "running"}] if "/TEST-9/" in url else []
        return 200, {}, json.dumps(live).encode()
    monkeypatch.setattr(plug, "_lookup_transport", transport)
    caplog.set_level("DEBUG")
    out = plug.hermes_handler({"summary": "s"})
    assert json.loads(out)["run_id"] == "pc-run-0009" and json.loads(out)["status"] == "ACCEPTED"
    assert seen["urls"] == [f"https://paperclip.example.test/api/issues/{i}/live-runs" for i in plug.APPROVED_ISSUES]
    assert seen["auth"] == "Bearer " + SECRET                                     # used for the read...
    assert SECRET not in out and SECRET not in caplog.text                        # ...but never returned or logged
    cap = capsys.readouterr()
    assert SECRET not in cap.out + cap.err
    assert "PAPERCLIP_API_KEY" not in os.environ


def test_wrong_origin_or_missing_secrets_fail_closed(monkeypatch):
    monkeypatch.setattr(plug, "_lookup_transport", lambda *a: (_ for _ in ()).throw(AssertionError("no call")))
    _profile_secrets(monkeypatch, values={"PAPERCLIP_API_URL": "https://evil.example", "PAPERCLIP_API_KEY": "a" * 32})
    assert json.loads(plug.hermes_handler({"summary": "s"}))["code"] == "LOOKUP_UNAVAILABLE"   # origin gate
    _profile_secrets(monkeypatch, values={})
    assert json.loads(plug.hermes_handler({"summary": "s"}))["code"] == "LOOKUP_UNAVAILABLE"   # no secrets


def test_plugin_never_reads_dotenv_files():
    import inspect
    src = inspect.getsource(plug)
    assert ".env" not in src.replace("os.environ", "") and "read_text" not in src


def test_model_cannot_choose_issue_and_unapproved_issue_refused(monkeypatch):
    _fake_lookup(monkeypatch, body=[{"id": "pc-run-0001", "status": "running"}])
    out = _call(args={"issue": "TEST-1", "work_item_id": "TEST-1"})
    assert out["issue"] == "TEST-9"                       # args ignored; the lookup picked TEST-9
    assert plug.post_sel9_comment("s", tool_context={"paperclip_run_id": "r-1"}, issue="TEST-1")["code"] == "ISSUE_NOT_APPROVED"


def test_sink_gate_allows_only_approved_issues():
    from hermes_integration.paperclip import SYNTHETIC_TEST_ISSUES
    assert SYNTHETIC_TEST_ISSUES == ("TEST-9", "TEST-21", "TEST-22", "TEST-23")      # == PAPERCLIP_APPROVED_ISSUES in conftest.py
    assert len(set(SYNTHETIC_TEST_ISSUES)) == 4
    _set_env()
    os.environ["PAPERCLIP_SYNTHETIC_TEST_APPROVAL"] = "PAPERCLIP_COMMENT_ONLY_APPROVED"
    try:
        tool = register_paperclip_writeback_tool(env={**os.environ, "PAPERCLIP_RUN_ID": "r-gate"}, run_id="r-gate")
    finally:
        os.environ.pop("PAPERCLIP_SYNTHETIC_TEST_APPROVAL", None)
    for ok in ("TEST-9", "TEST-21", "TEST-23"):
        tool.post_comment(ok, {"mock": False, "reasons": ["x"]})              # approved: no exception (network stubbed)
    for issue in ("TEST-1", "TEST-11", "TEST-24", "TEST-30"):  # not configured
        with pytest.raises(Exception, match="SYNTHETIC_ISSUE_NOT_APPROVED"):
            tool.post_comment(issue, {"mock": False, "reasons": ["x"]})


def test_unconfigured_plugin_approves_nothing():
    """Fail closed: with no PAPERCLIP_APPROVED_* variables no origin and no issue is approved."""
    import subprocess, sys
    code = ("import os\n"
            "for k in ('PAPERCLIP_APPROVED_ORIGIN', 'PAPERCLIP_APPROVED_ISSUES'): os.environ.pop(k, None)\n"
            "from hermes_integration import paperclip as p\n"
            "assert p.SYNTHETIC_TEST_ISSUES == () and p.SYNTHETIC_TEST_ORIGIN == ''\n"
            "try:\n"
            "    p.check_base_url('https://paperclip.example.test', synthetic_test=True)\n"
            "except Exception as e:\n"
            "    print(type(e).__name__)\n"
            "else:\n"
            "    raise SystemExit('origin was accepted')\n")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, cwd=os.getcwd())
    assert out.returncode == 0 and out.stdout.strip() == "RealModeLocked", (out.stdout, out.stderr)
