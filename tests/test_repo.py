"""repo:// + sync:// controlled persistence pipeline + merge-gate (IFURI-177)."""
from __future__ import annotations

from urirun_connector_repo import core


# ── classification + secret scan ──────────────────────────────────────────────

def test_classify_connector_docs_tests_are_auto():
    assert core.classify_change(["urirun-connector-kvm/README.md"])["class"] == "auto"
    assert core.classify_change(["urirun-connector-work/tests/test_work.py"])["class"] == "auto"
    assert core.classify_change(["docs/guide.md"])["class"] == "auto"


def test_classify_core_runtime_is_human():
    assert core.classify_change(["urirun/adapters/python/urirun/host/dispatch.py"])["class"] == "human"
    assert core.classify_change(["urirun-connector-grants/core.py"])["class"] == "human"


def test_classify_secret_paths_are_never():
    assert core.classify_change([".env"])["class"] == "never"
    assert core.classify_change(["config/autonomy.yaml"])["class"] == "never"
    assert core.classify_change(["x.py"], labels=["policy"])["class"] == "never"


def test_classify_mixed_change_taints_to_strictest():
    # one core file among safe files → human (not auto)
    assert core.classify_change(["a/README.md", "urirun/adapters/python/urirun/core.py"])["class"] == "human"


def test_secret_scan_detects_and_passes_clean():
    assert core.secret_scan("api_key = 'ABCD1234ABCD1234ABCD'")["clean"] is False
    assert core.secret_scan("token: ghp_ABCDEFGHIJKLMNOPQRSTUV")["findings"]
    assert core.secret_scan("-----BEGIN OPENSSH PRIVATE KEY-----")["clean"] is False
    assert core.secret_scan("just some normal code text")["clean"] is True


# ── merge-gate decisions (the 10 scenarios) ───────────────────────────────────

def test_3_connector_only_change_auto_pr():
    d = core.merge_gate(files=["urirun-connector-kvm/README.md"])
    assert d["decision"] == "auto_pr" and d["allowed_next_uri"].startswith("repo://")


def test_4_core_runtime_change_human_review():
    d = core.merge_gate(files=["urirun/adapters/python/urirun/host/dispatch.py"])
    assert d["decision"] == "human_review" and d["allowed_next_uri"].startswith("approval://")


def test_5_secret_scan_fail_blocks():
    d = core.merge_gate(files=["urirun-connector-kvm/README.md"], secrets_clean=False)
    assert d["decision"] == "block" and "secret" in d["reason"]


def test_6_tests_fail_blocks():
    d = core.merge_gate(files=["urirun-connector-kvm/README.md"], tests_passed=False)
    assert d["decision"] == "block" and "test" in d["reason"]


def test_1_gate_blocks_without_valid_lease():
    d = core.merge_gate(files=["urirun-connector-kvm/README.md"], lease_valid=False)
    assert d["decision"] == "block" and "lease" in d["reason"]


def test_7_non_git_project_routes_to_sync_publish():
    d = core.merge_gate(files=["urirun-connector-kvm/README.md"], is_git=False)
    assert d["decision"] == "auto_pr" and d["allowed_next_uri"].startswith("sync://")


def test_never_auto_change_blocks_even_if_tests_pass():
    d = core.merge_gate(files=[".env"], tests_passed=True, secrets_clean=True)
    assert d["decision"] == "block"


# ── lease-gated commit (1, 2, 8) ──────────────────────────────────────────────

def test_1_commit_rejected_without_lease(monkeypatch):
    monkeypatch.setattr(core, "_lease_valid", lambda lid, w: False)
    r = core.commit_create("/x", "msg", worker="w1", lease_id="")
    assert r["ok"] is False and r["rejected"] is True


def test_2_commit_rejected_foreign_lease(monkeypatch):
    # _lease_valid checks ownership; a foreign lease → invalid → rejected
    monkeypatch.setattr(core, "_lease_valid", lambda lid, w: False)
    r = core.commit_create("/x", "msg", worker="w2", lease_id="lease:w1:T1")
    assert r["rejected"] is True


def test_8_commit_refuses_main_branch(monkeypatch):
    monkeypatch.setattr(core, "_lease_valid", lambda lid, w: True)
    monkeypatch.setattr(core, "_git", lambda repo, *a, **k: (0, "main", ""))  # HEAD is main
    r = core.commit_create("/x", "msg", worker="w1", lease_id="lease:w1:T1")
    assert r["ok"] is False and "main" in r["reason"]


def test_lease_valid_checks_work_connector(monkeypatch):
    import types
    fake = types.SimpleNamespace(locks_query_list=lambda: {"active": [{"id": "lease:w1:T1", "worker": "w1"}]})
    monkeypatch.setitem(__import__("sys").modules, "urirun_connector_work", types.SimpleNamespace(core=fake))
    assert core._lease_valid("lease:w1:T1", "w1") is True
    assert core._lease_valid("lease:w1:T1", "w2") is False  # ownership


# ── provenance message ────────────────────────────────────────────────────────

def test_provenance_message_carries_audit_fields():
    msg = core.provenance_message("IFURI-177", "add merge gate", "koru-worker-1", "lease:abc",
                                  ["repo:if-uri/urirun-fleet", "path:urirun_fleet/executor.py"])
    assert "IFURI-177: add merge gate" in msg
    assert "worker: koru-worker-1" in msg and "lease: lease:abc" in msg
    assert "path:urirun_fleet/executor.py" in msg
    assert "tests: passed" in msg and "secret-scan: passed" in msg
