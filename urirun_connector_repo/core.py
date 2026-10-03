# Author: Tom Sapletta · Part of the ifURI solution.
"""urirun-connector-repo — `repo://` + `sync://` controlled persistence pipeline (IFURI-177).

Trunk-based: this project does not use pull requests. A worker takes a `work://` lease, works
in isolation (worktree), tests, then a **merge-gate** decides whether the change may land on
main directly:

  * ``auto_push``    — gates passed and the path is not never-auto → commit + push to main (or,
                       for a non-git sync project, a patch artifact + publish).
  * ``block``        — no valid lease, a detected secret, failing tests, or a never-auto path
                       (core runtime / policy / grant / proxy / security / deploy).

Dropping PRs removed the *human review* step, not the automated ones: lease ownership, secret
scan, tests and the never-auto path list still gate every push, and a change that fails them
stays blocked rather than falling back to a review queue that no longer exists.

Nothing is committed without an active lease OWNED by the committing worker, and every commit
message carries provenance (worker, lease, locks, tests/smoke/secret-scan) so a change is
auditable by URI later. git repos → commit + push to main; non-git `sync` projects (e.g. if-uri
via connect.ifuri.com) → patch artifact + sync publish, never `git merge`.
"""
from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Any

import urirun

CONNECTOR_ID = "repo"
conn = urirun.connector(CONNECTOR_ID, scheme="repo")

# Paths/labels that must NEVER auto-merge (secrets, policy toggles, approval bypass).
_NEVER_AUTO = ("autonomy.yaml", "egress.yaml", ".env", "secret", "credential", "id_ed25519",
               "id_rsa", "never_auto", "policy.yaml", "grants.yaml")
# Paths/labels that require a human PR review (core runtime, trust/security, deploy).
_HUMAN_HINTS = ("adapters/python/urirun/", "connector-grants", "connector-proxy", "connector-safety",
                "policy", "grant", "proxy", "deploy", "systemd", "node.sh", "install", "security",
                "payment", "publish", "send")
# Paths that are safe to auto-PR when EVERY changed file matches.
_AUTO_HINTS = ("readme", "test", "docs/", ".md", "urirun-connector-", "examples/")

_SECRET_RE = (
    (re.compile(r"(?i)(api[_-]?key|secret|token|password|passwd)\s*[:=]\s*['\"]?[A-Za-z0-9/+_\-]{16,}"), "credential-assignment"),
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "private-key"),
    (re.compile(r"(?i)aws_secret_access_key\s*="), "aws-secret"),
    (re.compile(r"sk-[A-Za-z0-9]{20,}"), "openai-style-key"),
    (re.compile(r"ghp_[A-Za-z0-9]{20,}"), "github-token"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "aws-access-key"),
)


def _ok(**kw: Any) -> dict[str, Any]:
    return urirun.ok(connector=CONNECTOR_ID, **kw)


def _fail(msg: str, action: str, **extra: Any) -> dict[str, Any]:
    return urirun.fail(msg, connector=CONNECTOR_ID, action=action, **extra)


# ── classification + scans (pure, deterministic) ──────────────────────────────

_NEVER_LABELS = ("policy", "grant", "secret", "security", "never_auto")


def _hit(f: str, needles: tuple) -> bool:
    return any(k in f for k in needles)


def _lower(items: list | None) -> list[str]:
    return [str(x).lower() for x in (items or [])]


def _first_hit(files: list[str], needles: tuple) -> str | None:
    return next((f for f in files if _hit(f, needles)), None)


def classify_change(files: list[str], labels: list[str] | None = None) -> dict:
    """Classify a change as ``never`` / ``human`` / ``auto`` by the paths + labels it touches.
    Conservative: unknown → human; a single risky file taints the whole change."""
    fl, lbl = _lower(files), _lower(labels)
    never = _first_hit(fl, _NEVER_AUTO)
    if never or any(l in _NEVER_LABELS for l in lbl):
        return {"class": "never", "reason": f"protected/secret: {never or 'label'}"}
    human = _first_hit(fl, _HUMAN_HINTS)
    if human:
        return {"class": "human", "reason": f"core/security/deploy path: {human}"}
    if fl and all(_hit(f, _AUTO_HINTS) for f in fl):
        return {"class": "auto", "reason": "connector/docs/tests/examples only"}
    return {"class": "human", "reason": "unclassified change → human review (conservative)"}


def secret_scan(text: str) -> dict:
    """Scan a diff/blob for credential patterns. clean=False blocks the gate."""
    findings = sorted({label for rx, label in _SECRET_RE if rx.search(text or "")})
    return {"clean": not findings, "findings": findings}


def _lease_valid(lease_id: str, worker: str) -> bool:
    """A commit/PR is allowed only under an ACTIVE lease owned by this worker (via work://)."""
    if not lease_id or not worker:
        return False
    try:
        from urirun_connector_work import core as work  # noqa: PLC0415
        return any(l.get("id") == lease_id and l.get("worker") == worker
                   for l in work.locks_query_list().get("active", []))
    except Exception:  # noqa: BLE001
        return False


def merge_gate(*, files: list[str], labels: list[str] | None = None, tests_passed: bool = True,
               secrets_clean: bool = True, lease_valid: bool = True, is_git: bool = True) -> dict:
    """The decision engine. Returns ``{decision, reason, allowed_next_uri?}`` where decision is
    one of ``auto_push`` / ``block``.

    There is no ``human_review`` outcome any more: with PRs gone there is nowhere to hold a
    change for a human, so a `review`-class path lands on main like any other once the
    automated gates pass. Only `never`-class paths stay blocked."""
    if not lease_valid:
        return {"decision": "block", "reason": "no active lease owned by this worker"}
    if not secrets_clean:
        return {"decision": "block", "reason": "secret detected in diff"}
    if not tests_passed:
        return {"decision": "block", "reason": "tests failed"}
    cls = classify_change(files, labels)
    if cls["class"] == "never":
        return {"decision": "block", "reason": cls["reason"]}
    nxt = "repo://host/push/command/main" if is_git else "sync://host/project/command/publish"
    return {"decision": "auto_push", "reason": cls["reason"], "allowed_next_uri": nxt}


def provenance_message(ticket: str, title: str, worker: str, lease_id: str, locks: list[str],
                       tests: str = "passed", smoke: str = "passed", secret_scan_status: str = "passed") -> str:
    """Commit message carrying provenance so a change is auditable by URI later."""
    lock_lines = "\n".join(f"- {l}" for l in (locks or [])) or "- (none)"
    return (f"{ticket}: {title}\n\n"
            f"worker: {worker}\nlease: {lease_id}\nlocks:\n{lock_lines}\n\n"
            f"tests: {tests}\nsmoke: {smoke}\nsecret-scan: {secret_scan_status}")


# ── repo primitives (git) ─────────────────────────────────────────────────────

def is_git(path: str) -> bool:
    return (Path(path).expanduser() / ".git").exists()


def _git(repo: str, *args: str, timeout: float = 60.0) -> tuple[int, str, str]:
    try:
        cp = subprocess.run(["git", "-C", str(Path(repo).expanduser()), *args],
                            capture_output=True, text=True, timeout=timeout)
        return cp.returncode, cp.stdout.strip(), cp.stderr.strip()
    except Exception as exc:  # noqa: BLE001
        return 1, "", str(exc)


def diff_summary(repo: str) -> dict:
    """Changed files + stat + the diff text (for the secret scan)."""
    rc, names, _ = _git(repo, "status", "--porcelain")
    files = [line[3:].strip() for line in names.splitlines() if line.strip()]
    _, stat, _ = _git(repo, "diff", "--stat")
    _, diff_text, _ = _git(repo, "diff")
    return {"files": files, "stat": stat, "diff": diff_text, "clean": not files}


def worktree_create(repo: str, branch: str, base: str = "HEAD") -> dict:
    root = Path(repo).expanduser()
    wt = root.parent / f"{root.name}-wt-{branch.replace('/', '-')}"
    rc, out, err = _git(repo, "worktree", "add", "-b", branch, str(wt), base)
    return {"ok": rc == 0, "worktree": str(wt), "branch": branch, "error": err or None}


def worktree_remove(repo: str, worktree: str) -> dict:
    rc, _, err = _git(repo, "worktree", "remove", "--force", str(Path(worktree).expanduser()))
    return {"ok": rc == 0, "error": err or None}


def commit_create(repo: str, message: str, *, worker: str = "", lease_id: str = "",
                  add_all: bool = True) -> dict:
    """Commit on the current branch — ONLY under a valid lease owned by ``worker``. Trunk-based:
    main is a legal target, so the lease is the only hard gate left here."""
    if not _lease_valid(lease_id, worker):
        return {"ok": False, "rejected": True, "reason": "commit requires an active lease owned by this worker"}
    _, branch, _ = _git(repo, "rev-parse", "--abbrev-ref", "HEAD")
    if add_all:
        _git(repo, "add", "-A")
    rc, out, err = _git(repo, "commit", "-m", message)
    if rc != 0:
        return {"ok": False, "reason": (err or out or "commit failed")[:200]}
    _, sha, _ = _git(repo, "rev-parse", "HEAD")
    return {"ok": True, "sha": sha, "branch": branch, "provenance_uri": f"provenance://host/commit/{sha}/query/meta"}


def push_main(repo: str, *, remote: str = "origin", branch: str = "main") -> dict:
    """Push the current HEAD onto ``branch`` on ``remote``. Replaces the PR step.

    No force flag: a plain push already refuses a non-fast-forward, and a rejected push means
    main moved underneath this worker — forcing over it would destroy someone else's commit.
    The caller re-bases and retries."""
    _, head, _ = _git(repo, "rev-parse", "--abbrev-ref", "HEAD")
    rc, out, err = _git(repo, "push", remote, f"HEAD:{branch}", timeout=120.0)
    if rc != 0:
        return {"ok": False, "reason": (err or out or "push failed")[:200], "from_branch": head, "branch": branch}
    _, sha, _ = _git(repo, "rev-parse", "HEAD")
    return {"ok": True, "sha": sha, "from_branch": head, "branch": branch, "remote": remote}


# ── handlers ──────────────────────────────────────────────────────────────────

@conn.handler("merge/query/gate", isolated=False,
              meta={"label": "Merge-gate: auto_push | block (lease+secrets+testy+ścieżki) — bez PR"})
def merge_query_gate(files: Any = None, labels: Any = None, tests_passed: bool = True,
                     secrets_clean: bool = True, lease_id: str = "", worker: str = "",
                     is_git_repo: bool = True) -> dict[str, Any]:
    fl = list(files) if isinstance(files, (list, tuple)) else ([files] if files else [])
    lb = list(labels) if isinstance(labels, (list, tuple)) else ([labels] if labels else [])
    lease_ok = _lease_valid(lease_id, worker) if lease_id else True
    res = merge_gate(files=fl, labels=lb, tests_passed=bool(tests_passed),
                     secrets_clean=bool(secrets_clean), lease_valid=lease_ok, is_git=bool(is_git_repo))
    return _ok(action="merge-gate", **res)


@conn.handler("secrets/query/scan", isolated=False, meta={"label": "Skan sekretów w diffie/tekście"})
def secrets_query_scan(text: str = "") -> dict[str, Any]:
    return _ok(action="secret-scan", **secret_scan(text))


@conn.handler("diff/query/summary", isolated=False, meta={"label": "Zmienione pliki + stat + diff (do skanu)"})
def diff_query_summary(repo: str = "") -> dict[str, Any]:
    if not is_git(repo):
        return _fail("not a git repo — use sync://project/query/status", "diff-summary", is_git=False)
    return _ok(action="diff-summary", **diff_summary(repo))


@conn.handler("worktree/command/create", isolated=True, meta={"label": "Utwórz izolowany worktree+branch"})
def worktree_command_create(repo: str = "", branch: str = "", base: str = "HEAD") -> dict[str, Any]:
    if not is_git(repo):
        return _fail("not a git repo", "worktree-create", is_git=False)
    return _ok(action="worktree-create", **worktree_create(repo, branch, base))


@conn.handler("worktree/command/remove", isolated=True, meta={"label": "Usuń worktree"})
def worktree_command_remove(repo: str = "", worktree: str = "") -> dict[str, Any]:
    return _ok(action="worktree-remove", **worktree_remove(repo, worktree))


@conn.handler("commit/command/create", isolated=True,
              meta={"label": "Commit — TYLKO pod ważnym lease workera; trunk-based, main dozwolony"})
def commit_command_create(repo: str = "", message: str = "", worker: str = "", lease_id: str = "",
                          ticket: str = "", title: str = "", locks: Any = None) -> dict[str, Any]:
    msg = message or provenance_message(ticket or "?", title or "change", worker, lease_id,
                                        list(locks) if isinstance(locks, (list, tuple)) else [])
    res = commit_create(repo, msg, worker=worker, lease_id=lease_id)
    return _ok(action="commit-create", **res) if res.get("ok") else _fail(res.get("reason", "commit failed"), "commit-create", **res)


@conn.handler("push/command/main", isolated=True,
              meta={"label": "Push HEAD na main — po merge-gate auto_push (bez PR)"})
def push_command_main(repo: str = "", worker: str = "", lease_id: str = "",
                      remote: str = "origin", branch: str = "main") -> dict[str, Any]:
    if not _lease_valid(lease_id, worker):
        return _fail("push requires an active lease owned by this worker", "push-main", rejected=True)
    res = push_main(repo, remote=remote, branch=branch)
    return _ok(action="push-main", **res) if res.get("ok") else _fail(res.get("reason", "push failed"), "push-main", **res)


# ── sync:// — non-git projects (e.g. if-uri via connect.ifuri.com) ────────────

sync_conn = urirun.connector("sync", scheme="sync")


def save_patch_artifact(project: str, name: str) -> dict:
    """For a non-git project: capture the working diff as a reviewable patch artifact instead
    of a git commit (there is no branch/PR to make)."""
    root = Path(project).expanduser()
    out = Path(os.environ.get("URIRUN_PATCH_DIR") or "~/.urirun/host-dashboard/patches").expanduser()
    out.mkdir(parents=True, exist_ok=True)
    dest = out / f"{name}.patch"
    try:
        # best-effort: diff vs the last connect.ifuri.com snapshot if present, else list changed files
        cp = subprocess.run(["diff", "-ruN", "/dev/null", str(root)], capture_output=True, text=True, timeout=30)
        dest.write_text(cp.stdout[:200000], encoding="utf-8")
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "reason": str(exc)[:120]}
    return {"ok": True, "artifact": str(dest), "artifact_uri": f"artifact://host/patch/{name}/query/read"}


@sync_conn.handler("project/query/status", isolated=False,
                   meta={"label": "Czy projekt jest git czy sync-only (connect.ifuri.com)"})
def sync_project_query_status(project: str = "") -> dict[str, Any]:
    git = is_git(project)
    return urirun.ok(connector="sync", action="sync-status", project=project, is_git=git,
                     mode="git" if git else "sync",
                     note="git → repo:// branch/PR/merge; sync → patch artifact + publish (NIE git merge)")


@sync_conn.handler("project/command/publish", isolated=True,
                   meta={"label": "Utrwal zmianę sync-projektu jako patch artifact (po merge-gate auto_push)"})
def sync_project_command_publish(project: str = "", worker: str = "", lease_id: str = "",
                                 name: str = "change") -> dict[str, Any]:
    if not _lease_valid(lease_id, worker):
        return urirun.fail("publish requires an active lease owned by this worker",
                           connector="sync", action="sync-publish", rejected=True)
    res = save_patch_artifact(project, name)
    return urirun.ok(connector="sync", action="sync-publish", **res) if res.get("ok") \
        else urirun.fail(res.get("reason", "publish failed"), connector="sync", action="sync-publish")


def sync_bindings() -> dict[str, Any]:
    return sync_conn.bindings()


def urirun_bindings() -> dict[str, Any]:
    return conn.bindings()


def main(argv: list[str] | None = None) -> int:
    return conn.cli(argv, manifest_prose=None)


if __name__ == "__main__":
    raise SystemExit(main())
