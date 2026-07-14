# urirun-connector-repo — `repo://` + `sync://` controlled persistence (IFURI-177)

Ends the *"Nothing committed (Tom commits)"* bottleneck **without** letting an agent commit to
main. A worker holds a `work://` lease, works in a worktree, tests, then a **merge-gate** decides
how the change may be persisted. The human only approves what the gate flags as needing review.

```
work claim-next → worktree → change → diff → tests → secret-scan → merge-gate
   ├─ auto_pr      → branch + PR   (git)   /  patch artifact + publish (sync project)
   ├─ human_review → PR held for approval://
   └─ block        → no lease / secret / tests fail / never-auto path
release lease (finally)
```

## Merge-gate decisions

`repo://host/merge/query/gate` returns one of:

| decision | when | allowed_next_uri |
|----------|------|------------------|
| `auto_pr` | connector / README / tests / docs / examples, tests pass, no secret, lease valid | `repo://host/pr/command/create` (git) or `sync://host/project/command/publish` |
| `human_review` | core runtime / `policy`/`grant`/`proxy` / security / deploy / send·publish·payment | `approval://human/pr/command/review` |
| `block` | no valid lease · secret in diff · tests failed · never-auto path (`.env`, `autonomy.yaml`, secrets) | — |

Conservative: an unclassified or mixed change defaults to `human_review`; one risky file taints
the whole change; `never-auto` paths never merge even when tests pass.

## Guarantees

- **No commit without a lease** owned by the committing worker (`work://` checked live).
- **Never main** — `commit/command/create` refuses `main`/`master`; work happens on a branch/worktree.
- **Provenance in every commit** — worker, lease, locks, tests/smoke/secret-scan — auditable by
  `provenance://host/commit/<sha>/query/meta`.
- **git vs sync** — git repos → branch/PR; non-git `sync` projects (e.g. `if-uri` via
  connect.ifuri.com) → **patch artifact + publish**, never `git merge`.

## Routes

`repo://` — `merge/query/gate`, `secrets/query/scan`, `diff/query/summary`,
`worktree/command/{create,remove}`, `commit/command/create`, `pr/command/create`.
`sync://` — `project/query/status`, `project/command/publish`.

## Integration with IFURI-176 (work://)

`repo://` has **no scheduler of its own** — it is the *persistence* gate; `work://` is the *work*
gate. `claim-next` gives the ticket + lease; the pipeline checks that lease at commit/PR; the
commit records the `lease_id`; `release` frees it in `finally`.

## Tests

```bash
python -m pytest tests/ -q   # 17 passed
```
