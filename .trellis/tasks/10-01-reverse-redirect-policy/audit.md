# TEAM B delivery audit — 2026-10-01

## Verdict

The current workspace does not contain an implemented delivery of this task.
Acceptance cannot pass on the available artifacts. This is a delivery audit,
not a finding that TEAM B introduced a regression.

The user confirmed that `D:/Repositories/Resin` is the delivery location. The
reviewed HEAD is `79b8ee97200e703e2a3a8d433589fcf7e5f5000a` on `master`.
Before this report was added, the only untracked change was this task directory;
`git diff --name-only HEAD` was empty. There was one worktree and no other local
branch. Local Git refs contained no redirect-related implementation commit.

## Findings

### 1. Blocking: no implementation of the stated remediation goal

- `task.json:6` remains `planning`; commit, branch, and completion metadata are
  unset. This metadata alone would not prove absence of implementation, but
  the source and Git checks below corroborate it.
- The reverse proxy still uses a single upstream round trip
  (`internal/proxy/reverse.go:330`) and does not implement redirect following
  or Location rewriting (`internal/proxy/reverse.go:367`). Request decisions
  have no redirect policy (`internal/proxy/reverse_decision.go:15`).
- No redirect-policy configuration is present in the runtime platform model
  (`internal/platform/platform.go:27`), platform service contracts
  (`internal/service/control_plane_platform.go:24`, `:328`), or WebUI platform
  types (`webui/src/features/platforms/types.ts:5`). Searches of proxy, state,
  service, API, and WebUI code found no redirect-policy implementation.
- The latest state migration is still `000010_platform_tls_policy`.

Impact: the identity-chain gap described in `prd.md:5` has not been remediated
in this workspace. This is existing behavior, not a newly introduced defect.
The absent configuration layers are corroborating evidence, not a requirement
to select a particular policy design before that design has been agreed.

### 2. Blocking: no testable acceptance contract

- `prd.md:48`: requirements are `TBD (interview in progress)`.
- `prd.md:52`: the only acceptance criterion is `TBD`.
- `prd.md:63`: supported modes and default remain undecided.
- `prd.md:65`: platform versus global configuration remains undecided.
- `prd.md:66`: rewrite scope and cross-host identity behavior remain undecided.

Impact: a reviewer cannot determine the expected behavior or approve a finished
implementation. Resolve these decisions and define observable acceptance cases
before claiming this task is complete.

### 3. Planning context and verification evidence are incomplete

Both `implement.jsonl:1` and `check.jsonl:1` contain only the `_example` seed.
There is no `design.md`, `implement.md`, or task-specific verification record.
The seed manifests do not satisfy the sub-agent planning gate; see
`.trellis/workflow.md:444`. Design and implementation plans are additionally
required if the final scope is complex.

`python ./.trellis/scripts/task.py validate reverse-redirect-policy` exited
successfully but explicitly reported **0 entries** for each manifest. That
result validates the available context files; it is not evidence of planning
readiness, implemented behavior, or passing functional tests.

### 4. The PRD misstates part of the current behavior

`prd.md:10` attributes relative redirects to 401/404 errors from `parsePathV1`.
For a root-relative Location such as `/x`, the reverse parser returns
`ErrAuthFailed` when the token does not match, or `ErrURLParseError` when there
are too few segments (`internal/proxy/reverse.go:168`). Those errors map to
**403 and 400**, respectively (`internal/proxy/errors.go:27`).

Relative references must also be distinguished: `/x` removes the identity
prefix, whereas `next` under an upstream directory or a query-only reference
can preserve it. An absolute URL pointing to the upstream causes a following
client to leave Resin. These cases need distinct acceptance examples; the
blanket description of relative references is too broad.

The initial 3xx response is recorded as network success
(`internal/proxy/reverse.go:410`). A subsequent request rejected during path
parsing emits no request event, which is explicitly asserted by the existing
`TestReverseProxy_ParseError_EmitsNoEvents`
(`internal/proxy/proxy_test.go:1272`). This supports the original logging-gap
concern but is not a new regression from this task.

## Verification scope

- Inspected task artifacts, tracked/untracked changes, local branches, local
  remote-tracking refs, worktrees, commit history, and relevant source contracts.
- No remote refresh was performed; the user identified this workspace as the
  delivery under review.
- No application source or task lifecycle state was changed by this audit.
- Existing proxy behavior and test availability were independently reviewed
  by a read-only Trellis check sub-agent.
- Targeted Go tests and `go vet` did not reach execution: the installed local
  toolchain is Go 1.25.1, below the Go 1.25.5 requirement in `go.mod:3`.
  Automatic toolchain selection also encountered a cache-lock access denial.
  These are environment limitations, not observed functional test failures.
  No passing runtime verification is claimed. No toolchain or dependency
  installation was undertaken, since there is no implementation to validate.

## Required before implementation acceptance

1. Finalize policy behavior, defaults, scope, and concrete acceptance criteria.
2. Complete the applicable planning artifacts and real context manifests.
3. Deliver the source changes and tests against that contract, with a
   reproducible verification record.

This audit deliberately does not choose PASS_THROUGH, REWRITE, or FOLLOW on
behalf of the product owner.
