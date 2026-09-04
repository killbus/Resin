# TEAM B implementation and verification plan

## Handoff contract

Read [prd.md](prd.md), [design.md](design.md), and
[research/implementation-map.md](research/implementation-map.md) in that order.
PRD requirements and acceptance own behavior. The task is planning; these
unchecked items are work for TEAM B, not implementation completion claims.

Before TEAM B starts, inspect current working changes and the next available
migration number. Preserve unrelated work. Load the curated implement.jsonl
context; do not expand this task into FOLLOW or cross-origin support. The PRD
already resolves the first-release product choices. The user's implementation
handoff/authorization and normal task start are separate from this document edit.

## Ordered implementation checklist

### 1. Model, defaults, persistence — R1; AC01–AC04

- [ ] Add exact enum and stored/runtime fields; carry them through constructors
  and BuildFromModel. Update direct test fixtures intentionally.
- [ ] Add/validate the env creation default and system response projection;
  wire fresh Default creation and custom create/reset. Existing rows must not
  adopt an env override on migration/restart.
- [ ] Append the state migration and update ordinary and aggregate SQL
  insert/update/select/scan paths. Cover old-database migration and reopen.
- [ ] Verify model/SQL/runtime round-trip for both values before integrating
  request behavior. Do not edit the historical TLS migration.

### 2. Service/API save contract — R1; AC02–AC04

- [ ] Add field to Platform responses and presence-aware create/config inputs;
  update PATCH allowlist and validation. Reject explicit null/empty/type/enum
  errors across endpoints.
- [ ] Preserve omitted values on legacy PATCH and old-client aggregate PUT.
  Merge under the mutation lock, carry through config_version/CAS and the
  existing aggregate transaction/publication sequence.
- [ ] Cover Default ordinary-field editability, reset defaults, singular TLS
  changes preserving the field, aggregate Platform+TLS saves, stale version,
  runtime preparation failure, and persistence rollback without partial publish.

### 3. URL policy and reverse integration — R2–R6; AC04–AC17, AC19

- [ ] Build the pure URL helper, duplicate/empty handling, origin comparison,
  URI validation, and safe root-relative prefix serialization. Include
  escaped identity, auth-disabled token, encoded dots, and ForceQuery cases.
- [ ] Capture mode from the resolver's Platform snapshot; preserve normal
  per-request Account extraction/TLS/egress and PASS_THROUGH baseline.
- [ ] Integrate one-hop ModifyResponse processing without body replay; strip
  outbound Referer only in REWRITE and set specified rewrite response headers.
- [ ] Add typed local redirect-error handling before generic transport
  classification. Preserve one positive routed response feedback, NetOK=true,
  current request attribution/log completion, body ownership, and 101 behavior.
- [ ] Ensure original headers are captured before a generated token-bearing
  Location is introduced, in both body and no-body paths.
- [ ] Exercise local upstream A/B fixtures with actual following clients,
  credentials, POST 303/307/308, loops, direct/routed HTTP/HTTPS, and snapshot
  changes. Assert B receives zero requests on blocked cross-origin redirects.

### 4. WebUI and operator docs — R7; AC18

- [ ] Add enum/defaults/types, draft initialization and serialization, create
  and detail controls, dirty/reset/read-back behavior, and both translations.
  Preserve the existing aggregate save flow and TLS controls.
- [ ] Update system-default types used by Platform creation. Test non-default
  env values and saved policies, not only PASS_THROUGH fixtures.
- [ ] Update DESIGN.md API/schema/env sections and applicable README/operator
  integration guidance. Document same-origin including scheme/port, error codes,
  per-request Account guidance, no fixed-IP promise, and PASS_THROUGH rollback.
- [ ] Record the accepted implementation contract in the appropriate backend
  spec and index; keep TLS-specific restrictions distinct from redirect policy.

### 5. Full verification and evidence — all ACs

- [ ] Review the complete change against check.jsonl and AC01–AC19, including
  unaffected forward/CONNECT/SOCKS and reverse streaming/upgrade behavior.
- [ ] Run the commands below in a compatible toolchain and address failures
  caused by this task. Record unrelated baseline failures with concrete evidence.
- [ ] Create verification.md in this task directory with revision/diff scope,
  environment, commands/results, each AC's test or manual evidence, and any
  remaining limitation. Do not turn an unexecuted check into a pass.
- [ ] Provide the implementation diff and evidence for review. Do not claim
  acceptance solely from task.py validate or unchecked PRD criteria.

## Validation commands

These commands are for the implementation stage. They were not executed as
runtime validation while producing this planning package.

First confirm Go >= 1.25.5 (go.mod), Node/npm, and a supported race-test/CGO
environment where required. The earlier local toolchain could not run Go tests;
use a prepared compatible environment rather than treating it as a code result.
Install locked WebUI dependencies with npm ci if needed in that environment.

At repository root, format changed Go files with gofmt, then run:

```text
go test ./internal/config ./internal/platform ./internal/state ./internal/service ./internal/api ./internal/proxy ./cmd/resin
go test ./...
go vet ./...
go test -race ./internal/proxy ./internal/service ./internal/state ./internal/topology ./internal/tlspolicy
git diff --check
```

The focused test command is for early iteration. Once full tests and required
checks pass, repeat only when later changes or unresolved failures justify it.
The race check verifies publication/lifecycle changes; run it on a supported
platform rather than silently dropping the check.

From webui:

```text
npm run lint
npm test
npm run build
```

At repository root, validate the task context after final artifact/spec updates:

```text
python .trellis/scripts/task.py validate .trellis/tasks/10-01-reverse-redirect-policy
```

Both JSONL files must contain real spec/research rows. The validator permits
zero usable rows, so inspect the reported counts. It does not run acceptance.

## Evidence expectations

| Area | Required evidence |
| --- | --- |
| AC01–AC04 | Migration/restart tests, API omissions/nulls, reset env override, aggregate failures/CAS, captured in-flight mode |
| AC05–AC11 | Table-driven URL/status results, round-trip through V1 parser, browser/WHATWG origin and encoded-dot checks |
| AC12–AC15 | Real client/upstream fixtures for Account/auth, one-hop methods/body, zero B requests, Referer and detail-capture assertions |
| AC16–AC17 | Tracking body close, exact error/log status and attribution, success/failure feedback counts, separate follow-up lifecycle |
| AC18 | Form serialization tests plus manual create/edit/reset and aggregate TLS save/read-back in both locales |
| AC19 | Relevant existing proxy streaming/upgrade/forward/tunnel regression coverage and full test results |

Use synthetic RoundTripper responses for malformed headers that net/http itself
rejects, and real HTTP fixtures for normal client following. For browser-sensitive
URLs, record a browser or Node WHATWG new URL result against the Resin origin;
assert retained V1 prefix and intended upstream target. Go-only parsing is not
evidence for browser normalization. A fragment-only navigation may make no new
HTTP request; assert the resulting client URL without inventing a request count.

## Risk and rollback points

Highest-risk boundaries are aggregate SQL field loss, old-client omission,
generated credential-bearing URLs, browser normalization of prefixes,
ModifyResponse-to-ErrorHandler misclassification, and double health feedback.
Review those before cosmetic UI refinement. The operational rollback is saving
PASS_THROUGH on the affected Platform; it does not require a data rollback.
