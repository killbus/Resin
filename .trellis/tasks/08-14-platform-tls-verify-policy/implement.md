# Implementation plan - reverse HTTPS exact-target TLS verification policy

Status: **implementation complete; task-scoped build, full internal/cmd tests,
and WebUI build pass. Repository-wide lint/vet retain untouched baseline
findings recorded below**.

The previous migration/service/proxy/WebUI checklist assumed a per-platform
three-state model that was replaced. The implemented target is an exact
`host:port` rule with strict VERIFY as the absence/default behavior and explicit
TRUST_CUSTOM_CA or BYPASS modes. The phases below record the completed
implementation and its validation contract.

## Phase 0 - evidence and decisions (completed)

### 0.1 Define representative TLS behavior

Record fixtures and expected outcomes for:

- system-trusted certificate under VERIFY;
- private CA under TRUST_CUSTOM_CA;
- wrong CA, wrong SAN, expiry, and incomplete chain under VERIFY/custom CA;
- otherwise-invalid certificates under an exact-target BYPASS rule;
- unmatched host/port and malformed/missing policies.

The same matrix applies to direct and routed requests. Production samples may
improve coverage but do not define the product scope.

### 0.2 Preserve the resolved authorization boundary

The product contract is fixed:

- only requests authorized by the shared admin token configure rules; there is
  no distinct administrator identity;
- one rule matches one exact normalized HTTPS `host:port` within a platform;
- requests presenting the current shared proxy token observe the same configured
  rules;
- direct and routed paths consume the same decision;
- no matching rule means VERIFY; explicit rules select TRUST_CUSTOM_CA or
  BYPASS.

Persistence ownership is fixed: active exact-target rules are independently
versioned platform child rows; immutable CA bundles are central material objects,
and PEM-free history outlives active/platform rows.

### 0.3 Finalize mode semantics

The capability boundary is decided: Resin validates, normalizes, and persists
administrator-provided public CA trust anchors in an immutable content-addressed
bundle registry. Platform policy binds only by bundle ID. It does not manage CA
private keys, certificate
issuance/renewal/distribution, or general PKI lifecycle, and the first version
does not support external secret references.

The implementation records:

- handshake-scoped revocation and correlated audit fields. BYPASS reason
  requirements are fixed:
  create/mode-switch requires a trimmed non-empty value, and extending a
  temporary exception or making it permanent requires a new reason. The expiry
  representation is fixed: create requires explicit null
  (permanent) or a future RFC3339 value (temporary); replacement omission is
  unchanged and explicit null is permanent. No actor identity is available under the
  shared admin token. BYPASS cannot be selected through fallback or a broader
  matcher.

The migration and API contract follow these decisions.

### 0.4 Update/revocation semantics (completed)

Snapshot publication changes new requests; idle obsolete profiles close, while
in-flight requests/upgrades drain under their captured policy.

### 0.5 Failure-attribution contract (completed)

The attribution categories are implemented behind a dedicated boundary. Only
explicit `NodeTransportFailure` proof permits negative node health; target
identity, target service, local policy, client, unknown, and direct failures do
not. Standard sing-box routed `DialContext` errors are composite and supply no
such proof: Resin marks them `OpaqueRoutedDialFailure`, attributes them Unknown,
and deliberately accepts passive-health false negatives. A future lower-layer
producer may opt in with explicit node evidence. Routed success retains the
existing positive/reset behavior.

### Phase 0 exit gate

- [x] Representative VERIFY/custom-CA/BYPASS behavior matrix defined.
- [x] Shared-admin-token configuration boundary and exact `host:port` target
      scope decided; no user/RBAC identity is introduced.
- [x] Direct/routed applicability decided.
- [x] CA responsibility limited to administrator-provided public trust anchors; no CA
      private keys, certificate issuance, or general PKI lifecycle.
- [x] Trust-material source decided: persist validated normalized CA PEM,
      fingerprint, and canonicalization version in Resin's central immutable
      bundle registry; no external secret reference.
- [x] Module/persistence ownership decided: `CABundleRegistry` owns immutable
      material import/dedup/delete; `PlatformTLSPolicy` owns platform exact-target
      bind/rebind/version/history/runtime publication.
- [x] Custom-root semantics decided: target-exclusive bundle only, with no
      system-root augmentation or fallback.
- [x] BYPASS included as an explicit exact-target mode with no automatic
      downgrade.
- [x] BYPASS expiry representation decided: explicit null is permanent, future
      RFC3339 is temporary, and PATCH omission preserves the value.
- [x] Expired temporary BYPASS resolves to strict VERIFY for new requests.
- [x] BYPASS reason requirement decided: trimmed non-empty on create/mode
      switch, with a new reason on extension or change to permanent.
- [x] Update/revocation semantics decided: snapshot publication switches new
      requests, old idle connections close, and pre-existing in-flight/upgrade
      sessions naturally drain; hard active-session termination is out of scope.
- [x] Node-health attribution is conservative: only explicit
      `NodeTransportFailure` proof permits negative node health; opaque standard
      sing-box dial/target-negotiation failures remain Unknown.
- [x] `prd.md` has no blocking product questions.
- [x] `design.md` contains the final persistence/API/runtime design.
- [x] History retention is indefinite, with no purge or archival path.

## Phase A - persistence and domain model (completed)

Added separate tables/repositories for immutable
CA bundles, platform-owned active rules, and append-only rule history. Bundle
storage includes canonical PEM, fingerprint algorithm/canonicalization version,
fingerprint, certificate count, and timestamps with unique fingerprint plus
canonical-byte collision confirmation. Active rules use
`UNIQUE(platform_id, normalized_target)`, restrictive platform/bundle references,
positive versions, and the discriminated state constraints. History has no
cascade FK to bundle/rule/platform. Cover bounded canonicalization, strict
defaults, fail-closed integrity loading, atomic CAS updates, restart/rollback,
and delete-if-unused. Lists/logs/audit bodies must not expose PEM.

Use a discriminated domain policy with exactly two persisted variants; absence
means VERIFY. TRUST_CUSTOM_CA contains only immutable `bundle_id`; BYPASS contains
only reason/expiry. If one table stores nullable variant columns, add SQL `CHECK`
constraints for mode, positive version, and all required/prohibited field
combinations. Mode-switch writes replace the complete variant and clear fields
from the previous mode atomically. Repository loads must pass through the shared
domain compiler and fail startup/snapshot publication on corrupt rows.

Persist executable rules separately from append-only configuration history.
History snapshots event/rule/platform/target/version/mode/bundle/fingerprint/reason/
expiry metadata but never PEM or tokens, and has no cascade-delete foreign key
to platform or active-rule rows. Platform/rule delete transactions append
terminal events before removing active rows. Startup reads active rules only;
history is queryable evidence, not a replay source for current policy.

Add a separate PEM-free append-only bundle lifecycle stream owned by the
Registry. First creation and delete-if-unused/GC append events; idempotent dedup
hits do not create state-transition versions. Neither bundle nor rule history
has cascade FKs to mutable/active rows.

## Phase B - service, API, and WebUI (completed)

Implemented `CABundleRegistry` and `PlatformTLSPolicy` as separate services. The
registry exposes idempotent import/create-or-return-existing, metadata list/detail,
integrity read, reference count, and delete-if-unused; it cannot mutate policy.
The policy service exposes platform exact-target create/full-variant replacement,
bundle bind/rebind under expected-version CAS, delete/revoke, and history; it
never accepts PEM. Use separate API resources and WebUI catalog/rule surfaces.
Unused imported bundles are legal staged state and do not authorize requests.
Apply one CAS contract to every active-rule mutation: expected absence on create,
current positive version on replace/rebind/revoke/delete, with CAS, history, and
active mutation in one transaction.
Include presence-aware BYPASS null decoding, public API contract tests, Default
behavior, and compatibility messaging.

## Phase C - request policy and data plane (completed)

The implementation follows this structure:

### C1 - establish safety boundaries before handler integration

1. Introduce `CABundleRegistry` canonicalization/integrity and a separate TLS
   policy compiler. Registry validation completely consumes bounded PEM input,
   accepts only CA-capable `CERTIFICATE` blocks, canonicalizes unique full DER
   as a sorted set, and computes a domain-separated/versioned/length-framed
   digest. The policy compiler validates mode, target, bundle ID, reason, expiry,
   and version on writes/startup and resolves bundles only after exact-rule
   authorization. Use presence-aware request types so reason omission/blank content and
   expiry omission/explicit null/timestamp remain distinct. Enforce a new
   trimmed non-empty reason when creating/switching to BYPASS, extending a
   temporary BYPASS, or making it permanent; invalid combinations never enter
   the runtime snapshot. Represent compiled policies as exhaustive custom-CA or
   BYPASS variants; VERIFY is absence. Reject cross-mode fields, and treat mode
   changes as full-variant replacement rather than merge.
2. Add an independently testable runtime policy evaluator using an injectable
   clock. It consumes an immutable snapshot and normalized target, evaluates
   exact matching/expiry, returns strict VERIFY at `now >= expires_at`, and
   otherwise returns `ResolvedTLSPolicy` or a typed fail-closed result.
3. Introduce the immutable `ReverseRequestDecision` contract and a shared
   resolver that consumes only `ResolvedTLSPolicy` before direct/routed
   selection. Keep `ProxyBypassRules` as transport selection only.
4. Add a dedicated failure-attribution module that returns symptom detail,
   causal attribution, and explicit negative-node-health eligibility.
5. Add a health-feedback collaborator that accepts the assessment and optional
   route, refuses ineligible negative updates, produces no feedback for direct
   attempts, preserves approved routed-success behavior, and exclusively owns
   request-outcome calls to the existing `HealthRecorder`.
6. Unit-test write/load validation, evaluator clock/expiry boundaries, resolver,
   attributor, and health gate independently. Do not change
   `ReverseProxy.ServeHTTP` until these contracts and tests pass review.

### C2 - make transports consume the decision

7. Introduce immutable `tlsProfile` carrying key, mode, root-composition
   semantics, bundle fingerprint, and resolved CA material. The key includes all
   effective semantics; BYPASS additionally binds platform + exact target.
   TRUST_CUSTOM_CA constructs roots from the verified bundle only and retains
   hostname/SNI, validity, and chain verification without system-root fallback.
8. Make routed transport caching profile-aware, with forward fixed to VERIFY.
9. Make direct transport consume the same effective TLS profile when selected
   by the final PRD.
10. Define stale-profile retirement, node eviction, and connection closing.
    Rebind preconstructs the candidate snapshot/profile, commits rule CAS,
    history, and bundle FK in one transaction, then atomically publishes before
    API success and retires/closes the old idle profile. Existing in-flight,
    streaming, and upgraded sessions retain their captured profile and drain.
    Resolved profiles carry their snapshot generation. Publication and cache
    acquisition share one linearization lock, so pre-publication captures may
    drain through non-cached transports but obsolete profiles cannot re-enter
    direct or routed indexes. A scheduled expiry publication retires temporary
    BYPASS profiles at the exact deadline without waiting for another request.

### C3 - integrate through orchestration only

11. Reduce the reverse handler to orchestration: resolve decision, select egress,
   execute transport, delegate assessment/health, and emit the correlated
   outcome. It must not parse CA material, inspect `reason`/`expires_at`, evaluate
   policy time, infer health causality inline, or call `HealthRecorder` directly
   for request outcomes.
12. Emit safely encoded, correlated policy/result audit evidence through a
    dedicated outcome/audit boundary rather than ad hoc `log.Printf` branches.
13. Add an integration gate proving every direct/routed failure reaches the same
    assessment boundary exactly once and that no handler branch can bypass the
    health-feedback collaborator.

Required data-plane tests will include paired direct/routed outcomes, wrong CA,
wrong SAN, expiry, unauthorized target, strict forward isolation, same-node
cross-platform interleaving, policy rotation/revocation, profile cleanup, and
node-health non-regression. Focused tests must prove non-node failures cannot
increment node failures, direct attempts emit no node feedback, and routed
success retains the approved positive/reset semantics. Expiry tests use a fake
clock and cover the exact boundary without sleeps. API/domain tests cover create
omission rejection, explicit-null permanence, future timestamps, past/invalid
timestamps, PATCH omission, permanent-to-temporary and temporary-to-permanent
changes, UTC normalization, persistence, restart restoration, missing/blank
reason rejection, reason retention without extension, and mandatory replacement
on extension or permanent conversion. Runtime tests cover before/equal/after
expiry, concurrent requests, configured-versus-effective audit fields,
versioned reason snapshots, VERIFY profile selection, and zero reuse of idle
BYPASS connections after expiry.

Registry/API tests cover complete input consumption, rejected private-key/
unknown/header/trailing/empty input, CA constraints, byte/count/certificate-size
bounds, formatting/order/duplicate-insensitive canonicalization, digest-version
persistence, canonical-byte comparison on uniqueness conflict, concurrent
idempotent import, unused staged bundles, reference-restricted delete, no content
PATCH/latest/automatic rebind, and absence of authorization changes on import.
Policy API tests prove TRUST_CUSTOM_CA accepts only bundle ID, BYPASS prohibits
it, resolver authorizes exact rule before bundle resolution, missing/damaged
references fail closed, and concurrent create/replace/rebind/revoke/delete obey
expected-absence/current-version CAS without ambiguous history.

Revocation tests use a publication barrier to prove requests before/after the
linearization point select old/new policy respectively, idle old connections are
closed, and pre-existing in-flight/stream/upgrade sessions can drain without a
false hard-revocation success claim.

TLS behavior tests prove system-root VERIFY remains unchanged without a rule;
matched custom trust accepts only chains terminating at its bound bundle; public
roots are not implicitly accepted; wrong SAN, incomplete chain, wrong bundle, and
custom verification failure do not fall back; transitional old/new-anchor bundles
work only after explicit rebind.

Persistence/domain tests exhaust the state matrix: no persisted VERIFY row;
required custom-CA bundle ID with prohibited BYPASS fields; required BYPASS fields
with prohibited CA fields; SQL constraint violations; stale-field clearing on
both mode-switch directions; fingerprint recomputation; positive versions; and
corrupt-row startup/snapshot-publication failure without fallback to VERIFY.
History tests prove each configuration transition appends one immutable version
event, rollback leaves neither partial history nor partial active state, platform
deletion preserves PEM-free terminal history, startup never replays history as
active policy, and runtime publication/idle-profile retirement follows commit.
Bundle-history tests prove first create and deletion append PEM-free events,
dedup hits do not invent versions, and retention never cascades through active
bundle/rule/platform relationships.

### C3 implementation review gate

The gate is satisfied: `internal/proxy/reverse.go` coordinates the resolved
decision, egress execution, delegated attribution/health feedback, and lifecycle
outcome without owning TLS policy semantics or failure causality.

- **Decision ordering:** focused resolver/handler tests and the orchestration
  structure verify policy resolution before bypass evaluation, route/lease
  selection, or transport use. Missing platform and evaluator rejection produce
  no egress selection or health feedback; missing policy wiring also fails
  closed for HTTPS instead of silently using VERIFY.
- **Handler purity:** static search plus code review confirms `ServeHTTP` does not
  parse CA material, inspect `reason`/`expires_at`, call `time.Now` for policy
  evaluation, match target authorization, branch on TLS mode or X.509 causality,
  or call `RecordResult`/`RecordPassiveResult` for request outcomes.
- **Single feedback path:** direct and routed failures reach the attributor and
  health gate exactly once. Negative health recording is reachable only through
  the health-feedback collaborator; target identity, target service, local
  policy, client, and unknown failures record zero negative node updates.
  Protocol-level SOCKS5 target-refusal and HTTP CONNECT 502 regressions prove
  standard sing-box adapter errors remain opaque/Unknown with no negative
  feedback, while explicit lower-layer proof remains eligible and routed
  success retains positive/reset feedback.

Adding interfaces without removing the corresponding branches from
`ServeHTTP` fails this gate.

## Phase D - docs and rollout follow-ups

The task PRD/design/implementation records now reflect the implemented model.
Product README/API/release-note publication remains a release-management
follow-up. That publication must call out that a bypass-matched request with an
invalid platform is rejected before egress.

## Final validation commands

```bash
go build ./...
go vet ./...
go test ./internal/... ./cmd/...
cd webui && npm run lint && npm run build
```

The final check covers the full diff against the approved PRD/design. The
project-level spec files remain placeholders, so the executable attribution
contract is recorded here and in focused tests.

Validation on 2026-08-18:

- `npm run build`: pass (after generating the embedded WebUI assets).
- `mise x go@1.25.5 -- go build ./...`: pass.
- `mise x go@1.25.5 -- go test -count=1 ./internal/... ./cmd/...`: pass.
- `git diff --check`: pass.
- `npm run lint`: retains five errors in untouched files
  `PlatformMonitorPanel.tsx` and `RequestLogsPage.tsx`, plus existing warnings.
- `mise x go@1.25.5 -- go vet ./...`: retains the untouched
  `cmd/resin/inbound_demux.go:92:2: unreachable code` finding.

Follow-up conservative attribution correction on 2026-08-18:

- focused proxy tests covering opaque generic/X.509 failures, explicit nested
  node proof, pinned sing-box SOCKS5 reply code 5, HTTP CONNECT 502, reverse
  audit attribution, and positive routed feedback: pass;
- focused generation/publication, BYPASS expiry, TLS API reason-redaction,
  persistence/history, request-log audit, and policy-governance tests: pass;
- `GOTMPDIR=$PWD/.tmp/go-build mise x go@1.25.5 -- go build ./...`: pass;
- `GOTMPDIR=$PWD/.tmp/go-build mise x go@1.25.5 -- go test -count=1 ./internal/... ./cmd/...`:
  pass;
- `git diff --check`: pass;
- `GOTMPDIR=$PWD/.tmp/go-build mise x go@1.25.5 -- go vet ./...`: retains only
  the same untouched `cmd/resin/inbound_demux.go:92:2: unreachable code`
  finding.

## Rollback points

- The down migration removes the new executable TLS policy and history tables;
  operators must back up retained audit history before an intentional rollback.
- Removing an active rule restores strict VERIFY for subsequent requests.
- Reverting runtime publication closes obsolete idle profiles; already-started
  requests retain their captured handshake-scoped policy until completion.
