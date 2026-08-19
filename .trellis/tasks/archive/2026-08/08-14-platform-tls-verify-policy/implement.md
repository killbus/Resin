# Implementation plan: platform TLS policy correction

## Phase 1 - contract and persistence

- [x] Replace exact-target terminology and contracts in task/spec documents.
- [x] Refactor TLS domain records/snapshots/evaluator to key by platform only.
- [x] Rewrite migration 000010 as one optional active policy per platform plus
      append-only PEM-free history.
- [x] Update repositories for singular get/create/replace/delete, bundle
      reference counts, platform deletion history, and integrity loading.
- [x] Preserve immutable CA registry behavior and mode-specific constraints.

## Phase 2 - service, API, and runtime

- [x] Replace rule collection endpoints with singular platform TLS policy
      GET/PUT/DELETE/history endpoints and version preconditions.
- [x] Reject non-VERIFY mutations for the built-in Default platform.
- [x] Resolve platform policy before direct/routed selection while retaining the
      request target for SNI/audit only.
- [x] Change custom CA profile construction to system roots plus the selected
      bundle; keep VERIFY canonical and BYPASS isolated.
- [x] Preserve generation-linearized publication, idle profile retirement,
      expiry scheduling, request audit, failure attribution, and health feedback.

## Phase 3 - WebUI

- [x] Remove the dedicated TLS tab and exact-target rule editor/list.
- [x] Add platform-wide HTTPS certificate verification controls to the existing
      platform Config tab, with Default read-only and mode-dependent fields.
- [x] Rename and restyle the central CA page using existing resource page,
      table, form, toast, responsive, and translation conventions.
- [x] Remove implementation/audit jargon and add all Chinese/English strings to
      the central translation map.

## Phase 4 - verification

- [x] Focused domain/state/API tests: mode matrix, versions, Default rejection,
      history, bundle references, redaction, migration up/down, restart.
- [x] Focused runtime/TLS tests: multiple targets per platform, direct/routed,
      public + custom roots, SAN/expiry/wrong CA, BYPASS expiry, forward
      isolation, publication and cache retirement.
- [x] Existing failure attribution, request-log, and reverse orchestration tests.
- [x] `go build ./...`
- [x] `go test -count=1 ./internal/... ./cmd/...`
- [x] touched WebUI lint and `npm run build`
- [x] `git diff --check`
- [x] Record repository-wide pre-existing lint/vet findings separately.

Verification completed on 2026-08-19. Focused and full Go tests, Go build,
WebUI production build, touched-file ESLint, and diff checks pass. Repository
baselines remain unchanged: `go vet ./...` reports unreachable code in
`cmd/resin/inbound_demux.go:92`; full WebUI ESLint reports five errors in
untouched `PlatformMonitorPanel.tsx` and `RequestLogsPage.tsx`.

## Delivery

- [x] Restore task status to completed and keep its archive location.
- [x] Create fixup commits for the feature and archive records, autosquash from
      `upstream/master`, and retain the journal without adding a standalone
      feature commit.
- [x] Keep `origin/master` and the fork-only `v1.3.0` tag at the published commit
      until the user explicitly requests publication of the rewritten history.

## Correction round - atomic configuration and UI conformity

- [x] Add aggregate Platform configuration versioning and a GET/PUT
      configuration contract while preserving singular TLS API compatibility.
- [x] Add a coordinator and repository transaction that validate/compile first,
      atomically persist Platform + TLS + history, then publish the matching
      runtime candidates.
- [x] Publish Platform deletion and TLS-policy removal under the same shared
      gate so resolvers cannot observe a still-routable Platform under VERIFY.
- [x] Cover success, stale aggregate/policy versions, missing/in-use CA,
      Default behavior, validation rollback, no partial history, and publication
      ordering with focused Go tests.
- [x] Merge TLS fields into the Platform React Hook Form with one baseline,
      dirty state, BYPASS confirmation, save action, and authoritative reset.
- [x] Rebuild the CA page with the established toolbar/data-card/DataTable/modal
      resource pattern and responsive/icon-action behavior.
- [x] Run focused/full checks and browser screenshots, then restore the task to
      completed and autosquash fixes into the existing feature/archive/journal
      history without creating a standalone feature commit.

## Closure audit correction

- [x] Expose current BYPASS reason only in the aggregate management projection;
      keep a blank per-change reason input and retain request-log/singular/history
      redaction.
- [x] Expose configured/effective TLS modes and explicit expired state, and show
      both when an expired BYPASS is effectively VERIFY.
- [x] Make `重置为默认配置` atomically restore Platform fields and TLS VERIFY,
      including revocation history and joint runtime publication.
- [x] Add PEM-free, certificate-derived CA identity metadata to the resource
      table and Platform selector without adding mutable aliases.
- [x] Record CA `CREATE`/`REUSE`/`DELETE` history with credential context and
  verified certificate-derived metadata, retaining the metadata after deletion
  without persisting or exposing PEM.
- [x] Add a minimal Vitest runner and focused red-to-green behavior tests for
      form governance, expired display, and CA identity; rerun full Go tests,
      WebUI tests/build, focused ESLint, and diff checks.
- [x] Re-run screenshot-based visual checks for the Platform configuration and
      CA resource pages after the closure corrections.
- [x] Reflow BYPASS Reason into one contextual field group: show the current
      reason read-only, progressively disclose a blank per-change reason only
      for enable/extend/permanent mutations, clear withdrawn drafts at the
      payload boundary, and show a concrete TLS change summary before saving.
- [x] Add focused tests for the Reason state matrix, hidden-value omission,
      and concrete save-confirmation summaries.
- [x] Add red-to-green CA governance checks for multi-certificate identity,
      unavailable active bundles, draft-preserving import navigation, and
      auditable CREATE/REUSE/DELETE history.
- [x] Verify CA identity metadata through the real restart boundary: canonical
      PEM remains the active source of truth, Registry reads revalidate and
      rederive metadata, and only deletion-surviving history stores snapshots.
- [x] Add restart and corruption regressions for custom-CA policy compilation,
      deletion-surviving history, missing/damaged active material, and corrupt
      history metadata.
- [x] Recheck custom-CA references transactionally in singular and aggregate
      writes, including a delete/bind race regression with no dangling state.
- [x] Record the actual shared-token or auth-disabled credential class and prove
      unauthorized CA requests cannot mutate state or history.
- [x] Refine the Platform CA UX with three-state availability, TLS-change-only
      gating, always-visible import/refocus refresh, and bounded summaries.

## Create-form closure correction

- [x] Add red tests for create VERIFY/custom-CA/BYPASS payloads and fresh
      expiry defaults, then implement shared TLS payload/validation helpers.
- [x] Make the Reason field state-dependent: first enablement uses one required
      label; existing BYPASS shows current reason; renewal/permanent conversion
      adds a separate blank change reason.
- [x] Reuse the fields-only TLS panel in the Platform create form and preserve
      CA availability gating, BYPASS confirmation, and one-submit semantics.
- [x] Extend `POST /platforms` with an optional TLS policy while preserving the
      legacy flat response and omitted-policy VERIFY behavior.
- [x] Add `CreatePlatformConfiguration` and shared-gate publication so Platform,
      active policy, history, and runtime registration are atomic on create.
- [x] Add failing-to-green state/service/API tests for missing CA, invalid
      policy/version, history rollback, audit context, and publication ordering.
- [x] Close the publication race with a red-to-green regression: the final
      pool write-locked publication rebuild captures nodes that become routable
      while a candidate Platform waits for the shared gate.
- [x] Preserve error-category boundaries with a red-to-green closed-store
      regression: unexpected transaction/store failures are wrapped as
      persistence errors and returned as `INTERNAL`, while domain validation,
      missing-CA, and conflict errors retain their existing mappings.
- [x] Run full Go tests/build, all WebUI tests/build, touched-file lint, and
      `git diff --check`; retain the known unrelated full-lint baseline.
