# Implementation map and evidence

Inspected on 2026-10-01 at HEAD
79b8ee97200e703e2a3a8d433589fcf7e5f5000a. This file describes current code;
the task PRD/design define the intended changes. No application implementation
or passing runtime tests are claimed by this research.

## Cross-layer navigation

| Layer | Existing paths | Change/pitfall |
| --- | --- | --- |
| Env/defaults | internal/config/env.go; cmd/resin/main.go:418 | EnvConfig loading/validation; fresh Default creation |
| Stored model | internal/model/models.go:7 | Platform field and row round-trip |
| Runtime model | internal/platform/platform.go:27; internal/platform/model_codec.go:64, :101 | Constructors and BuildFromModel; do not drop the field on load/replacement |
| Persistence | internal/state/repo_state.go; internal/state/repo_platform_configuration.go:77, :173, :248 | Ordinary SQL plus aggregate insert/update/scan; next append-only state migration after 000010 |
| Service | internal/service/control_plane_platform.go:24, :100, :328, :637 | API projection, default config, create/patch/reset and model/runtime conversion |
| Aggregate | internal/service/control_plane_platform_configuration.go:52, :104, :149 | Presence-aware field, merge omission from current model, CAS and shared publication |
| API | internal/api/handler_platform.go; internal/api/handler_platform_configuration.go; internal/api/handler_system.go | Create nesting, configuration decoding, system env projection |
| Reverse entry | internal/proxy/reverse.go:168, :220, :291, :330 | Retain escaped identity; empty query delimiter; captured Platform; single round trip |
| Decision/egress | internal/proxy/reverse_decision.go:54-117; internal/proxy/reverse_egress.go | Preserve snapshot across direct/routed choice; no second Platform lookup |
| Response/lifecycle | internal/proxy/reverse.go:348, :367, :410; internal/proxy/request_lifecycle.go | Generic error trap, capture before rewrite, single completion, NetOK semantics |
| Health/errors | internal/proxy/failure_attribution.go; internal/proxy/errors.go | Typed redirect errors, existing LocalPolicy/TargetService taxonomy |
| UI | webui/src/features/platforms/types.ts; formModel.ts; formModel.test.ts; PlatformPage.tsx; PlatformDetailPage.tsx (same directory) | Draft/default/reset/serialize/read-back and aggregate save |
| System/UI locale | webui/src/features/systemConfig/types.ts; webui/src/i18n/translations.ts | Env default projection and both languages |
| Docs | DESIGN.md; README.md; README.zh-CN.md; doc/integration-prompt.md | Canonical API/env/identity docs and operator examples |

## Default/create/reset behavior

defaultPlatformConfig takes ordinary policy defaults from EnvCfg and is used by
custom Platform creation and reset. ensureDefaultPlatform returns early if the
well-known Default ID exists; it does not overwrite an existing persisted row.
The new redirect field should follow that lifecycle. A database migration has
no operator env intent and must backfill PASS_THROUGH.

envStr uses os.LookupEnv (env.go:319), so explicitly empty can be distinguished
from absent and rejected by validation. Existing unit-test fixtures often build
EnvConfig/Platform literals directly; update those fixtures intentionally.

## Presence and atomicity

PlatformConfigurationFields currently holds ordinary strings, and
platformConfigFromConfigurationFields reconstructs a full config. Adding a
plain string there would lose a saved REWRITE value on old-client omission.
Merge this new omitted field from current under platformMu. optionalString in
internal/api/handler_tls_policy.go:20 demonstrates Present/Null/Value decoding,
but the new service/API boundary must retain the same information; do not add a
service import of the API package.

Aggregate writes prepare a runtime Platform, invoke the TLS configuration
transaction, then publish the prepared Platform and TLS snapshot under one
PublicationGate. The reverse resolver holds its read side while capturing both.
The established contract is .trellis/spec/backend/tls-policy.md, section
"Scenario: Atomic Platform Configuration". Only reuse the aggregate/snapshot
rules; VERIFY-only Default and TLS reason/expiry rules remain TLS-specific.

## Reverse response traps

- Header.Get hides extra Location values; examine the full field slice.
- parsePathV1 expects EscapedPath, decodes segments separately, and accepts an
  ignored empty token when auth is disabled. Naively rebuilding that prefix
  yields //identity/... and changes the browser authority.
- buildReverseTargetURL accepts RawQuery only and loses ForceQuery for an empty
  '?' delimiter; REWRITE must carry this semantic explicitly.
- stripForwardingIdentityHeaders strips X-Resin-Account, not Authorization,
  Cookie, or Referer (reverse.go:116). AccountMatcher returns raw header values
  (account_matcher.go:170). Never use resolved Account as a redirect URL field.
- Generic ErrorHandler assesses and classifies an error, records failure, and
  sets NetOK=false. A ModifyResponse rejection must be identified before that
  branch or the redirect error will appear as a network error.
- ModifyResponse currently marks success at headers, captures response headers
  in body/no-body/101 paths, and preserves io.ReadWriteCloser for upgrades.
  Capture original Location before transformation and retain single success
  feedback even if redirect validation rejects the response.
- request_lifecycle.go already owns one deferred finish and existing error,
  attribution, status, and NetOK fields. No new chain/log schema is needed.

## Existing verification starting points

- Config/defaults: internal/config/env_test.go; cmd/resin/main_test.go.
- Persistence: internal/state/repo_state_test.go;
  internal/state/platform_configuration_test.go; internal/state/engine_test.go.
- Aggregate service/API: internal/service/control_plane_platform_configuration_test.go;
  internal/api/platform_configuration_contract_test.go.
- Proxy: internal/proxy/proxy_test.go and adjacent reverse/identity tests; add
  URL policy tables and local upstream fixtures. Existing
  TestReverseProxy_ParseError_EmitsNoEvents (proxy_test.go:1272) is outside the
  post-upstream-response lifecycle contract and should remain unchanged.
- UI: webui/src/features/platforms/formModel.test.ts; webui/package.json provides
  lint, test (vitest run), and build (tsc -b then vite build).

The earlier audit could not execute Go tests/vet: local Go 1.25.1 is below
go.mod:3's Go 1.25.5 requirement, and auto-selection encountered a cache-lock
access denial. These are environment limitations, not observed test failures.
TEAM B must run the checks in implement.md in a compatible environment and
record actual outcomes; historical TLS-task lint notes are not current results.
