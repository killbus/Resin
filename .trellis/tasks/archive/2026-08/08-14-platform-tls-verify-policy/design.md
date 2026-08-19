# Design: platform reverse HTTPS TLS verification

## Decision correction

The exact-target rule design is withdrawn. Repository evidence shows platform
is Resin's existing whole-request configuration boundary; exact target scope
entered the design as an unverified assistant recommendation. The implementation
must model one optional TLS policy per custom platform.

## Ownership

- `CABundleRegistry` owns immutable CA import, validation, canonicalization,
  fingerprint deduplication, integrity reads, metadata, history, and
  reference-aware deletion.
- `PlatformTLSPolicy` owns one optional active policy per custom platform,
  versioned replacement/removal, history, runtime snapshots, expiry publication,
  and profile retirement. It references bundles only by immutable ID.
- `ReverseRequestResolver` resolves platform existence and the platform TLS
  policy before direct/routed selection. It retains the actual normalized target
  only for transport/SNI and audit context, not policy matching.
- `OutboundTransportPool` constructs and caches transports from complete
  immutable TLS profiles. Forward uses canonical VERIFY only.
- `FailureAttributor` and `HealthFeedback` retain their existing exclusive
  ownership of request failure attribution and node-health updates.

## Domain model

Absence of an active policy is VERIFY. Persisted policy variants are exhaustive:

```text
TRUST_CUSTOM_CA { policy_id, platform_id, bundle_id, fingerprint, version }
BYPASS          { policy_id, platform_id, reason, expires_at?, version }
```

`DefaultPlatformID` may never have an active policy. Validation exists in the
domain/service boundary and is reinforced by repository/database constraints
where practical.

`ResolvedPolicy` contains configured/effective mode, platform ID, policy ID and
version, optional bundle fingerprint/PEM, reason/expiry for internal evaluation,
expiry marker, and snapshot generation. Target is request context, not the lookup
key.

## Trust composition

- VERIFY leaves `TLSClientConfig == nil` and therefore preserves Go/system
  defaults.
- TRUST_CUSTOM_CA starts from `x509.SystemCertPool()` and appends the selected
  canonical CA bundle. Hostname/SNI and normal certificate validation stay on.
- BYPASS uses an isolated `tls.Config{InsecureSkipVerify: true}` only for reverse
  HTTPS requests using the configured custom platform.
- Profile keys include every effective trust input: mode, platform, policy
  version, and bundle fingerprint as applicable. They do not require target
  because the policy semantics are platform-wide.

## Persistence

Migration `000010_platform_tls_policy` is intentionally rewritten in this
personal project release line. Force-push/rebase is allowed, and compatibility
with already-created pre-rewrite state databases is explicitly out of scope;
an old state database must be rebuilt before running this schema. This is a
release-line prerequisite, not a runtime fallback or silent destructive repair.

```text
ca_bundles
ca_bundle_history
platform_tls_policies       UNIQUE(platform_id)
platform_tls_policy_history no cascade FK to active objects
```

Active policy rows have a restrictive bundle reference and discriminated mode
constraints. CA history records `CREATE`, `REUSE`, and `DELETE` management
events for successful outcomes, preserving request/credential context and
verified certificate-derived metadata (Subject, Issuer, serial, and validity)
without PEM. Rejected input and fingerprint collisions do not create lifecycle
events. Policy history
snapshots platform/policy/version/mode/bundle fingerprint/reason/expiry
metadata but no PEM or token. Platform deletion appends terminal history and
removes the active row in one transaction.

Canonical PEM is the active CA bundle source of truth. `CABundleRegistry`
revalidates it and derives certificate identity metadata on verified reads,
including after restart; `ca_bundles` does not duplicate that derived metadata.
The history table stores a PEM-free metadata snapshot because active PEM may be
deleted while audit evidence must remain readable.

The HTTP boundary records `SHARED_ADMIN_TOKEN` for shared-token authentication
and `AUTH_DISABLED` for an explicitly empty admin token; neither value denotes
a per-user operator. Singular and aggregate custom-CA writes share the same
transactional bundle-reference and fingerprint recheck.

`platforms.config_version` is the aggregate optimistic-concurrency version for
the complete Platform configuration. Platform-only updates, singular TLS
mutations, and the combined configuration command all increment it, so no
mutation path can bypass aggregate conflict detection.

## API

CA endpoints remain resource-oriented:

```text
GET/POST /api/v1/ca-bundles
GET/DELETE /api/v1/ca-bundles/{bundle_id}
GET /api/v1/ca-bundles/{bundle_id}/history
```

Platform policy endpoints become singular:

```text
GET    /api/v1/platforms/{platform_id}/tls-policy
PUT    /api/v1/platforms/{platform_id}/tls-policy
DELETE /api/v1/platforms/{platform_id}/tls-policy
GET    /api/v1/platforms/{platform_id}/tls-policy/history
```

GET returns effective VERIFY with version 0 when no active row exists. PUT uses
`If-None-Match: *` for creation or `If-Match` for replacement. Sending VERIFY
is represented by DELETE in the API client. The handler uses presence-aware
decoding for BYPASS expiry and returns existing project error envelopes.

The Platform configuration UI uses a task-oriented aggregate endpoint:

```text
GET /api/v1/platforms/{platform_id}/configuration
PUT /api/v1/platforms/{platform_id}/configuration
```

GET returns `{ platform, tls_policy, config_version }`. PUT requires the
aggregate version through `If-Match`, accepts complete Platform fields plus the
desired TLS mode and current TLS policy version, and returns the full new
snapshot and ETag. Omitting `tls_policy` preserves it; `VERIFY` removes an
active row. Re-submitting an unchanged TLS state is a no-op and does not require
the redacted BYPASS reason or append history. A real BYPASS enablement,
extension, or conversion to permanent still requires a new reason.

The aggregate management projection is intentionally richer than the
compatibility singular-policy projection: it returns the current BYPASS reason,
configured mode, effective mode, and an expiry marker so the form can show the
state it governs. The reason input remains blank and means “reason for this
change”; it never silently reuses visible text for a renewal. Request audit and
compatibility policy/history responses remain reason-redacted.

`PlatformConfigurationCoordinator` compiles the Platform runtime and asks
`PolicyService` to validate/build the TLS candidate and history event while
holding its mutation lock. `StateRepo.ApplyPlatformConfiguration` then rechecks
aggregate/policy versions and referenced bundle integrity and writes Platform,
TLS active state, and TLS history in one `sql.Tx`. No domain rule is duplicated
in the coordinator or repository.

## Runtime and publication

The immutable snapshot indexes policy by `platform_id`. Resolve performs:

1. normalize HTTPS request target for dialing/audit;
2. resolve the platform, rejecting unknown platforms;
3. resolve the platform policy (Default always VERIFY);
4. compile the immutable TLS profile;
5. choose direct or routed egress;
6. execute, attribute failure, apply eligible health feedback, and emit outcome.

Candidate snapshots/profiles are compiled before commit. After commit, listeners
publish the new generation and retire obsolete cached profiles before exposing
the candidate snapshot. Temporary BYPASS expiry schedules publication at the
boundary and resolves to VERIFY for new requests.

Combined saves use a shared publication gate so request resolution captures a
matching Platform runtime and TLS snapshot generation. Router execution uses
the captured Platform rather than resolving its name a second time. Every
fallible runtime preparation (including routable view/name-conflict checks)
happens before the database commit. Publication then takes the pool write lock,
performs one non-failing final routable-view rebuild, and atomically swaps the
Platform pointer/index; node dirty notifications are blocked during that rebuild
and replayed against the newly registered Platform afterward. This final rebuild
is required because a candidate can wait for the publication gate while node
state changes.

Platform deletion uses the same gate. After the delete/history transaction
commits, one write-locked callback unregisters the runtime Platform and publishes
the snapshot without its TLS policy. A resolver therefore observes either the
complete pre-delete Platform/policy pair or a missing Platform, never a deleted
Platform temporarily routed under VERIFY.

## WebUI

- Remove the dedicated TLS platform tab and exact-target rule editor/list.
- Add an `HTTPS 证书校验` section to the existing platform configuration tab.
  It uses existing form groups, Select/Input/Textarea/Switch/Button components,
  section headings, inline help, toast, and loading/error conventions.
- Default shows `使用系统证书` read-only. A custom platform selects the mode;
  custom CA reveals the CA selector; BYPASS reveals a warning, reason, and
  `到指定时间` / `长期有效` control.
- Keep a central CA resource page, label the navigation/page `CA 证书`, and use
  ordinary resource language. Do not render registry, authorization, CAS,
  immutable payload, normalized target, or JSON-null terminology.
- Derive immutable display metadata (Subject, Issuer, serial, validity) while
  validating canonical PEM. Return that PEM-free metadata from bundle
  list/detail/import responses and use Subject plus fingerprint in selectors;
  do not add mutable aliases or a second naming lifecycle. Multi-certificate
  bundles use a bounded identity summary plus fingerprint; complete verified
  identities remain available in detail/tooltip context. If an
  active bundle is absent from the authoritative list, the selector fails
  closed for a custom-CA mutation rather than rendering a raw UUID. A transient
  list failure does not block an unrelated Platform save whose unchanged TLS
  state is omitted from the aggregate request.
- The Platform detail page owns one composite form baseline, dirty state,
  validation, conflict handling, and save mutation. The TLS subsection is a
  fields-only component. The current BYPASS reason is read-only and appears in
  the same reason field context as the TLS controls. A blank per-change reason
  input is progressively disclosed only when the draft enables BYPASS, extends
  its expiry, or converts it to permanent; it is cleared and omitted from the
  payload when that condition is withdrawn. BYPASS confirmation occurs
  immediately before the one save and summarizes the concrete mode/expiry
  change; cancellation leaves the draft untouched.
- The CA page follows the established resource layout: module header, toolbar
  card, separate data card with shared `DataTable`, and an import modal. Row
  deletion is an icon-only action and remains disabled while referenced. The
  Platform import affordance opens the central CA page in a new tab so the
  current composite form draft remains mounted; the affordance stays visible and
  the selector refetches on window focus so newly imported material appears.
- The existing reset action is a complete Platform-configuration reset. It uses
  the same atomic Platform/TLS persistence and publication boundary as Save
  Config, appends policy revocation history when needed, and returns the legacy
  Platform response shape for compatibility.

## Compatibility and non-goals

Existing reverse requests without a custom-platform policy remain VERIFY.
Forward, CONNECT, SOCKS5, probes, bypass routing, and failure attribution remain
unchanged. No target matcher, global TLS control, Default relaxation, PKI, RBAC,
automatic rotation, or hard active-session revocation is added.

## Verification

Tests cover the discriminated state matrix, singular API/version contracts,
Default rejection, restart/integrity failure, multiple targets under one
platform, direct/routed parity, system-root plus custom-root trust, SAN/expiry/
wrong-CA rejection, BYPASS expiry, publication ordering, forward isolation,
history/redaction, and conservative node-health attribution. Aggregate tests
also cover complete success, Platform/TLS/CA/CAS rollback, no partial history,
authoritative responses, singular-mutation version increments, and absence of
mixed runtime generations.

## Create path closure correction

Creation uses the existing resource route and compatibility response rather
than introducing a second configuration endpoint:

```text
POST /api/v1/platforms
{
  ...legacy platform fields,
  "tls_policy": { ...optional desired policy, "expected_version": 0 }
}
```

The API handler decodes the optional policy with the same presence-aware
expiry/reason conversion used by singular and aggregate policy mutations. It
passes the request's actual shared-token/auth-disabled audit context to the
service. Existing callers that omit `tls_policy` retain the old request and
flat `PlatformResponse` behavior.

`ControlPlaneService.CreatePlatformWithAudit` prepares the runtime Platform,
validates its name/view/registry invariants, and asks `PolicyService` to build
the optional initial policy and history event. `StateRepo.CreatePlatformConfiguration`
then performs one transaction:

```text
prepare Platform + TLS candidate
  -> INSERT Platform(config_version=1)
  -> optional INSERT active policy(version=1)
  -> optional INSERT policy history
  -> commit
```

The repository rechecks the referenced CA and fingerprint inside that
transaction, and requires an absent current policy/expected version zero.
After commit, the prepared Platform and TLS snapshot are published under the
shared publication write gate; publication performs the non-failing final view
rebuild described above before installing the pointer. No fallible registration
step occurs after commit. Thus readers see either a missing Platform or the
complete initial Platform/TLS pair; a failed create cannot leave partial
database, history, or runtime state.

The create WebUI uses `PlatformConfigurationFormValues` and the existing
fields-only `PlatformTLSPolicyPanel` with a synthetic strict baseline. VERIFY
is omitted from the request, while custom CA/BYPASS use version zero. The
panel's reason presentation is a state matrix, not a generic nested heading:
first enablement has one required reason label, current exceptions have a
read-only current reason, and only extension/permanent changes add a blank
per-change reason. A fresh form factory regenerates temporary expiry values.
