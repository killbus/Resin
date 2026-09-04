# Reverse redirect policy — technical design

## Authority and architecture

[prd.md](prd.md) owns requirements R1–R7 and acceptance AC01–AC19. This design
constrains implementation without introducing a redirect session, transport,
or second configuration service. The existing Platform snapshot owns the mode;
the reverse response path consumes it. [implementation-map.md](research/implementation-map.md)
contains source navigation and current pitfalls.

Request flow:

1. Parse the V1 entry and retain its escaped token/identity segments separately
   from the resolved Account. Build the upstream target.
2. Capture Platform/TLS through the existing resolver publication gate; capture
   redirect mode from that same Platform object. Resolve Account/select egress
   using existing rules.
3. Send exactly one request. In REWRITE, remove outbound Referer before header
   byte accounting. Keep existing identity-header stripping.
4. At response arrival, record upstream header bytes and network-success feedback
   exactly once, including responses that redirect policy will reject.
5. For eligible responses under REWRITE, resolve/validate Location with a pure
   helper; produce a safe proxy reference or a typed redirect error.
6. Return an accepted 3xx through the existing streaming path, or write the R6
   local error through an explicit branch. The normal deferred lifecycle finishes
   once. Any later client request starts again at step 1.

## Configuration contract (R1)

Use a small enum in internal/platform, carried by model.Platform, runtime
Platform, codecs, constructors, state CRUD/aggregate SQL, service config and
responses, API inputs, and WebUI models. Store it on the Platform row; it is an
ordinary field, not part of a TLS policy row or new history resource.

Append the next available state migration after 000010_platform_tls_policy
(currently 000011). Backfill/default to PASS_THROUGH independently of environment.
Update every SQL insert/select/scan, including the aggregate configuration
transaction; updating only ordinary CRUD will lose the field on form saves.
Fresh Default creation and service create/reset use the env creation default.
Persisted invalid nonempty values must fail validation rather than silently
enable another mode. Existing in-memory constructor call sites may use an
explicit PASS_THROUGH default; that convenience must not weaken API validation.

Inputs need presence awareness: absent means default on create and preserve on
update; null is invalid. A bare string loses omission and a plain *string
normally conflates null with absence. Reuse an appropriate optional-value decoder
or add one that retains presence and null/type errors. Cover both create handler
decoding and aggregate PlatformConfigurationFields; legacy PATCH already uses a
validated key map and must allow/validate the new key.

For aggregate PUT, merge an omitted redirect field from the current model inside
the existing Platform mutation lock before preparing the candidate. Preserve
existing config_version/ETag checks. Compile/prepare before persistence, commit
the Platform/TLS aggregate transaction, then publish through the shared gate.
Legacy PATCH, reset, and singular TLS mutations must carry/preserve the field
while following their existing aggregate-version rules. An old complete form
payload is explicitly allowed to omit this newly introduced field; other
existing required-field semantics stay intact.

The API layout remains:

- POST/PATCH Platform: reverse_proxy_redirect_policy at the ordinary field level.
- GET/list/reset responses: the same field on PlatformResponse.
- GET/PUT configuration: platform.reverse_proxy_redirect_policy, with existing
  tls_policy and config_version/If-Match behavior.
- System environment view: default_platform_reverse_proxy_redirect_policy.

Do not apply Default's VERIFY-only TLS restriction to redirects. Do not re-resolve
Platform by name in ModifyResponse; the resolver already captures the correct
runtime object for Default fallback and routed/direct execution.

## URL helper and invariants (R2–R4)

Prefer an isolated helper accepting captured mode, upstream base URL, trusted
escaped V1 prefix data, response status, and Location values. It must not receive
the resolved Account or credential headers. It returns unchanged, rewritten, or
a typed failure; it does no I/O and owns no body or health feedback.

Validation and construction order:

1. Apply eligibility before Location parsing, including missing versus present
   empty. Read the full Location value slice; Header.Get hides duplicate fields.
   Do not split commas. Remove only outer HTTP optional whitespace; reject
   remaining raw controls/backslashes and malformed percent escapes in every
   component, including query/fragment.
2. Parse a hierarchical URI reference. Reject non-HTTP(S), userinfo, empty or
   malformed authority, invalid/empty explicit ports, and opaque URLs. Revalidate
   the resolved HTTP(S) URL, including existing host validation. Parser acceptance
   alone does not establish browser-safe authority syntax.
3. Reject percent-encoded dot path segments before resolution can hide them,
   including segments inherited from the upstream base. Resolve normal literal
   dot segments against the upstream base first. Recheck the resolved path.
   Do not reject harmless percent-encoded periods inside a longer segment.
4. Compare scheme/hostname/effective port. Lowercase scheme and hostname; map
   missing http/https ports to 80/443. Validate numeric port range. No DNS lookup,
   CNAME equivalence, trailing-dot stripping, or arbitrary Unicode/IDNA alias
   equivalence. Ambiguous or unsupported host spellings fail closed rather than
   being accepted as equivalent by a different client parser.
5. Assemble a root-relative reference with exactly one leading slash and the
   captured escaped prefix. This avoids dependence on untrusted Forwarded or
   X-Forwarded-Host and works behind a public TLS-terminating proxy without a new
   public-base-URL configuration. The existing V1 root mount remains required.
6. Preserve escaped path data/RawPath and RawQuery/ForceQuery as appropriate,
   append the fragment once, and validate the assembled reference's invariants.
   No path.Join, global PathUnescape, whole-path PathEscape, or cleaning of the
   prefixed result. Encoding component separators is not the same as encoding
   data inside a segment. Host/protocol serialization must round-trip V1.

For authentication enabled, retain the original valid escaped token. Preserve
the original escaped identity segment, including an empty identity, instead of
rebuilding it from resolved Platform/Account. Dot-only segments (literal or
browser-recognized encoded equivalents) that cannot be preserved safely fail
with REDIRECT_LOCATION_INVALID.

For authentication disabled, a safe nonempty placeholder token such as underscore
is permitted, since that segment is ignored by authentication. In particular,
canonicalize an empty or unsafe ignored token to this placeholder instead of
emitting a leading // authority reference. Never replace an authenticated token
or silently change the identity. The output must pass both V1 parsing and
WHATWG URL resolution against the Resin origin; Go url.Parse alone is insufficient
to catch browser dot-segment normalization.

buildReverseTargetURL currently drops an empty query delimiter by reading only
RawQuery. Carry ForceQuery for REWRITE through the request target and Location
helper so a target ending in '?' can be represented and tested. Keep this fix
bounded to REWRITE if changing baseline behavior would violate R2. Fragments
remain client-side; they are not sent upstream. A browser may treat a
fragment-only redirect as same-document navigation without making another HTTP
request; no extra Resin log should be invented for that case.

Same-origin comparison is between upstream URLs, not between generated Resin
paths. Never decide that two different upstreams are equivalent merely because
their proxy URLs share the Resin host.

## Credentials and capture (R4–R5)

The safe identity source is the URL representation provided by the caller.
resolveReverseProxyAccount and AccountMatcher are not prefix constructors.
X-Resin-Account can override the URL Account; header-rule extraction can return
an entire Authorization value. Neither belongs in a generated URL.

Keep outbound application auth/cookies for the original upstream and strip
Referer in REWRITE. On accepted rewrites, replace Referrer-Policy with no-referrer
and Cache-Control with no-store. This limits leakage/caching of newly generated
token-bearing references; it does not promise to remove secrets already present
in all caller URLs, existing logs, or upstream content.

Capture original upstream response headers before modifying Location, including
the no-body branch, or redact the generated field in a copied capture map.
Record upstream header byte accounting before modifications. Do not emit an
unredacted URL in a typed error's Error() method, logger, tracing attribute,
test failure message, or local response. Existing request detail capture and
raw Account logging are not expanded or globally redesigned by this task.

## Local errors without transport misclassification (R6)

Returning an ordinary error from ModifyResponse invokes ReverseProxy.ErrorHandler,
whose current generic branch marks NetOK=false and classifies an upstream error.
Add a dedicated typed redirect result/error branch before that classifier.
It maps only to the two PRD codes and stated attributions. Never classify it as
NodeTransportFailure or reverse_roundtrip failure.

When headers arrive, keep exactly one success feedback and NetOK=true, even if
the content policy rejects them. Apply the local 502 status and proxy code to
the same lifecycle. Do not call RecordFailure for redirect policy errors. Keep
normal transport errors on their existing attribution/health path.

Make body ownership explicit: Go ReverseProxy closes resp.Body when
ModifyResponse returns an error before invoking ErrorHandler. Verify this path
against the required Go version, and test with a tracking body; do not add an
unbounded drain or conflicting close ownership. The error writer must not copy
upstream Location/Set-Cookie and must use a static body and no-store. Preserve
normal streaming counters and the writable 101 body wrapper on unaffected paths.

## UI, rollout, and trade-offs (R7)

Add one enum control to the existing create/detail form model and translations.
Use the same draft, dirty-state calculation, reset initialization, aggregate save,
and read-back as other ordinary fields. Include the field in the system-default
types consumed by creation. No independent redirect modal or save action.

Existing databases remain PASS_THROUGH; an operator opts selected Platforms into
REWRITE. Switching back to PASS_THROUGH through normal saving is the operational
rollback. An in-flight captured REWRITE request can still finish with REWRITE;
later requests use the rollback value. Do not prescribe database downgrade as
the normal rollback. If a down migration is supplied under repository migration
conventions, validate it on a disposable database.

The first release intentionally rejects HTTP-to-HTTPS redirects and other origin
changes in REWRITE. Supporting them would require a separate credential/origin
contract. FOLLOW would additionally require method/body replay, loop/time limits,
and multi-hop logging/health attribution, which are outside this implementation.
