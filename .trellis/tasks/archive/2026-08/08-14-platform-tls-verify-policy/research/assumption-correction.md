# Assumption correction: platform scope versus target rules

## Trigger

Post-implementation UI review found that the interface, terminology, and exact
target rule model did not resemble Resin's existing platform configuration.
The user asked for a fact-grounded reassessment rather than a cosmetic rewrite.

## Proven repository facts

- `platform.Platform` and the platform control-plane model contain settings for
  node filters, region filters, lease duration, allocation, reverse-proxy account
  handling, and passive circuit breaking. Each setting applies to the whole
  platform.
- Platform details expose those settings in one `配置` tab. Existing product
  language describes user operations and effects, not storage or concurrency
  mechanisms.
- Reverse request URLs already select a platform and independently carry a
  target. The platform is a routing/configuration scope, not an allowlist of
  targets.
- `Default` is a built-in fallback platform. A relaxed policy on it would be a
  de facto global relaxation.
- `ProxyBypassRules` is a system-level direct/routed dialing choice and remains
  unrelated to TLS verification.

## Proven conversation history

The first-principles statement was "allow per-platform adjustment of reverse
HTTPS trust while preserving strict defaults and isolation." Exact `host:port`
scope appeared later in an assistant recommendation offered while requesting a
real failure sample. The user approved BYPASS, expiry semantics, CA registry
separation, and history lifecycle, but did not independently establish that a
platform policy must be decomposed into target rules.

## Invalid inference

The design treated the safer, narrower assistant proposal as a confirmed product
requirement. Subsequent reviews evaluated internal consistency after accepting
that premise, so they improved implementation boundaries without rechecking the
premise against Resin's domain model. The WebUI then exposed internal terms such
as exact target, immutable bundle, CAS replacement, explicit null, and rule
version, making the mismatch visible.

## Corrected decision

- One optional active TLS policy belongs to each custom platform.
- No row means VERIFY; Default is permanently VERIFY.
- Custom CA augments system roots so a platform remains usable across normal
  public and private HTTPS targets.
- BYPASS is platform-wide and therefore explicitly labeled high risk, with
  reason and expiry controls retained.
- Actual target remains request/audit/SNI context but is removed from policy
  identity and mutation UI.
- CA bundles remain central reusable resources because their material lifecycle
  differs from platform policy lifecycle.

## Prevention

Before converting a safety suggestion into a product scope, record separately:

1. repository/domain facts;
2. explicit user decisions;
3. proposed defaults awaiting confirmation.

Internal consistency review must revisit any proposed default that changes the
product's resource model or information architecture, even if the narrower
choice looks safer in isolation.
