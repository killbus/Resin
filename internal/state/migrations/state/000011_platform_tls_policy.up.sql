ALTER TABLE platforms
ADD COLUMN config_version INTEGER NOT NULL DEFAULT 1 CHECK (config_version > 0);

CREATE TABLE IF NOT EXISTS ca_bundles (
    id                          TEXT PRIMARY KEY,
    fingerprint_algorithm       TEXT NOT NULL CHECK (fingerprint_algorithm = 'SHA256'),
    canonicalization_version    INTEGER NOT NULL CHECK (canonicalization_version > 0),
    fingerprint                 TEXT NOT NULL UNIQUE,
    canonical_pem               BLOB NOT NULL,
    certificate_count           INTEGER NOT NULL CHECK (certificate_count > 0),
    created_at_ns               INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS ca_bundle_history (
    id                          TEXT PRIMARY KEY,
    bundle_id                   TEXT NOT NULL,
    event_kind                  TEXT NOT NULL CHECK (event_kind IN ('CREATE', 'REUSE', 'DELETE')),
    fingerprint_algorithm       TEXT NOT NULL,
    fingerprint                 TEXT NOT NULL,
    canonicalization_version    INTEGER NOT NULL,
    certificate_count           INTEGER NOT NULL,
    certificates_json           TEXT NOT NULL DEFAULT '[]',
    occurred_at_ns              INTEGER NOT NULL,
    request_id                  TEXT NOT NULL DEFAULT '',
    remote_address              TEXT NOT NULL DEFAULT '',
    credential_class            TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS platform_tls_policies (
    id                   TEXT PRIMARY KEY,
    platform_id          TEXT NOT NULL REFERENCES platforms(id) ON DELETE RESTRICT,
    platform_name        TEXT NOT NULL,
    mode                 TEXT NOT NULL,
    bundle_id            TEXT REFERENCES ca_bundles(id) ON DELETE RESTRICT,
    bundle_fingerprint   TEXT NOT NULL DEFAULT '',
    bypass_reason        TEXT NOT NULL DEFAULT '',
    expires_at_ns        INTEGER,
    version              INTEGER NOT NULL CHECK (version > 0),
    created_at_ns        INTEGER NOT NULL,
    updated_at_ns        INTEGER NOT NULL,
    UNIQUE(platform_id),
    CHECK (platform_id <> '00000000-0000-0000-0000-000000000000'),
    CHECK (
        (mode = 'TRUST_CUSTOM_CA' AND bundle_id IS NOT NULL AND bundle_fingerprint <> '' AND bypass_reason = '' AND expires_at_ns IS NULL)
        OR
        (mode = 'BYPASS' AND bundle_id IS NULL AND bundle_fingerprint = '' AND length(trim(bypass_reason)) > 0)
    )
);

CREATE TABLE IF NOT EXISTS platform_tls_policy_history (
    id                         TEXT PRIMARY KEY,
    event_kind                 TEXT NOT NULL,
    policy_id                  TEXT NOT NULL DEFAULT '',
    platform_id                TEXT NOT NULL,
    platform_name              TEXT NOT NULL,
    old_version                INTEGER,
    new_version                INTEGER,
    old_mode                   TEXT NOT NULL DEFAULT '',
    new_mode                   TEXT NOT NULL DEFAULT '',
    old_bundle_id              TEXT NOT NULL DEFAULT '',
    new_bundle_id              TEXT NOT NULL DEFAULT '',
    old_bundle_fingerprint     TEXT NOT NULL DEFAULT '',
    new_bundle_fingerprint     TEXT NOT NULL DEFAULT '',
    old_bypass_reason          TEXT NOT NULL DEFAULT '',
    new_bypass_reason          TEXT NOT NULL DEFAULT '',
    old_expires_at_ns          INTEGER,
    new_expires_at_ns          INTEGER,
    occurred_at_ns             INTEGER NOT NULL,
    request_id                 TEXT NOT NULL DEFAULT '',
    remote_address             TEXT NOT NULL DEFAULT '',
    credential_class           TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_platform_tls_policies_platform ON platform_tls_policies(platform_id);
CREATE INDEX IF NOT EXISTS idx_platform_tls_history_platform ON platform_tls_policy_history(platform_id, occurred_at_ns);
CREATE INDEX IF NOT EXISTS idx_platform_tls_history_policy ON platform_tls_policy_history(policy_id, occurred_at_ns);
CREATE INDEX IF NOT EXISTS idx_ca_bundle_history_bundle ON ca_bundle_history(bundle_id, occurred_at_ns);
