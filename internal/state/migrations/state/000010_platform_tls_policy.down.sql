DROP TABLE IF EXISTS platform_tls_policy_history;
DROP TABLE IF EXISTS platform_tls_policies;
DROP TABLE IF EXISTS ca_bundle_history;
DROP TABLE IF EXISTS ca_bundles;
ALTER TABLE platforms DROP COLUMN config_version;
