#!/bin/sh
# Creates the per-service roles and schemas. Idempotent: safe to run on
# every start, so services added later get their roles in an existing
# database too.
#
# Run by the Compose "db-init" service and by CI against a service
# container. Connection settings come from the standard PG* variables.
#
# For every service <svc> (core, cloud):
#   pf_<svc>_owner  owns schema "<svc>"; used only to run migrations
#   pf_<svc>        runtime role; DML only, granted per table by migrations
set -eu

: "${PF_CORE_OWNER_DB_PASSWORD:?must be set}"
: "${PF_CORE_DB_PASSWORD:?must be set}"
: "${PF_CLOUD_OWNER_DB_PASSWORD:?must be set}"
: "${PF_CLOUD_DB_PASSWORD:?must be set}"

psql -v ON_ERROR_STOP=1 \
  --username "${POSTGRES_USER:-postgres}" \
  --dbname "${POSTGRES_DB:-parallelf}" \
  -v core_owner_pw="$PF_CORE_OWNER_DB_PASSWORD" \
  -v core_runtime_pw="$PF_CORE_DB_PASSWORD" \
  -v cloud_owner_pw="$PF_CLOUD_OWNER_DB_PASSWORD" \
  -v cloud_runtime_pw="$PF_CLOUD_DB_PASSWORD" <<'SQL'
-- Nobody creates objects in "public"; every service works in its own schema.
REVOKE CREATE ON SCHEMA public FROM PUBLIC;

-- core -----------------------------------------------------------------------
SELECT format('CREATE ROLE pf_core_owner LOGIN PASSWORD %L', :'core_owner_pw')
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'pf_core_owner') \gexec
SELECT format('CREATE ROLE pf_core LOGIN PASSWORD %L', :'core_runtime_pw')
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'pf_core') \gexec

CREATE SCHEMA IF NOT EXISTS core AUTHORIZATION pf_core_owner;
GRANT USAGE ON SCHEMA core TO pf_core;
ALTER ROLE pf_core_owner SET search_path = core;
ALTER ROLE pf_core SET search_path = core;

-- cloud ----------------------------------------------------------------------
SELECT format('CREATE ROLE pf_cloud_owner LOGIN PASSWORD %L', :'cloud_owner_pw')
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'pf_cloud_owner') \gexec
SELECT format('CREATE ROLE pf_cloud LOGIN PASSWORD %L', :'cloud_runtime_pw')
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'pf_cloud') \gexec

CREATE SCHEMA IF NOT EXISTS cloud AUTHORIZATION pf_cloud_owner;
GRANT USAGE ON SCHEMA cloud TO pf_cloud;
ALTER ROLE pf_cloud_owner SET search_path = cloud;
ALTER ROLE pf_cloud SET search_path = cloud;
SQL
