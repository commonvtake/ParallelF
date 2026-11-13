#!/bin/sh
# Creates the per-service roles and schemas. Idempotent.
#
# Runs automatically on first start of the postgres container
# (docker-entrypoint-initdb.d) and is reused by CI against a service
# container. Connection settings come from the standard PG* variables.
#
#   pf_core_owner  owns schema "core"; used only to run migrations
#   pf_core        runtime role of pf-core; DML only, granted per table
set -eu

: "${PF_CORE_OWNER_DB_PASSWORD:?must be set}"
: "${PF_CORE_DB_PASSWORD:?must be set}"

psql -v ON_ERROR_STOP=1 \
  --username "${POSTGRES_USER:-postgres}" \
  --dbname "${POSTGRES_DB:-parallelf}" \
  -v owner_pw="$PF_CORE_OWNER_DB_PASSWORD" \
  -v runtime_pw="$PF_CORE_DB_PASSWORD" <<'SQL'
SELECT format('CREATE ROLE pf_core_owner LOGIN PASSWORD %L', :'owner_pw')
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'pf_core_owner') \gexec

SELECT format('CREATE ROLE pf_core LOGIN PASSWORD %L', :'runtime_pw')
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'pf_core') \gexec

-- Nobody creates objects in "public"; every service works in its own schema.
REVOKE CREATE ON SCHEMA public FROM PUBLIC;

CREATE SCHEMA IF NOT EXISTS core AUTHORIZATION pf_core_owner;
GRANT USAGE ON SCHEMA core TO pf_core;

ALTER ROLE pf_core_owner SET search_path = core;
ALTER ROLE pf_core SET search_path = core;
SQL
