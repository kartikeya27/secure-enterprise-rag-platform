#!/bin/sh
set -eu
# Run by postgres official entrypoint, during first DB initialization only.
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" -v app_password="$APP_DB_PASSWORD" <<'SQL'
CREATE EXTENSION IF NOT EXISTS vector;
CREATE ROLE app_api LOGIN PASSWORD :'app_password';
\i /opt/rag/schema.sql
SQL
