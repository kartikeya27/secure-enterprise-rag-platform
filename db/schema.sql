-- Tables are owned by postgres. The API role is NOT an owner and cannot disable RLS.
CREATE TABLE documents (
    id uuid PRIMARY KEY,
    tenant_id text NOT NULL,
    source_name text NOT NULL,
    owner_id text NOT NULL,
    classification text NOT NULL CHECK (classification IN ('public','internal','confidential','restricted')),
    classification_rank smallint NOT NULL CHECK (classification_rank BETWEEN 0 AND 3),
    allowed_groups text[] NOT NULL DEFAULT '{}',
    content_sha256 text NOT NULL,
    flagged_injection boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE chunks (
    id uuid PRIMARY KEY,
    tenant_id text NOT NULL,
    document_id uuid NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    ordinal integer NOT NULL,
    content text NOT NULL,
    content_sha256 text NOT NULL,
    embedding vector(384) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE(document_id, ordinal)
);
CREATE INDEX chunks_embedding_hnsw ON chunks USING hnsw (embedding vector_cosine_ops);
CREATE INDEX docs_tenant_class ON documents(tenant_id, classification_rank);
CREATE INDEX chunks_tenant_document ON chunks(tenant_id, document_id);
CREATE TABLE audit_events (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id text NOT NULL,
    actor_id text NOT NULL,
    action text NOT NULL,
    decision text NOT NULL,
    reason text NOT NULL,
    resource_id uuid,
    request_id text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_tenant_time ON audit_events(tenant_id, created_at DESC);

ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE chunks ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE documents FORCE ROW LEVEL SECURITY;
ALTER TABLE chunks FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_events FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_documents ON documents FOR ALL TO app_api
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_chunks ON chunks FOR ALL TO app_api
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_audit ON audit_events FOR ALL TO app_api
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

GRANT CONNECT ON DATABASE rag_security TO app_api;
GRANT USAGE ON SCHEMA public TO app_api;
GRANT SELECT, INSERT ON documents, chunks TO app_api;
GRANT SELECT, INSERT ON audit_events TO app_api;
GRANT USAGE, SELECT ON SEQUENCE audit_events_id_seq TO app_api;
