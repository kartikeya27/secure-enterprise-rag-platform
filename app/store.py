"""Postgres access with SQL predicates + Postgres RLS in each scoped transaction."""
from contextlib import contextmanager
from uuid import UUID, uuid4
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from .auth import Principal
from .policy import Resource, can_read
from .embedding import vector_literal


class Store:
    def __init__(self, database_url: str):
        self.pool = ConnectionPool(conninfo=database_url, min_size=1, max_size=8,
                                   open=False, timeout=10, kwargs={'row_factory': dict_row})

    def open(self) -> None:
        self.pool.open(wait=True, timeout=30)

    def close(self) -> None:
        self.pool.close()

    def ping(self) -> None:
        with self.pool.connection() as conn:
            conn.execute('SELECT 1')

    @contextmanager
    def scoped(self, tenant_id: str):
        with self.pool.connection() as conn:
            with conn.transaction():
                # Transaction-local setting. Cannot leak across pooled connections.
                conn.execute("SELECT set_config('app.tenant_id', %s, true)", (tenant_id,))
                yield conn

    @staticmethod
    def audit(conn, principal: Principal, action: str, decision: str,
              reason: str, request_id: str, resource_id: UUID | None = None):
        conn.execute('''INSERT INTO audit_events
                       (tenant_id, actor_id, action, decision, reason, request_id, resource_id)
                       VALUES (%s,%s,%s,%s,%s,%s,%s)''',
                     (principal.tenant_id, principal.subject, action, decision,
                      reason, request_id, resource_id))

    def ingest(self, principal: Principal, source_name: str, text: str, classification: str,
               groups: list[str], sha256: str, flagged: bool,
               embeddings: list[tuple[str, str, list[float]]], request_id: str) -> UUID:
        doc_id = uuid4()
        with self.scoped(principal.tenant_id) as conn:
            conn.execute('''INSERT INTO documents
                (id, tenant_id, source_name, owner_id, classification, classification_rank,
                 allowed_groups, content_sha256, flagged_injection)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)''',
                (doc_id, principal.tenant_id, source_name, principal.subject, classification,
                 {'public': 0, 'internal': 1, 'confidential': 2, 'restricted': 3}[classification],
                 groups, sha256, flagged))
            for ordinal, (chunk, digest, vector) in enumerate(embeddings):
                conn.execute('''INSERT INTO chunks
                     (id, tenant_id, document_id, ordinal, content, content_sha256, embedding)
                     VALUES (%s,%s,%s,%s,%s,%s,%s::vector)''',
                     (uuid4(), principal.tenant_id, doc_id, ordinal, chunk, digest,
                      vector_literal(vector)))
            self.audit(conn, principal, 'ingest', 'allow', 'policy_pass', request_id, doc_id)
        return doc_id

    def search(self, principal: Principal, vector: list[float], limit: int, request_id: str) -> list[dict]:
        literal = vector_literal(vector)
        with self.scoped(principal.tenant_id) as conn:
            # Filter BEFORE vector top-k. A global top-k + post-filter is unsafe and inaccurate.
            rows = conn.execute('''
                SELECT d.id AS document_id, d.tenant_id, d.source_name,
                       d.classification, d.allowed_groups, d.flagged_injection,
                       c.ordinal AS chunk_index, c.content,
                       1 - (c.embedding <=> %s::vector) AS score
                FROM chunks c JOIN documents d ON c.document_id = d.id
                  AND c.tenant_id = d.tenant_id
                WHERE d.tenant_id = %s
                  AND d.classification_rank <= %s
                  AND (cardinality(d.allowed_groups)=0 OR d.allowed_groups && %s::text[])
                ORDER BY c.embedding <=> %s::vector
                LIMIT %s''', (literal, principal.tenant_id, principal.clearance_rank,
                             sorted(principal.groups), literal, limit)).fetchall()
            safe = [row for row in rows if can_read(principal, Resource(
                row['tenant_id'], row['classification'], frozenset(row['allowed_groups'])))]
            self.audit(conn, principal, 'query', 'allow', f'authorized_hits={len(safe)}', request_id)
            return safe

    def metadata(self, principal: Principal, doc_id: UUID, request_id: str) -> dict | None:
        with self.scoped(principal.tenant_id) as conn:
            row = conn.execute('''SELECT id AS document_id, tenant_id, source_name, classification,
                  allowed_groups, content_sha256, flagged_injection
                  FROM documents WHERE id = %s AND tenant_id = %s''',
                  (doc_id, principal.tenant_id)).fetchone()
            authorized = row is not None and can_read(principal, Resource(
                row['tenant_id'], row['classification'], frozenset(row['allowed_groups'])))
            self.audit(conn, principal, 'metadata', 'allow' if authorized else 'deny',
                       'authorized' if authorized else 'not_found_or_not_entitled', request_id, doc_id)
            return row if authorized else None

    def audit_log(self, principal: Principal, limit: int) -> list[dict]:
        with self.scoped(principal.tenant_id) as conn:
            return conn.execute('''SELECT id, actor_id, action, decision, reason,
                         resource_id, request_id, created_at
                         FROM audit_events WHERE tenant_id = %s
                         ORDER BY id DESC LIMIT %s''',
                         (principal.tenant_id, limit)).fetchall()
