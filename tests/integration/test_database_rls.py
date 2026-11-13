"""Run only against docker-compose PostgreSQL; exercises actual database RLS."""
import os
from uuid import uuid4
import pytest

pytestmark = pytest.mark.skipif(os.getenv('RUN_INTEGRATION') != '1', reason='RUN_INTEGRATION=1 requires Docker PostgreSQL')


def test_postgres_rls_denies_cross_tenant_reads_and_writes():
    from app.store import Store
    import psycopg
    repo = Store(os.environ['DATABASE_URL'])
    repo.open()
    tenant_a, tenant_b = 'rls-a-' + uuid4().hex[:9], 'rls-b-' + uuid4().hex[:9]
    doc_id = uuid4()
    try:
        with repo.scoped(tenant_a) as conn:
            conn.execute('''INSERT INTO documents
                (id,tenant_id,source_name,owner_id,classification,classification_rank,content_sha256)
                VALUES (%s,%s,'test','tester','public',0,'fixture')''',(doc_id,tenant_a))
        with repo.scoped(tenant_b) as conn:
            assert conn.execute('SELECT id FROM documents WHERE id=%s',(doc_id,)).fetchone() is None
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                # The API role cannot create a row in a different tenant despite explicit SQL.
                conn.execute('''INSERT INTO documents
                  (id,tenant_id,source_name,owner_id,classification,classification_rank,content_sha256)
                  VALUES (%s,%s,'attack','tester','public',0,'fixture')''',(uuid4(),tenant_a))
    finally:
        repo.close()
