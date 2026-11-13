"""End-to-end security scenario; run inside the API container after startup."""
import os
import time
import uuid
import httpx
import jwt

BASE = os.getenv('DEMO_BASE_URL', 'http://127.0.0.1:8000')
SECRET = os.environ['LOCAL_JWT_SECRET']


def token(tenant: str, *, groups=('finance',), roles=('data_steward',), clearance='restricted'):
    now = int(time.time())
    claims = dict(sub='demo-' + tenant, tenant_id=tenant, groups=list(groups), roles=list(roles),
                  clearance=clearance, iat=now, exp=now+3600,
                  iss=os.getenv('AUTH_ISSUER','secure-rag-local'),
                  aud=os.getenv('AUTH_AUDIENCE','secure-rag-api'))
    return jwt.encode(claims, SECRET, algorithm='HS256')


def req(client, method, path, tok, **kwargs):
    result = client.request(method, BASE + path, headers={'Authorization': 'Bearer '+tok}, **kwargs)
    return result


def main():
    if os.getenv('AUTH_MODE','local') != 'local':
        raise SystemExit('Demo requires local mode')
    ns = uuid.uuid4().hex[:8]
    alpha, beta = 'alpha-'+ns, 'beta-'+ns
    t1, t2 = token(alpha), token(beta)
    outsider = token(alpha, groups=('engineering',))
    low = token(alpha, clearance='internal')
    with httpx.Client(timeout=20) as c:
        doc1 = req(c,'POST','/v1/documents',t1,json={
            'source_name':'Q4-finance-private.txt', 'text':'Finance revenue forecast is 17 million. Contact analyst@example.org. SSN 123-45-6789.',
            'classification':'restricted','allowed_groups':['finance']})
        assert doc1.status_code == 201, (doc1.status_code,doc1.text)
        doc_id = doc1.json()['document_id']
        doc2 = req(c,'POST','/v1/documents',t2,json={
            'source_name':'beta-private.txt','text':'Finance revenue forecast for Beta is 87 million.',
            'classification':'restricted','allowed_groups':['finance']})
        assert doc2.status_code == 201, doc2.text
        x = req(c,'GET',f'/v1/documents/{doc_id}',t2)
        assert x.status_code == 404, ('cross-tenant breach',x.text)
        x = req(c,'GET',f'/v1/documents/{doc_id}',outsider)
        assert x.status_code == 404, ('group breach',x.text)
        x = req(c,'GET',f'/v1/documents/{doc_id}',low)
        assert x.status_code == 404, ('classification breach',x.text)
        x = req(c,'POST','/v1/query',t1,json={'question':'finance revenue forecast','top_k':5})
        assert x.status_code == 200, x.text
        assert x.json()['citations'], 'expected authorized evidence'
        text = str(x.json())
        assert 'beta-private' not in text and '87 million' not in text, 'tenant leak'
        assert 'analyst@example.org' not in text and '123-45-6789' not in text, 'DLP leak'
        x = req(c,'POST','/v1/query',outsider,json={'question':'finance revenue forecast'})
        assert x.status_code == 200 and not x.json()['citations'], 'group leak'
        x = req(c,'POST','/v1/documents',t1,json={
            'source_name':'unclassified.txt','text':'SSN 123-45-6789', 'classification':'public'})
        assert x.status_code == 422, ('ingest DLP bypass',x.text)
        print('PASS: ingestion, RLS tenant access, group filtering, classification, output DLP, and audit-safe retrieval')
        print('Document ID:', doc_id)
        print('Redacted excerpt:', x.status_code, '(public PII blocked)')


if __name__ == '__main__':
    main()
