"""Secure document ingestion and *extractive* RAG retrieval service."""
import hashlib
from contextlib import asynccontextmanager
from uuid import UUID, uuid4
import httpx

from fastapi import FastAPI, HTTPException, Request

from .auth import PrincipalDep
from .chunking import chunk_text
from .config import Settings
from .dlp import detect_pii, has_prompt_injection_indicators, redact
from .embedding import get_embedding
from .models import (AuditRecord, Citation, DocumentMetadata, IngestRequest,
                     IngestResponse, QueryRequest, QueryResponse)
from .policy import can_audit, can_ingest
from .store import Store


@asynccontextmanager
async def lifespan(application: FastAPI):
    settings = Settings.from_env()
    store = Store(settings.database_url)
    store.open()
    application.state.settings = settings
    application.state.store = store
    try:
        yield
    finally:
        store.close()


app = FastAPI(title='Enterprise Secure RAG – AI Data Security', version='1.0.0',
              description='Authenticated multi-tenant retrieval with prefilter entitlements and audit trail.',
              lifespan=lifespan)


@app.get('/health/live')
def liveness():
    return {'status': 'ok'}


@app.get('/health/ready')
def readiness(request: Request):
    try:
        request.app.state.store.ping()
    except Exception as exc:
        raise HTTPException(status_code=503, detail='Database not ready') from exc
    return {'status': 'ready'}


@app.post('/v1/documents', response_model=IngestResponse, status_code=201)
def ingest(data: IngestRequest, principal: PrincipalDep, request: Request):
    groups = frozenset(data.allowed_groups)
    if not can_ingest(principal, data.classification, groups):
        raise HTTPException(status_code=403, detail='Insufficient ingest entitlement')
    pii = detect_pii(data.text)
    if pii and data.classification in ('public', 'internal'):
        raise HTTPException(status_code=422, detail='DLP: sensitive data requires confidential or restricted classification')
    chunks = chunk_text(data.text)
    if not chunks:
        raise HTTPException(status_code=422, detail='Document has no indexable text')
    settings = request.app.state.settings
    # Embeddings happen ONLY after the ingest policy and DLP check.
    try:
        vectors = [(chunk, hashlib.sha256(chunk.encode()).hexdigest(), get_embedding(chunk, settings))
                   for chunk in chunks]
    except (ValueError, OSError, RuntimeError, httpx.HTTPError) as exc:
        raise HTTPException(status_code=503, detail='Embedding service unavailable') from exc
    doc_id = request.app.state.store.ingest(
        principal, data.source_name, data.text, data.classification,
        list(groups), hashlib.sha256(data.text.encode()).hexdigest(),
        has_prompt_injection_indicators(data.text), vectors, str(uuid4()))
    return IngestResponse(document_id=doc_id, chunk_count=len(chunks),
                          classification=data.classification, pii_types=sorted(pii),
                          flagged_injection=has_prompt_injection_indicators(data.text))


@app.post('/v1/query', response_model=QueryResponse)
def query(data: QueryRequest, principal: PrincipalDep, request: Request):
    try:
        vector = get_embedding(data.question, request.app.state.settings)
    except (ValueError, OSError, RuntimeError, httpx.HTTPError) as exc:
        raise HTTPException(status_code=503, detail='Embedding service unavailable') from exc
    rows = request.app.state.store.search(principal, vector, data.top_k, str(uuid4()))
    citations = [Citation(document_id=row['document_id'], source_name=row['source_name'],
                          chunk_index=row['chunk_index'], classification=row['classification'],
                          excerpt=redact(row['content'])[:900], score=round(float(row['score']), 4),
                          warning='Potential prompt injection in source' if row['flagged_injection'] else None)
                 for row in rows]
    # Extractive-only: no call to an LLM, no claims of synthesized or trustworthy answers.
    answer = ('Authorized excerpts are provided below; verify the original sources.' if citations else
              'No authorized matching evidence is available in this tenant.')
    return QueryResponse(answer=answer, citations=citations, searched_tenant=principal.tenant_id)


@app.get('/v1/documents/{document_id}', response_model=DocumentMetadata)
def metadata(document_id: UUID, principal: PrincipalDep, request: Request):
    row = request.app.state.store.metadata(principal, document_id, str(uuid4()))
    if row is None:
        # Do not confirm whether an unauthorized document exists.
        raise HTTPException(status_code=404, detail='Document not found')
    return row


@app.get('/v1/audit', response_model=list[AuditRecord])
def audits(principal: PrincipalDep, request: Request, limit: int = 50):
    if not can_audit(principal):
        raise HTTPException(status_code=403, detail='Auditor role required')
    if not 1 <= limit <= 100:
        raise HTTPException(status_code=422, detail='limit must be 1..100')
    return request.app.state.store.audit_log(principal, limit)
