from datetime import datetime
from uuid import UUID
from pydantic import BaseModel, Field, field_validator
from typing import Literal

Classification = Literal['public', 'internal', 'confidential', 'restricted']


class IngestRequest(BaseModel):
    source_name: str = Field(min_length=1, max_length=150)
    text: str = Field(min_length=1, max_length=20000)
    classification: Classification
    allowed_groups: list[str] = Field(default_factory=list, max_length=32)

    @field_validator('source_name', 'text')
    @classmethod
    def non_whitespace(cls, value: str) -> str:
        if not value.strip():
            raise ValueError('Cannot be whitespace only')
        return value

    @field_validator('allowed_groups')
    @classmethod
    def valid_groups(cls, value: list[str]) -> list[str]:
        import re
        if any(not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.:@-]{0,127}', g) for g in value):
            raise ValueError('Invalid group name')
        return list(dict.fromkeys(value))


class IngestResponse(BaseModel):
    document_id: UUID
    chunk_count: int
    classification: Classification
    pii_types: list[str]
    flagged_injection: bool


class QueryRequest(BaseModel):
    question: str = Field(min_length=2, max_length=2000)
    top_k: int = Field(default=3, ge=1, le=10)

    @field_validator('question')
    @classmethod
    def non_whitespace_question(cls, value: str) -> str:
        if not value.strip():
            raise ValueError('Question cannot be whitespace only')
        return value


class Citation(BaseModel):
    document_id: UUID
    source_name: str
    chunk_index: int
    classification: Classification
    excerpt: str
    score: float
    warning: str | None = None


class QueryResponse(BaseModel):
    answer: str
    citations: list[Citation]
    searched_tenant: str
    generation_mode: Literal['extractive_only'] = 'extractive_only'


class DocumentMetadata(BaseModel):
    document_id: UUID
    source_name: str
    classification: Classification
    allowed_groups: list[str]
    content_sha256: str
    flagged_injection: bool


class AuditRecord(BaseModel):
    id: int
    actor_id: str
    action: str
    decision: str
    reason: str
    resource_id: UUID | None
    request_id: str
    created_at: datetime
