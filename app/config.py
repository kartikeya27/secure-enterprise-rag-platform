"""Validated service configuration; production must use a real OIDC issuer."""
import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    app_env: str
    auth_mode: str
    issuer: str
    audience: str
    local_jwt_secret: str
    jwks_url: str
    database_url: str
    embedding_backend: str
    ollama_base_url: str
    ollama_embed_model: str

    @classmethod
    def from_env(cls) -> 'Settings':
        s = cls(
            app_env=os.getenv('APP_ENV', 'local'),
            auth_mode=os.getenv('AUTH_MODE', 'local'),
            issuer=os.getenv('AUTH_ISSUER', 'secure-rag-local'),
            audience=os.getenv('AUTH_AUDIENCE', 'secure-rag-api'),
            local_jwt_secret=os.getenv('LOCAL_JWT_SECRET', ''),
            jwks_url=os.getenv('OIDC_JWKS_URL', ''),
            database_url=os.getenv('DATABASE_URL', ''),
            embedding_backend=os.getenv('EMBEDDING_BACKEND', 'hash'),
            ollama_base_url=os.getenv('OLLAMA_BASE_URL', 'http://host.docker.internal:11434').rstrip('/'),
            ollama_embed_model=os.getenv('OLLAMA_EMBED_MODEL', 'all-minilm'),
        )
        if s.auth_mode not in ('local', 'oidc'):
            raise RuntimeError('AUTH_MODE must be local or oidc')
        if s.app_env not in ('local', 'test') and s.auth_mode != 'oidc':
            raise RuntimeError('Nonlocal deployments MUST use OIDC/JWKS, not symmetric local tokens')
        if s.auth_mode == 'local' and len(s.local_jwt_secret) < 32:
            raise RuntimeError('LOCAL_JWT_SECRET must have >=32 characters')
        if s.auth_mode == 'oidc' and not (s.jwks_url.startswith('https://') and s.issuer.startswith('https://')):
            raise RuntimeError('OIDC requires HTTPS issuer and JWKS URL')
        if not s.database_url.startswith(('postgresql://', 'postgres://')):
            raise RuntimeError('DATABASE_URL must be PostgreSQL')
        if s.embedding_backend not in ('hash', 'ollama'):
            raise RuntimeError('EMBEDDING_BACKEND must be hash or ollama')
        if s.app_env not in ('local', 'test') and s.embedding_backend == 'hash':
            raise RuntimeError('Nonlocal deployments must supply a vetted real embedding backend')
        if s.embedding_backend == 'ollama' and not (s.ollama_base_url.startswith('http://') or s.ollama_base_url.startswith('https://')):
            raise RuntimeError('OLLAMA_BASE_URL must be an HTTP(S) URL')
        return s
