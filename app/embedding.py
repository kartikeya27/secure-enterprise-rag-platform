"""384D vector embeddings: deterministic lexical demo, optional local Ollama."""
import hashlib
import math
import re
import httpx

DIMENSIONS = 384
TOKENS = re.compile(r"[\w']+", flags=re.UNICODE)


def hash_embedding(text: str) -> list[float]:
    """Signed feature hashing is deterministic, NOT a semantic ML embedding."""
    vector = [0.0] * DIMENSIONS
    for word in TOKENS.findall(text.lower()):
        raw = hashlib.blake2b(word.encode('utf-8'), digest_size=8).digest()
        slot = int.from_bytes(raw[:4], 'big') % DIMENSIONS
        sign = 1 if raw[4] & 1 else -1
        vector[slot] += sign
    norm = math.sqrt(sum(val * val for val in vector))
    if not norm:
        raise ValueError('No indexable text')
    return [v / norm for v in vector]


def get_embedding(text: str, settings) -> list[float]:
    if settings.embedding_backend == 'hash':
        return hash_embedding(text)
    with httpx.Client(timeout=20.0, trust_env=False) as client:
        response = client.post(settings.ollama_base_url + '/api/embed',
                               json={'model': settings.ollama_embed_model, 'input': text})
        response.raise_for_status()
        payload = response.json()
    embeddings = payload.get('embeddings')
    if not isinstance(embeddings, list) or not embeddings or not isinstance(embeddings[0], list):
        raise ValueError('Embedding service returned invalid output')
    vector = embeddings[0]
    if len(vector) != DIMENSIONS or not all(isinstance(v, (float, int)) and math.isfinite(v) for v in vector):
        raise ValueError(f'Expected exactly {DIMENSIONS} finite embedding dimensions')
    return [float(v) for v in vector]


def vector_literal(embedding: list[float]) -> str:
    if len(embedding) != DIMENSIONS or not all(math.isfinite(v) for v in embedding):
        raise ValueError('Invalid embedding')
    return '[' + ','.join(f'{v:.10f}' for v in embedding) + ']'
