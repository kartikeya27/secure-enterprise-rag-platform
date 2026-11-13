import math
import pytest
from app.chunking import chunk_text
from app.embedding import DIMENSIONS, hash_embedding, vector_literal


def test_chunking_preserves_content_and_has_overlap():
    words = ' '.join(f'w{i}' for i in range(200))
    chunks = chunk_text(words, size=40, overlap=10)
    assert len(chunks) > 2
    assert chunks[0].split()[-10:] == chunks[1].split()[:10]
    assert chunks[-1].split()[-1] == 'w199'


def test_embedding_is_normalized_and_deterministic():
    a = hash_embedding('tenant security vector database')
    assert len(a) == DIMENSIONS
    assert a == hash_embedding('tenant security vector database')
    assert math.isclose(sum(x*x for x in a), 1.0)
    assert vector_literal(a).startswith('[')
    assert hash_embedding('alpha alpha alpha') != hash_embedding('beta beta beta')


def test_empty_embedding_fails_closed():
    with pytest.raises(ValueError):
        hash_embedding('   ')
    with pytest.raises(ValueError):
        vector_literal([float('nan')] * DIMENSIONS)
