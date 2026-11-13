"""Deterministic word windowing with bounded overlap."""
import re


def chunk_text(text: str, size: int = 90, overlap: int = 15) -> list[str]:
    if not 0 <= overlap < size:
        raise ValueError('Invalid chunk overlap')
    words = re.findall(r'\S+', text)
    if not words:
        return []
    chunks = []
    step = size - overlap
    for start in range(0, len(words), step):
        chunks.append(' '.join(words[start:start + size]))
        if start + size >= len(words):
            break
    return chunks
