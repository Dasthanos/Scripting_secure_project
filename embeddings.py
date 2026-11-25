"""Bounded text chunks and local Ollama embeddings for semantic retrieval."""
from __future__ import annotations

from array import array
from http.client import HTTPConnection, HTTPException
import json
import math
from urllib.parse import urlsplit

from .llm import LocalModelError


def text_chunks(text: str, size: int = 360, overlap: int = 60) -> list[str]:
    """Bound chunks in UTF-8 bytes, preserving complete characters."""
    if not 0 <= overlap < size:
        raise ValueError("Chunk overlap must be smaller than the chunk size.")
    data = text.encode("utf-8")
    chunks = []
    start = 0
    while start < len(data):
        end = min(start + size, len(data))
        if end < len(data):
            while end > start and data[end] & 0xC0 == 0x80:
                end -= 1
            if end == start:
                raise ValueError("Chunk size is too small for a UTF-8 character.")
            boundary_start = max(start + size // 2, start + overlap + 1)
            boundary = max(data.rfind(b"\n", boundary_start, end),
                           data.rfind(b" ", boundary_start, end))
            if boundary != -1:
                end = boundary + 1
        chunk = data[start:end].decode("utf-8").strip()
        if chunk:
            chunks.append(chunk)
        if end == len(data):
            break
        start = max(start + 1, end - overlap)
        while start < end and data[start] & 0xC0 == 0x80:
            start += 1
    return chunks


class OllamaEmbedder:
    """Embed document and query chunks with the same locally installed model."""

    def __init__(self, model: str, host: str, timeout: int):
        endpoint = urlsplit(host)
        if (endpoint.scheme != "http" or endpoint.hostname not in {"localhost", "127.0.0.1", "::1"}
                or endpoint.username is not None or endpoint.path not in {"", "/"}
                or endpoint.query or endpoint.fragment):
            raise LocalModelError("Embedding endpoint must be an HTTP loopback Ollama URL.")
        if model.lower().endswith(("-cloud", ":cloud")):
            raise LocalModelError("Choose a locally installed Ollama embedding model.")
        self.model = model
        self.host = endpoint.hostname
        self.port = endpoint.port or 80
        self.timeout = timeout
        self.dimensions = 0

    def embed(self, inputs: list[str]) -> list[array]:
        vectors = []
        for offset in range(0, len(inputs), 32):
            batch = inputs[offset:offset + 32]
            payload = json.dumps({
                "model": self.model,
                "input": batch,
                "truncate": False,
                "options": {"num_ctx": 512},
            })
            connection = HTTPConnection(self.host, self.port, timeout=self.timeout)
            try:
                connection.request("POST", "/api/embed", payload, {"Content-Type": "application/json"})
                with connection.getresponse() as response:
                    if response.status != 200:
                        raise LocalModelError(
                            f"Ollama embeddings returned HTTP {response.status} for {self.model}. "
                            "Check that Ollama supports /api/embed and the model is installed locally."
                        )
                    data = json.loads(response.read())
            except (OSError, HTTPException, ValueError) as exc:
                raise LocalModelError(f"Unable to read local Ollama embeddings: {exc}") from exc
            finally:
                connection.close()

            rows = data.get("embeddings") if isinstance(data, dict) else None
            if not isinstance(rows, list) or len(rows) != len(batch):
                raise LocalModelError("Ollama returned the wrong number of embeddings.")
            for row in rows:
                if not isinstance(row, list) or not row:
                    raise LocalModelError("Ollama returned an empty or invalid embedding.")
                try:
                    length = math.hypot(*row)
                except (TypeError, OverflowError) as exc:
                    raise LocalModelError("Ollama returned an invalid embedding.") from exc
                if not math.isfinite(length) or length == 0:
                    raise LocalModelError("Ollama returned a non-finite or zero-length embedding.")
                if self.dimensions and len(row) != self.dimensions:
                    raise LocalModelError("Ollama returned inconsistent embedding dimensions.")
                self.dimensions = len(row)
                vectors.append(array("f", (value / length for value in row)))
        return vectors
