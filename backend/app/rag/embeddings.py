"""
Embedding backends for CIS KB: local BGE-large (GPU) or OpenAI text-embedding-3-large.

Queries for BGE use the official instruction prefix to align with retrieval tuning.
Documents are embedded as plain text (combined semantic field from ingestion).
"""

from __future__ import annotations

import os
import warnings
from abc import ABC, abstractmethod
from typing import Literal

import numpy as np

Provider = Literal["bge", "openai"]


def _torch_device() -> str:
    try:
        import torch

        return "cuda" if torch.cuda.is_available() else "cpu"
    except Exception:
        return "cpu"


def resolve_torch_device(requested: str | None) -> str:
    """
    Map CIS_*_DEVICE env (or explicit string) to a device PyTorch can use.

    If ``requested`` is empty, auto-select (CUDA when available, else CPU).
    If ``cuda``/``gpu`` is requested but this PyTorch build has no CUDA, fall back to CPU
    instead of raising (common on Windows with CPU-only ``torch`` wheels).
    """
    r = (requested or "").strip().lower()
    if not r:
        return _torch_device()
    if r in ("cuda", "gpu"):
        try:
            import torch

            if torch.cuda.is_available():
                return "cuda"
        except Exception:
            pass
        warnings.warn(
            "CUDA was requested (e.g. CIS_EMBED_DEVICE=cuda) but CUDA is not usable; "
            "using CPU. Install a CUDA-enabled PyTorch build or set CIS_EMBED_DEVICE=cpu.",
            UserWarning,
            stacklevel=2,
        )
        return "cpu"
    if r == "cpu":
        return "cpu"
    # e.g. mps for Apple Silicon
    return r


class EmbeddingBackend(ABC):
    @abstractmethod
    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        ...

    @abstractmethod
    def embed_queries(self, texts: list[str]) -> list[list[float]]:
        ...


class BgeLargeBackend(EmbeddingBackend):
    """BAAI/bge-large-en-v1.5 — strong general-purpose retriever embeddings; uses GPU if available."""

    QUERY_INSTR = "Represent this sentence for searching relevant passages: "

    def __init__(self, model_name: str | None = None) -> None:
        from sentence_transformers import SentenceTransformer

        name = model_name or os.environ.get(
            "CIS_EMBED_MODEL", "BAAI/bge-large-en-v1.5"
        )
        device = resolve_torch_device(os.environ.get("CIS_EMBED_DEVICE"))
        # trust_remote_code not needed for BGE on HF
        self._model = SentenceTransformer(name, device=device)
        self._model.max_seq_length = min(self._model.max_seq_length, 512)

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        if not texts:
            return []
        emb = self._model.encode(
            texts,
            batch_size=int(os.environ.get("CIS_EMBED_BATCH", "8")),
            normalize_embeddings=True,
            show_progress_bar=os.environ.get("CIS_ST_SHOW_PROGRESS", "").lower()
            in ("1", "true", "yes"),
        )
        return np.asarray(emb).tolist()

    def embed_queries(self, texts: list[str]) -> list[list[float]]:
        if not texts:
            return []
        prefixed = [f"{self.QUERY_INSTR}{t}" for t in texts]
        emb = self._model.encode(
            prefixed,
            batch_size=int(os.environ.get("CIS_EMBED_BATCH", "8")),
            normalize_embeddings=True,
            show_progress_bar=False,
        )
        return np.asarray(emb).tolist()


class OpenAIEmbeddingBackend(EmbeddingBackend):
    """OpenAI text-embedding-3-large (or override via CIS_OPENAI_EMBED_MODEL)."""

    def __init__(self) -> None:
        from openai import OpenAI

        self._client = OpenAI()
        self._model = os.environ.get(
            "CIS_OPENAI_EMBED_MODEL", "text-embedding-3-large"
        )

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        return self._embed(texts)

    def embed_queries(self, texts: list[str]) -> list[list[float]]:
        return self._embed(texts)

    def _embed(self, texts: list[str]) -> list[list[float]]:
        if not texts:
            return []
        out: list[list[float]] = []
        batch = int(os.environ.get("CIS_OPENAI_EMBED_BATCH", "16"))
        for i in range(0, len(texts), batch):
            chunk = texts[i : i + batch]
            resp = self._client.embeddings.create(model=self._model, input=chunk)
            # API returns in request order
            data = sorted(resp.data, key=lambda d: d.index)
            out.extend([list(d.embedding) for d in data])
        return out


_backend_singleton: EmbeddingBackend | None = None


def get_embedding_backend() -> EmbeddingBackend:
    global _backend_singleton
    if _backend_singleton is None:
        provider = os.environ.get("CIS_EMBEDDING_PROVIDER", "bge").lower().strip()
        if provider == "openai":
            _backend_singleton = OpenAIEmbeddingBackend()
        else:
            _backend_singleton = BgeLargeBackend()
    return _backend_singleton
