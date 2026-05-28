"""
Hybrid CIS retriever: semantic (Chroma) + BM25 + optional cross-encoder reranking.

Query parser maps natural language to a category metadata filter for higher precision.
Output rows: cis_id, title, relevant_text, remediation (minimal tokens for LLM context).
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import numpy as np
from rank_bm25 import BM25Okapi

from app.rag.embeddings import get_embedding_backend, resolve_torch_device
from app.rag.vector_store import DEFAULT_PERSIST, get_collection

# Intent → Chroma `category` value (must match ingestion.SECTION_META)
CATEGORY_ALIASES: list[tuple[frozenset[str], str]] = [
    (
        frozenset(
            {
                "iam",
                "identity",
                "service account",
                "service accounts",
                "mfa",
                "api key",
                "kms",
                "admin",
                "iam policy",
            }
        ),
        "IAM",
    ),
    (
        frozenset(
            {
                "network",
                "networking",
                "vpc",
                "firewall",
                "flow log",
                "flow logs",
                "subnet",
                "dns",
                "ssl",
                "iap",
                "load balancer",
            }
        ),
        "Networking",
    ),
    (
        frozenset(
            {
                "storage",
                "bucket",
                "buckets",
                "gcs",
                "cloud storage",
                "uniform",
                "versioning",
            }
        ),
        "Storage",
    ),
    (
        frozenset(
            {
                "sql",
                "cloud sql",
                "database",
                "mysql",
                "postgres",
                "postgresql",
            }
        ),
        "SQL",
    ),
    (
        frozenset(
            {
                "log",
                "logging",
                "monitoring",
                "sink",
                "sinks",
                "audit log",
                "alert",
                "metric",
            }
        ),
        "Logging",
    ),
    (
        frozenset(
            {
                "compute",
                "vm",
                "vms",
                "instance",
                "instances",
                "shielded",
                "serial port",
                "ssh",
                "oslogin",
            }
        ),
        "Compute",
    ),
    (frozenset({"bigquery", "bq", "dataset", "datasets"}), "BigQuery"),
    (frozenset({"dataproc", "spark", "hadoop"}), "Dataproc"),
]


def parse_query_intent(query: str) -> tuple[str, str | None]:
    """
    Returns (normalized_query, category_filter or None).
    Category filter is applied as Chroma metadata where ``category == filter``.
    Uses word-boundary checks for short tokens to avoid false positives (e.g. ``log`` in ``catalog``).
    """
    q = query.lower()
    for phrases, cat in CATEGORY_ALIASES:
        for p in phrases:
            if " " in p:
                if p in q:
                    return query, cat
            else:
                if len(p) <= 3:
                    if re.search(rf"(?<![a-z0-9]){re.escape(p)}(?![a-z0-9])", q):
                        return query, cat
                elif re.search(rf"\b{re.escape(p)}\b", q):
                    return query, cat
    return query, None


def _tokenize(text: str) -> list[str]:
    return re.findall(r"[a-z0-9]{2,}", text.lower())


def _rrf_merge(rank_lists: list[list[str]], k: int = 60) -> list[str]:
    scores: dict[str, float] = {}
    for ranks in rank_lists:
        for i, doc_id in enumerate(ranks):
            scores[doc_id] = scores.get(doc_id, 0.0) + 1.0 / (k + i + 1)
    return sorted(scores.keys(), key=lambda x: scores[x], reverse=True)


class CISRetriever:
    """
    Loads Chroma collection + BM25 over the same corpus. Optional cross-encoder rerank.
    """

    def __init__(
        self,
        *,
        persist_directory: str | Path | None = None,
        semantic_k: int = 20,
        bm25_k: int = 20,
        final_k: int = 5,
        enable_rerank: bool | None = None,
    ) -> None:
        self.persist_directory = str(persist_directory or DEFAULT_PERSIST)
        self.semantic_k = semantic_k
        self.bm25_k = bm25_k
        self.final_k = final_k
        if enable_rerank is None:
            enable_rerank = os.environ.get("CIS_ENABLE_RERANK", "1").lower() in (
                "1",
                "true",
                "yes",
            )
        self.enable_rerank = enable_rerank
        self._coll = get_collection(persist_directory=self.persist_directory)
        self._backend = get_embedding_backend()
        self._bm25: BM25Okapi | None = None
        self._ids: list[str] = []
        self._corpus_tokens: list[list[str]] = []
        self._meta_by_id: dict[str, dict[str, Any]] = {}
        self._reranker = None
        self._warm_cache()

    def _warm_cache(self) -> None:
        data = self._coll.get(include=["documents", "metadatas"])
        self._ids = data["ids"] or []
        docs = data["documents"] or []
        metas = data["metadatas"] or []
        self._meta_by_id = {}
        for i, m in zip(self._ids, metas):
            if m is not None:
                self._meta_by_id[i] = m
        self._corpus_tokens = [_tokenize(d or "") for d in docs]
        if self._corpus_tokens:
            self._bm25 = BM25Okapi(self._corpus_tokens)
        if self.enable_rerank:
            try:
                from sentence_transformers import CrossEncoder

                device = resolve_torch_device(os.environ.get("CIS_RERANK_DEVICE"))
                model = os.environ.get(
                    "CIS_RERANK_MODEL", "BAAI/bge-reranker-base"
                )
                self._reranker = CrossEncoder(model, device=device)
            except Exception:
                self._reranker = None

    def retrieve(
        self,
        query: str,
        *,
        top_k: int | None = None,
        category: str | None = None,
    ) -> list[dict[str, Any]]:
        """
        Hybrid retrieval + optional rerank.
        If ``category`` is None, parser infers from ``query``.
        """
        k = top_k or self.final_k
        _, parsed_cat = parse_query_intent(query)
        cat_filter = category or parsed_cat

        if not self._ids:
            return []

        q_emb = self._backend.embed_queries([query])[0]

        where: dict[str, Any] | None = None
        if cat_filter:
            where = {"category": cat_filter}

        n_sem = min(self.semantic_k, max(len(self._ids), 1))
        sem = self._coll.query(
            query_embeddings=[q_emb],
            n_results=n_sem,
            where=where,
            include=["distances"],
        )
        sem_ids = (sem.get("ids") or [[]])[0]

        bm25_ids: list[str] = []
        if self._bm25 and self._ids:
            scores = self._bm25.get_scores(_tokenize(query))
            ranked_idx = np.argsort(scores)[::-1][: self.bm25_k]
            bm25_ids = [self._ids[i] for i in ranked_idx if i < len(self._ids)]
            if cat_filter:
                bm25_ids = [
                    i
                    for i in bm25_ids
                    if (self._meta_by_id.get(i) or {}).get("category") == cat_filter
                ]

        fused = _rrf_merge([sem_ids, bm25_ids])
        pool = fused[: max(12, k * 3)]

        rows = [self._to_output_row(doc_id) for doc_id in pool]
        rows = [r for r in rows if r]

        if self._reranker and rows:
            pairs = [
                (query, f"{r['title']}\n{r['relevant_text']}") for r in rows
            ]
            scores = self._reranker.predict(
                pairs,
                show_progress_bar=os.environ.get("CIS_ST_SHOW_PROGRESS", "").lower()
                in ("1", "true", "yes"),
            )
            order = np.argsort(scores)[::-1]
            rows = [rows[int(i)] for i in order]

        return rows[:k]

    def _to_output_row(self, doc_id: str) -> dict[str, Any] | None:
        meta = self._meta_by_id.get(doc_id)
        if not meta:
            return None
        desc = meta.get("description") or ""
        rem = meta.get("remediation") or ""
        return {
            "cis_id": meta.get("cis_id", ""),
            "title": meta.get("title", ""),
            "relevant_text": desc[:2000] if desc else "",
            "remediation": rem[:2000] if rem else "",
            "category": meta.get("category"),
            "profile_level": meta.get("profile_level"),
        }


def format_retrieval_for_prompt(results: list[dict[str, Any]]) -> str:
    """Compact string for LLM consumption (minimal tokens)."""
    parts = []
    for i, r in enumerate(results, start=1):
        parts.append(
            f"### CIS {r.get('cis_id','')} — {r.get('title','')}\n"
            f"**Relevant excerpt:**\n{r.get('relevant_text','')}\n\n"
            f"**Remediation:**\n{r.get('remediation','')}\n"
        )
    return "\n---\n".join(parts) if parts else "(No CIS rules retrieved.)"


# --- Backwards compatibility for agent / rag_engine ---
_default_retriever: CISRetriever | None = None


def get_retriever(persist_directory: str | None = None) -> CISRetriever:
    global _default_retriever
    path = persist_directory or os.environ.get("CHROMA_CIS_PATH", DEFAULT_PERSIST)
    if _default_retriever is None or _default_retriever.persist_directory != str(path):
        _default_retriever = CISRetriever(persist_directory=path)
    return _default_retriever


def retrieve_cis(
    query: str,
    *,
    top_k: int = 5,
    category: str | None = None,
    persist_directory: str | None = None,
) -> str:
    """One-shot: hybrid retrieve + formatted markdown-ish text."""
    r = get_retriever(persist_directory)
    rows = r.retrieve(query, top_k=top_k, category=category)
    return format_retrieval_for_prompt(rows)


if __name__ == "__main__":
    import sys

    q = " ".join(sys.argv[1:]) or "check IAM risks for service account keys"
    for row in CISRetriever().retrieve(q, top_k=5):
        print(row["cis_id"], "-", row["title"][:80])
