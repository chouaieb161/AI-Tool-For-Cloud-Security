from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import numpy as np
from supabase import create_client, Client

from app.rag.embeddings import get_embedding_backend
from dotenv import load_dotenv
load_dotenv()
# =========================
# SUPABASE CONFIG ONLY
# =========================

SUPABASE_TABLE = os.environ.get("OCI_SUPABASE_VECTORS_TABLE", "oci_vectors")
SUPABASE_URL = os.environ.get("OCI_SUPABASE_URL")
SUPABASE_KEY = os.environ.get("OCI_SUPABASE_KEY")
SUPABASE_QUERY_NAME = os.environ.get("OCI_SUPABASE_QUERY_NAME", "match_documents")


# =========================
# UTILS
# =========================

def _normalize_embedding(embedding: list[float]) -> np.ndarray:
    return np.asarray(embedding, dtype=np.float32)


def _cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
    if a.size == 0 or b.size == 0:
        return 0.0
    denom = float(np.linalg.norm(a) * np.linalg.norm(b))
    if denom <= 0:
        return 0.0
    return float(np.dot(a, b) / denom)


# =========================
# SUPABASE COLLECTION
# =========================

class SupabaseCollection:
    def __init__(self, client: Client, table: str, query_name: str | None = None) -> None:
        self._client = client
        self._table = table
        self._query_name = query_name or SUPABASE_QUERY_NAME

    def add(
        self,
        *,
        ids: list[str],
        embeddings: list[list[float]],
        documents: list[str],
        metadatas: list[dict[str, Any]],
    ) -> None:
        if not ids:
            return

        rows: list[dict[str, Any]] = []
        for doc_id, emb, doc, meta in zip(ids, embeddings, documents, metadatas):
            rows.append(
                {
                    "id": doc_id,
                    "document": doc,
                    "metadata": meta,
                    "embedding": [float(x) for x in emb],
                }
            )

        self._client.table(self._table).upsert(rows).execute()

    def get(self) -> dict[str, Any]:
        resp = self._client.table(self._table).select(
            "id,document,metadata"
        ).execute()

        rows = resp.data or []
        return {
            "ids": [r["id"] for r in rows],
            "documents": [r.get("document", "") for r in rows],
            "metadatas": [r.get("metadata", {}) for r in rows],
        }

    def query(
        self,
        query_embeddings: list[list[float]],
        n_results: int,
        where: dict[str, Any] | None = None,
        include: list[str] | None = None,
    ) -> dict[str, Any]:

        if not query_embeddings:
            return {"ids": [[]], "distances": [[]]}

        query_vec = _normalize_embedding(query_embeddings[0])

        # =========================
        # Try Supabase RPC (pgvector)
        # =========================
        try:
            res = self._client.rpc(
                self._query_name,
                {
                    "query_embedding": query_embeddings[0],
                    "match_count": n_results,
                },
            ).execute()

            rows = res.data or []

            # metadata filter (optional)
            if where:
                rows = [
                    r for r in rows
                    if isinstance(r.get("metadata"), dict)
                    and all(r["metadata"].get(k) == v for k, v in where.items())
                ]

            ids = []
            distances = []

            for row in rows[:n_results]:
                ids.append(row.get("id"))

                sim = row.get("similarity")
                if sim is None:
                    emb = row.get("embedding")
                    if isinstance(emb, list):
                        sim = _cosine_similarity(query_vec, np.asarray(emb, dtype=np.float32))
                    else:
                        sim = 0.0

                distances.append(1.0 - float(sim))

            return {"ids": [ids], "distances": [distances]}

        # =========================
        # Fallback: client-side search
        # =========================
        except Exception:
            resp = self._client.table(self._table).select(
                "id,embedding,metadata"
            ).execute()

            rows = resp.data or []

            if where:
                rows = [
                    r for r in rows
                    if isinstance(r.get("metadata"), dict)
                    and all(r["metadata"].get(k) == v for k, v in where.items())
                ]

            scored = []

            for row in rows:
                emb = row.get("embedding")

                if isinstance(emb, str):
                    try:
                        import json
                        emb = json.loads(emb)
                    except Exception:
                        try:
                            emb = [float(x) for x in emb.strip("[]").split(",")]
                        except Exception:
                            continue

                if not isinstance(emb, list):
                    continue

                score = _cosine_similarity(
                    query_vec,
                    np.asarray(emb, dtype=np.float32),
                )

                scored.append((row["id"], score))

            scored.sort(key=lambda x: x[1], reverse=True)
            top = scored[:n_results]

            return {
                "ids": [[t[0] for t in top]],
                "distances": [[1.0 - t[1] for t in top]],
            }

    def count(self) -> int:
        resp = self._client.table(self._table).select("id", count="exact").execute()
        return int(resp.count or 0)

    def delete(self) -> None:
        self._client.table(self._table).delete().neq("id", "").execute()


# =========================
# CLIENT
# =========================

def get_client() -> Client:
    if not SUPABASE_URL or not SUPABASE_KEY:
        raise ValueError("Missing SUPABASE_URL or SUPABASE_KEY")

    return create_client(SUPABASE_URL, SUPABASE_KEY)


def get_collection(client: Client | None = None) -> SupabaseCollection:
    client = client or get_client()
    return SupabaseCollection(client, SUPABASE_TABLE, SUPABASE_QUERY_NAME)


# =========================
# INDEXING
# =========================

def index_records(
    records: list[dict[str, Any]],
    *,
    reset: bool = True,
) -> int:
    backend = get_embedding_backend()
    coll = get_collection()

    if reset:
        try:
            coll.delete()
        except Exception:
            pass

    ids: list[str] = []
    documents: list[str] = []
    metadatas: list[dict[str, Any]] = []

    seen = set()

    for rec in records:
        cid = rec["cis_id"].replace(".", "_")
        doc_id = f"oci_{cid}"

        if doc_id in seen:
            continue
        seen.add(doc_id)

        ids.append(doc_id)
        documents.append(rec.get("description", ""))

        metadatas.append({
            "cis_id": rec["cis_id"],
            "title": rec.get("title", ""),
            "section": rec.get("section", ""),
            "category": rec.get("category", "General"),
            "profile_level": rec.get("profile_level", "Unknown"),
            "severity": rec.get("severity", "Unknown"),
            "cloud_provider": "OCI",
        })

    if not ids:
        return 0

    embeddings = backend.embed_documents(documents)
    coll.add(
        ids=ids,
        embeddings=embeddings,
        documents=documents,
        metadatas=metadatas,
    )

    return len(ids)


# =========================
# UTILITY
# =========================

def collection_count() -> int:
    return get_collection().count()


if __name__ == "__main__":
    print("Supabase-only vector store ready.")