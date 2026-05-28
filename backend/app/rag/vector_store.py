"""
Chroma persistent store for structured CIS recommendations.

Embeddings are supplied explicitly (from embeddings.py) so the same model is used
for indexing and querying without relying on Chroma’s built-in embedding wrappers.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import chromadb
from chromadb.api.models.Collection import Collection

from app.rag.embeddings import get_embedding_backend
from app.rag.ingestion import build_semantic_text, ingest_cis_pdf

DEFAULT_PERSIST = os.environ.get("CHROMA_CIS_PATH", "./.chroma_cis")
COLLECTION_NAME = "cis_gcp_structured_kb"


def _truncate(s: str, max_len: int = 1024) -> str:
    if len(s) <= max_len:
        return s
    return s[: max_len - 3] + "..."


def get_client(persist_directory: str | Path | None = None) -> chromadb.PersistentClient:
    path = str(persist_directory or DEFAULT_PERSIST)
    Path(path).mkdir(parents=True, exist_ok=True)
    return chromadb.PersistentClient(path=path)


def get_collection(
    client: chromadb.PersistentClient | None = None,
    *,
    persist_directory: str | Path | None = None,
) -> Collection:
    cl = client or get_client(persist_directory)
    return cl.get_or_create_collection(
        name=COLLECTION_NAME,
        metadata={"cloud_provider": "GCP", "source": "CIS_GCP_Foundation_Benchmark"},
    )


def index_from_pdf(
    pdf_path: str | Path,
    *,
    persist_directory: str | Path | None = None,
    reset: bool = True,
    use_pdfplumber: bool = False,
) -> int:
    """
    Parse PDF, embed semantic_text per recommendation, upsert into Chroma.
    Returns number of records indexed.
    """
    records = ingest_cis_pdf(pdf_path, use_pdfplumber=use_pdfplumber)
    return index_records(records, persist_directory=persist_directory, reset=reset)


def index_records(
    records: list[dict[str, Any]],
    *,
    persist_directory: str | Path | None = None,
    reset: bool = True,
) -> int:
    backend = get_embedding_backend()
    client = get_client(persist_directory)
    if reset:
        try:
            client.delete_collection(COLLECTION_NAME)
        except Exception:
            pass
    coll = get_collection(client)

    ids: list[str] = []
    documents: list[str] = []
    metadatas: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for rec in records:
        cid = rec["cis_id"].replace(".", "_")
        doc_id = f"cis_{cid}"
        # Safety net: dedupe before Chroma add() to avoid DuplicateIDError.
        if doc_id in seen_ids:
            continue
        seen_ids.add(doc_id)
        ids.append(doc_id)
        sem = build_semantic_text(rec)
        documents.append(sem)
        metadatas.append(
            {
                "cis_id": rec["cis_id"],
                "title": _truncate(rec.get("title", ""), 900),
                "section": _truncate(rec.get("section", ""), 500),
                "category": rec.get("category", "General"),
                "profile_level": rec.get("profile_level", "Unknown"),
                "severity": rec.get("severity", "Unknown"),
                "cloud_provider": "GCP",
                # Truncated for Chroma metadata limits; full control text remains in `documents`.
                "description": _truncate(rec.get("description", ""), 1800),
                "remediation": _truncate(rec.get("remediation", ""), 1800),
            }
        )

    if not ids:
        return 0
    embeddings = backend.embed_documents(documents)
    coll.add(ids=ids, embeddings=embeddings, documents=documents, metadatas=metadatas)
    return len(ids)


def collection_count(coll: Collection | None = None) -> int:
    c = coll or get_collection()
    return c.count()


if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(description="Index CIS PDF into Chroma")
    p.add_argument("pdf_path", type=Path)
    p.add_argument(
        "-o",
        "--out",
        type=Path,
        default=Path(DEFAULT_PERSIST),
        help="Chroma persist directory",
    )
    p.add_argument(
        "--no-reset",
        action="store_true",
        help="Do not delete existing collection first",
    )
    p.add_argument("--pdfplumber", action="store_true")
    args = p.parse_args()
    n = index_from_pdf(
        args.pdf_path,
        persist_directory=args.out,
        reset=not args.no_reset,
        use_pdfplumber=args.pdfplumber,
    )
    print(f"Indexed {n} CIS controls into {args.out}")
