from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import numpy as np

from app.rag.embeddings import get_embedding_backend
from app.oci_agent.rag.vector_store import get_collection


JSONL_PATH = Path("cis_oci.jsonl")


def build_document(rec: dict[str, Any]) -> str:
    """Text used for embedding + retrieval."""
    return "\n\n".join([
        rec.get("title", ""),
        rec.get("description", ""),
        rec.get("rationale", ""),
        rec.get("remediation", ""),
    ])


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    records = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            try:
                records.append(json.loads(line))
            except Exception:
                continue
    return records


def ingest_to_supabase(reset: bool = True) -> int:
    backend = get_embedding_backend()
    coll = get_collection()

    records = load_jsonl(JSONL_PATH)

    if reset:
        try:
            coll.delete()
        except Exception:
            pass

    ids = []
    documents = []
    metadatas = []

    for rec in records:
        cid = rec["cis_id"]
        doc_id = f"oci_{cid}"

        text = build_document(rec)

        ids.append(doc_id)
        documents.append(text)

        metadatas.append({
            "cis_id": rec["cis_id"],
            "title": rec.get("title", ""),
            "category": rec.get("category", ""),
            "severity": rec.get("severity", "Medium"),
            "profile_level": rec.get("profile_level", ""),
            "cloud_provider": "OCI",
        })

    embeddings = backend.embed_documents(documents)

    coll.add(
        ids=ids,
        embeddings=embeddings,
        documents=documents,
        metadatas=metadatas,
    )

    return len(ids)


if __name__ == "__main__":
    n = ingest_to_supabase(reset=True)
    print(f"✅ Stored {n} CIS OCI records into Supabase")