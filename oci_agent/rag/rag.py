"""Unified OCI CIS RAG Pipeline: PDF ingestion → embedding → Supabase storage + retrieval.

Supabase-only (no Chroma local storage). Single module for all RAG operations.

Usage:
    # Ingest CIS PDF/JSONL into Supabase:
    python -m app.oci_agent.rag.ingest_cis ingest [pdf_path]
    
    # Retrieve CIS controls from Supabase:
    python -m app.oci_agent.rag.ingest_cis retrieve "IAM security" [category] [top_k]

Example:
    export OCI_SUPABASE_URL=https://...
    export OCI_SUPABASE_KEY=...
    python -m app.oci_agent.rag.ingest_cis ingest ~/Downloads/cis.pdf
    python -m app.oci_agent.rag.ingest_cis retrieve "check user MFA"
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from typing import Any

import numpy as np
from supabase import create_client, Client

from app.rag.embeddings import get_embedding_backend

# ============================================================================
# CONFIG & CONSTANTS
# ============================================================================

PDF_DIR = Path(__file__).resolve().parent / "cis_pdf"
JSONL_PATH = Path(__file__).resolve().parents[3] / "cis_parsed.jsonl"

# Supabase env config
SUPABASE_URL = os.environ.get("OCI_SUPABASE_URL")
SUPABASE_KEY = os.environ.get("OCI_SUPABASE_KEY")
SUPABASE_TABLE = os.environ.get("OCI_SUPABASE_VECTORS_TABLE", "oci_vectors")
SUPABASE_QUERY_NAME = os.environ.get("OCI_SUPABASE_QUERY_NAME", "match_documents")

# CIS 6-category mapping
SECTION_CATEGORY = {
    "1": "Identity and Access Management",
    "2": "Networking",
    "3": "Logging and Monitoring",
    "4": "Compute",
    "5": "Storage",
    "6": "Asset Management",
}

SECTION_TITLE = {
    "1": "Identity and Access Management",
    "2": "Networking",
    "3": "Logging and Monitoring",
    "4": "Compute",
    "5": "Storage",
    "6": "Asset Management",
}

CONTROL_HEADER_RE = re.compile(r"(?P<id>\d+\.\d+(?:\.\d+)?)\s*(?P<title>[^\n]+)")


# ============================================================================
# PDF EXTRACTION & PARSING
# ============================================================================


def _find_pdf() -> Path | None:
    """Find first PDF in cis_pdf/ directory."""
    if not PDF_DIR.exists():
        return None
    pdfs = sorted(PDF_DIR.glob("*.pdf"))
    return pdfs[0] if pdfs else None


def _extract_text_from_pdf(pdf_path: Path) -> str:
    """Extract text from PDF using fitz or pdfplumber."""
    try:
        import fitz  # type: ignore

        doc = fitz.open(str(pdf_path))
        pages: list[str] = []
        for page in doc:
            pages.append(page.get_text("text"))
        doc.close()
        return "\n".join(pages)
    except Exception:
        pass

    try:
        import pdfplumber  # type: ignore

        text_parts: list[str] = []
        with pdfplumber.open(str(pdf_path)) as pdf:
            for page in pdf.pages:
                text_parts.append(page.extract_text() or "")
        return "\n".join(text_parts)
    except Exception as exc:
        raise RuntimeError(f"Could not extract text from PDF {pdf_path}: {exc}")


def _parse_controls(text: str) -> list[dict[str, Any]]:
    """Parse CIS control blocks from raw PDF text."""
    lines = text.splitlines()
    records: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    current_section: str | None = None

    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue

        header = CONTROL_HEADER_RE.match(line)
        if header and not line.lower().startswith(("figure", "table", "page")):
            if current is not None:
                records.append(current)
            major = header.group("id").split(".", maxsplit=1)[0]
            current = {
                "cis_id": header.group("id"),
                "title": header.group("title").strip().strip("."),
                "section": SECTION_TITLE.get(major, "General"),
                "category": SECTION_CATEGORY.get(major, "General"),
                "profile_level": "Level 1",
                "severity": "Medium",
                "description": "",
                "remediation": "",
            }
            current_section = "header"
            continue

        if current is None:
            continue

        lower = line.lower()
        if lower.startswith("description"):
            current_section = "description"
            continue
        if lower.startswith("rationale"):
            current_section = "rationale"
            continue
        if lower.startswith("remediation") or lower.startswith("remediation:"):
            current_section = "remediation"
            continue
        if lower.startswith("impact"):
            current_section = "impact"
            continue
        if lower.startswith("default value"):
            current_section = "default"
            continue
        if lower.startswith("references") or lower.startswith("see also"):
            current_section = "references"
            continue
        if lower.startswith("profile applicability"):
            current_section = "profile"
            if "level 2" in lower:
                current["profile_level"] = "Level 2"
            continue

        # Accumulate text into active section
        if current_section == "description":
            current["description"] = (current["description"] + " " + line).strip()
        elif current_section == "remediation":
            current["remediation"] = (current["remediation"] + " " + line).strip()
        elif current_section == "profile":
            if "level 2" in lower:
                current["profile_level"] = "Level 2"

    if current is not None:
        records.append(current)

    # Post-process: infer severity from keywords
    for rec in records:
        blob = (rec["title"] + " " + rec["description"]).lower()
        if any(k in blob for k in ("public", "0.0.0.0/0", "open", "unencrypted", "disabled", "root")):
            rec["severity"] = "High"
        if any(k in blob for k in ("mfa", "password", "key", "secret", "admin")):
            rec["severity"] = "High"
        if rec["remediation"] and not rec["description"]:
            rec["description"] = rec["title"]

    return records


def _load_from_jsonl() -> list[dict[str, Any]] | None:
    """Load pre-parsed CIS records from cis_parsed.jsonl."""
    if not JSONL_PATH.exists():
        return None
    records: list[dict[str, Any]] = []
    with JSONL_PATH.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                if isinstance(rec, dict) and rec.get("cis_id"):
                    records.append(rec)
            except json.JSONDecodeError:
                continue
    return records if records else None


def build_records(pdf_path: str | Path | None = None) -> list[dict[str, Any]]:
    """Build CIS records from JSONL or PDF (in that order)."""
    # Try JSONL first
    records = _load_from_jsonl()
    if records:
        print(f"✓ Loaded {len(records)} records from cis_parsed.jsonl")
        return records

    # Try explicit PDF path
    if pdf_path:
        pdf_path = Path(pdf_path).resolve()
        if not pdf_path.exists():
            raise FileNotFoundError(f"PDF not found: {pdf_path}")
        text = _extract_text_from_pdf(pdf_path)
        records = _parse_controls(text)
        print(f"✓ Parsed {len(records)} controls from {pdf_path.name}")
        return records

    # Search cis_pdf/ directory
    found_pdf = _find_pdf()
    if found_pdf is None:
        raise FileNotFoundError(
            f"No CIS PDF found in {PDF_DIR} and no cis_parsed.jsonl at {JSONL_PATH}"
        )
    text = _extract_text_from_pdf(found_pdf)
    records = _parse_controls(text)
    print(f"✓ Parsed {len(records)} controls from {found_pdf.name}")
    return records


# ============================================================================
# SUPABASE UTILITIES
# ============================================================================


def _get_supabase_client() -> Client:
    """Get Supabase client; raise if credentials missing."""
    if not SUPABASE_URL or not SUPABASE_KEY:
        raise ValueError(
            "Missing OCI_SUPABASE_URL or OCI_SUPABASE_KEY. "
            "Set these environment variables to use Supabase."
        )
    return create_client(SUPABASE_URL, SUPABASE_KEY)


def _normalize_embedding(embedding: list[float]) -> np.ndarray:
    """Normalize embedding to float32 numpy array."""
    return np.asarray(embedding, dtype=np.float32)


def _cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
    """Compute cosine similarity between two vectors."""
    if a.size == 0 or b.size == 0:
        return 0.0
    denom = float(np.linalg.norm(a) * np.linalg.norm(b))
    if denom <= 0:
        return 0.0
    return float(np.dot(a, b) / denom)


# ============================================================================
# INGESTION PIPELINE
# ============================================================================


def ingest_to_supabase(pdf_path: str | Path | None = None, reset: bool = True) -> int:
    """
    Complete ingest pipeline: parse CIS PDF/JSONL → embed → Supabase.
    
    Args:
        pdf_path: Optional explicit PDF path. If None, searches cis_pdf/ or uses cis_parsed.jsonl.
        reset: If True, clears Supabase table before ingesting.
    
    Returns:
        Number of records ingested.
    
    Raises:
        ValueError: If Supabase credentials not set.
        FileNotFoundError: If no CIS source found.
    """
    client = _get_supabase_client()
    backend = get_embedding_backend()

    # Load records
    records = build_records(pdf_path)
    if not records:
        print("✗ No records to ingest.")
        return 0

    # Clear table if requested
    if reset:
        try:
            client.table(SUPABASE_TABLE).delete().neq("id", "").execute()
            print(f"✓ Cleared {SUPABASE_TABLE}")
        except Exception as e:
            print(f"⚠ Warning: Could not clear table: {e}")

    # Prepare data
    ids: list[str] = []
    documents: list[str] = []
    metadatas: list[dict[str, Any]] = []
    seen_ids: set[str] = set()

    for rec in records:
        cid = rec["cis_id"].replace(".", "_")
        doc_id = f"oci_{cid}"
        if doc_id in seen_ids:
            continue
        seen_ids.add(doc_id)
        ids.append(doc_id)
        documents.append(rec.get("description", ""))
        metadatas.append(
            {
                "cis_id": rec["cis_id"],
                "title": rec.get("title", ""),
                "section": rec.get("section", ""),
                "category": rec.get("category", "General"),
                "profile_level": rec.get("profile_level", "Unknown"),
                "severity": rec.get("severity", "Unknown"),
                "cloud_provider": "OCI",
            }
        )

    # Embed documents
    print(f"→ Embedding {len(ids)} documents...")
    embeddings = backend.embed_documents(documents)

    # Prepare rows
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

    # Upsert to Supabase (batch processing)
    batch_size = 100
    for i in range(0, len(rows), batch_size):
        batch = rows[i : i + batch_size]
        try:
            client.table(SUPABASE_TABLE).upsert(batch).execute()
            progress = min(i + batch_size, len(rows))
            print(f"  ✓ Upserted {len(batch)} rows ({progress}/{len(rows)})")
        except Exception as e:
            print(f"  ✗ Upsert batch failed: {e}")
            raise

    print(f"✓ Successfully ingested {len(ids)} CIS controls to Supabase table '{SUPABASE_TABLE}'")
    return len(ids)


# ============================================================================
# RETRIEVAL PIPELINE
# ============================================================================


def retrieve_from_supabase(
    query: str,
    top_k: int = 5,
    category: str | None = None,
) -> list[dict[str, Any]]:
    """
    Retrieve CIS controls from Supabase via semantic similarity.
    
    Uses server-side pgvector RPC (match_documents) if available,
    falls back to client-side cosine similarity if RPC fails.
    
    Args:
        query: User query text.
        top_k: Number of results.
        category: Optional category filter (e.g., "Identity and Access Management").
    
    Returns:
        List of CIS control dicts with cis_id, title, relevant_text, category, severity.
    
    Raises:
        ValueError: If Supabase credentials not set.
    """
    client = _get_supabase_client()
    backend = get_embedding_backend()

    # Embed query
    q_emb = backend.embed_queries([query])[0]

    # Try server-side pgvector RPC
    try:
        match_params = {"query_embedding": q_emb, "match_count": top_k}
        res = client.rpc(SUPABASE_QUERY_NAME, match_params).execute()
        rows = res.data or []
        
        # Apply client-side category filter if needed
        if category and rows:
            rows = [
                r for r in rows
                if isinstance(r.get("metadata"), dict) and r["metadata"].get("category") == category
            ]
    except Exception as e:
        # Fallback: client-side scoring
        print(f"⚠ RPC '{SUPABASE_QUERY_NAME}' not available; using client-side scoring: {e}")
        resp = client.table(SUPABASE_TABLE).select("id,embedding,metadata,document").execute()
        rows_raw = resp.data or []

        if category:
            rows_raw = [
                r
                for r in rows_raw
                if isinstance(r.get("metadata"), dict) and r["metadata"].get("category") == category
            ]

        q_vec = _normalize_embedding(q_emb)
        scored: list[tuple[dict[str, Any], float]] = []
        for row in rows_raw:
            emb = row.get("embedding")
            # Handle embedding as JSON string or list
            if isinstance(emb, str):
                try:
                    emb = json.loads(emb)
                except (json.JSONDecodeError, TypeError):
                    continue
            if not isinstance(emb, list):
                continue
            score = _cosine_similarity(q_vec, np.asarray(emb, dtype=np.float32))
            scored.append((row, score))

        scored.sort(key=lambda x: x[1], reverse=True)
        rows = [r[0] for r in scored[:top_k]]

    # Format results
    results: list[dict[str, Any]] = []
    for row in rows:
        meta = row.get("metadata") or {}
        results.append(
            {
                "cis_id": meta.get("cis_id", ""),
                "title": meta.get("title", ""),
                "relevant_text": row.get("document", "")[:2000],
                "remediation": meta.get("remediation", "")[:2000],
                "category": meta.get("category"),
                "profile_level": meta.get("profile_level"),
                "severity": meta.get("severity"),
            }
        )

    return results


# ============================================================================
# CLI ENTRY POINT
# ============================================================================


def main() -> None:
    """CLI for ingest and retrieve operations."""
    if len(sys.argv) < 2:
        print("Unified OCI CIS RAG Pipeline (Supabase-only)")
        print()
        print("Usage:")
        print("  python -m app.oci_agent.rag.ingest_cis ingest [pdf_path]")
        print("  python -m app.oci_agent.rag.ingest_cis retrieve <query> [category] [top_k]")
        print()
        print("Examples:")
        print("  python -m app.oci_agent.rag.ingest_cis ingest")
        print("  python -m app.oci_agent.rag.ingest_cis ingest ~/Downloads/oci-cis.pdf")
        print("  python -m app.oci_agent.rag.ingest_cis retrieve 'check IAM policy'")
        print("  python -m app.oci_agent.rag.ingest_cis retrieve 'MFA' 'Identity and Access Management' 10")
        sys.exit(1)

    cmd = sys.argv[1].lower()

    if cmd == "ingest":
        try:
            pdf_path = sys.argv[2] if len(sys.argv) > 2 else None
            n = ingest_to_supabase(pdf_path=pdf_path, reset=True)
            print(f"\n✓✓✓ Ingestion complete: {n} CIS controls in Supabase")
        except Exception as e:
            print(f"\n✗ Ingestion failed: {e}")
            sys.exit(1)

    elif cmd == "retrieve":
        if len(sys.argv) < 3:
            print("Usage: retrieve <query> [category] [top_k]")
            print("Example: retrieve 'check MFA' 'Identity and Access Management' 5")
            sys.exit(1)
        try:
            query_str = sys.argv[2]
            cat = sys.argv[3] if len(sys.argv) > 3 else None
            k = int(sys.argv[4]) if len(sys.argv) > 4 else 5

            results = retrieve_from_supabase(query_str, top_k=k, category=cat)
            print(f"\nRetrieved {len(results)} result(s) for: '{query_str}'")
            if cat:
                print(f"(filtered by category: {cat})\n")
            else:
                print()

            for i, r in enumerate(results, 1):
                print(f"{i}. CIS {r['cis_id']}: {r['title']}")
                print(f"   Category: {r['category']} | Severity: {r['severity']}")
                print(f"   Profile: {r['profile_level']}")
                excerpt = r["relevant_text"][:150].replace("\n", " ")
                print(f"   → {excerpt}...\n")

        except Exception as e:
            print(f"\n✗ Retrieval failed: {e}")
            sys.exit(1)

    else:
        print(f"Unknown command: {cmd}")
        print("Available: ingest, retrieve")
        sys.exit(1)


if __name__ == "__main__":
    main()