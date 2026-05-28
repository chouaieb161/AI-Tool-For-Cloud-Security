"""
CIS GCP Benchmark PDF → structured recommendation records (one document per CIS ID).

Design choices:
- PyMuPDF (fitz) for fast, reliable text extraction (user may swap to pdfplumber via flag).
- Split on ``^(?m)\\d{1,2}\\.\\d{1,3}\\s+`` then keep blocks that look like real controls
  (contain Description + Rationale, sufficient length) — avoids Table-of-Contents rows.
- Field boundaries use CIS header labels (Description, Rationale, Audit, Remediation, …).
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

import fitz  # PyMuPDF

# Major section number → (full section title, short category for filters / agent)
SECTION_META: dict[str, tuple[str, str]] = {
    "1": ("Identity and Access Management", "IAM"),
    "2": ("Logging and Monitoring", "Logging"),
    "3": ("Networking", "Networking"),
    "4": ("Virtual Machines", "Compute"),
    "5": ("Storage", "Storage"),
    "6": ("Cloud SQL Database Services", "SQL"),
    "7": ("BigQuery", "BigQuery"),
    "8": ("Dataproc", "Dataproc"),
}

# Ordered headers; first occurrence wins (avoids duplicate subsection labels).
HEADER_PATTERNS: list[tuple[str, str]] = [
    ("profile_raw", r"^\s*Profile Applicability\s*:"),
    ("description", r"^\s*Description\s*:"),
    ("rationale", r"^\s*Rationale(?:\s+Statement)?\s*:"),
    ("impact", r"^\s*Impact(?:\s+Statement)?\s*:"),
    ("audit", r"^\s*Audit(?:\s+Procedure)?\s*:"),
    ("remediation", r"^\s*Remediation(?:\s+Procedure)?\s*:"),
    ("default_value", r"^\s*Default Value\s*:"),
    ("references", r"^\s*References\s*:"),
    ("prevention", r"^\s*Prevention\s*:"),
    ("additional_information", r"^\s*Additional Information\s*:"),
]

# Strictly match benchmark control numbering at line start.
# This avoids accidental captures from reference text such as "CIS Controls v8 14.6".
REC_START = re.compile(r"(?m)^\s*([1-8])\.(\d{1,3})\s+")
PAGE_LINE = re.compile(r"^\s*Page\s+\d+\s*$", re.I)
DOT_LEADER = re.compile(r"\.{8,}.*$")  # TOC / page leaders on same line as title


def normalize_ws(text: str) -> str:
    text = text.replace("\r", "\n")
    text = re.sub(r"[ \t\u00a0]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def strip_headers_footers(page_text: str) -> str:
    lines = []
    for ln in page_text.split("\n"):
        if PAGE_LINE.match(ln.strip()):
            continue
        lines.append(ln)
    return "\n".join(lines)


def extract_pdf_text(pdf_path: Path, *, use_pdfplumber: bool = False) -> str:
    if use_pdfplumber:
        import pdfplumber

        chunks: list[str] = []
        with pdfplumber.open(pdf_path) as pdf:
            for page in pdf.pages:
                t = page.extract_text() or ""
                chunks.append(strip_headers_footers(t))
        return normalize_ws("\n".join(chunks))

    doc = fitz.open(pdf_path)
    try:
        parts = []
        for i in range(len(doc)):
            t = doc[i].get_text()
            parts.append(strip_headers_footers(t))
        return normalize_ws("\n".join(parts))
    finally:
        doc.close()


def _first_header_positions(body: str) -> dict[str, tuple[int, int]]:
    """Map logical field → (start_idx, end_of_label_idx) for first occurrence."""
    found: dict[str, tuple[int, int]] = {}
    for key, pat in HEADER_PATTERNS:
        m = re.search(pat, body, re.MULTILINE)
        if m and key not in found:
            found[key] = (m.start(), m.end())
    return found


def slice_labeled_sections(body: str) -> dict[str, str]:
    """Slice body between CIS field headers."""
    found = _first_header_positions(body)
    if not found:
        return {}
    order = sorted(found.items(), key=lambda kv: kv[1][0])
    sections: dict[str, str] = {}
    for i, (key, (_s, e)) in enumerate(order):
        content_start = e
        content_end = order[i + 1][1][0] if i + 1 < len(order) else len(body)
        sections[key] = normalize_ws(body[content_start:content_end])
    return sections


def parse_profile_level(profile_raw: str) -> str:
    t = profile_raw.lower()
    if "level 2" in t or "l2" in t.split():
        return "Level 2"
    if "level 1" in t or "l1" in t.split():
        return "Level 1"
    return "Unknown"


def parse_recommendation_block(major: str, minor: str, block: str) -> dict[str, Any] | None:
    """Parse one recommendation text block into structured record."""
    m_profile = re.search(r"^\s*Profile Applicability\s*:", block, re.MULTILINE)
    if not m_profile:
        return None

    title_region = block[: m_profile.start()]
    title = normalize_ws(title_region.replace("\n", " "))
    title = re.sub(r"^\s*\d{1,2}\.\d{1,3}\s+", "", title)
    title = DOT_LEADER.sub("", title).strip()

    body = block[m_profile.start() :]
    fields = slice_labeled_sections(body)

    description = fields.get("description", "")
    rationale = fields.get("rationale", "")
    if len(description) < 20 or len(rationale) < 20:
        return None

    profile_raw = fields.get("profile_raw", "")
    section_title, category = SECTION_META.get(
        major, (f"Section {major}", "General")
    )
    profile_level = parse_profile_level(profile_raw)
    cis_id = f"{int(major)}.{int(minor)}"

    remediation = fields.get("remediation", "")
    prevention = fields.get("prevention", "")
    if prevention and remediation:
        remediation = f"{remediation}\n\nPrevention:\n{prevention}"
    elif prevention:
        remediation = prevention

    record: dict[str, Any] = {
        "cis_id": cis_id,
        "title": title,
        "section": section_title,
        "profile_level": profile_level,
        "description": description,
        "rationale": rationale,
        "impact": fields.get("impact", ""),
        "audit": fields.get("audit", ""),
        "remediation": remediation,
        "default_value": fields.get("default_value", ""),
        "references": fields.get("references", ""),
        "category": category,
        # Short severity tag for metadata filters / dashboards
        "severity": (
            "L2"
            if profile_level == "Level 2"
            else ("L1" if profile_level == "Level 1" else "UNK")
        ),
        "cloud_provider": "GCP",
    }
    return record


def split_into_candidate_blocks(full_text: str) -> list[tuple[str, str, str]]:
    matches = list(REC_START.finditer(full_text))
    blocks: list[tuple[str, str, str]] = []
    for i, m in enumerate(matches):
        start = m.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(full_text)
        major, minor = m.group(1), m.group(2)
        blocks.append((major, minor, full_text[start:end]))
    return blocks


def ingest_cis_pdf(
    pdf_path: str | Path,
    *,
    use_pdfplumber: bool = False,
    min_block_chars: int = 400,
) -> list[dict[str, Any]]:
    """
    Parse PDF into structured recommendations.
    min_block_chars drops TOC rows and short noise segments.
    """
    path = Path(pdf_path)
    raw = extract_pdf_text(path, use_pdfplumber=use_pdfplumber)
    out: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for major, minor, block in split_into_candidate_blocks(raw):
        if len(block) < min_block_chars:
            continue
        if "Description" not in block or "Rationale" not in block:
            continue
        rec = parse_recommendation_block(major, minor, block)
        if not rec:
            continue
        # Keep first occurrence when PDF extraction yields duplicate blocks for same control.
        if rec["cis_id"] in seen_ids:
            continue
        seen_ids.add(rec["cis_id"])
        out.append(rec)
    # Stable sort by numeric cis_id
    def sort_key(r: dict[str, Any]) -> tuple[int, int]:
        a, b = r["cis_id"].split(".")
        return int(a), int(b)

    out.sort(key=sort_key)
    return out


def build_semantic_text(rec: dict[str, Any]) -> str:
    """Single embedding field: description + rationale + remediation (high signal)."""
    parts = [
        rec.get("description", ""),
        rec.get("rationale", ""),
        rec.get("remediation", ""),
    ]
    return normalize_ws("\n\n".join(p for p in parts if p))


def main() -> None:
    parser = argparse.ArgumentParser(description="Parse CIS GCP Benchmark PDF to structured JSON")
    parser.add_argument("pdf_path", type=Path, help="Path to CIS PDF")
    parser.add_argument(
        "--pdfplumber",
        action="store_true",
        help="Use pdfplumber instead of PyMuPDF for extraction",
    )
    parser.add_argument(
        "--jsonl",
        type=Path,
        default=None,
        help="Optional path to write records as JSONL (debug / audit)",
    )
    args = parser.parse_args()

    records = ingest_cis_pdf(args.pdf_path, use_pdfplumber=args.pdfplumber)
    print(f"Parsed {len(records)} CIS recommendations.")

    if args.jsonl:
        args.jsonl.parent.mkdir(parents=True, exist_ok=True)
        with args.jsonl.open("w", encoding="utf-8") as f:
            for r in records:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
        print(f"Wrote {args.jsonl}")


if __name__ == "__main__":
    main()
