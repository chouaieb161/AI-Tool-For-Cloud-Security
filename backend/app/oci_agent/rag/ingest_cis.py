"""
OCI CIS Benchmark PDF → structured recommendation records (Supabase ingestion ready)

Design:
- PyMuPDF for extraction
- Split by CIS control IDs (1.1.1 style)
- Extract structured fields:
  Description, Rationale, Impact, Audit, Remediation
- Clean boilerplate noise
- Build embedding-ready semantic text
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

import fitz  # PyMuPDF


# =========================
# SECTION MAPPING (OCI)
# =========================

SECTION_META: dict[str, tuple[str, str]] = {
    "1": ("Identity and Access Management", "IAM"),
    "2": ("Networking", "Networking"),
    "3": ("Logging and Monitoring", "Logging"),
    "4": ("Compute", "Compute"),
    "5": ("Storage", "Storage"),
    "6": ("Asset Management", "Asset"),
}


# =========================
# PDF CLEANING
# =========================

PAGE_RE = re.compile(r"^\s*Page\s+\d+\s*$", re.I)

IGNORE_PATTERNS = [
    r"detailed information pertaining",
    r"rationale statement",
    r"impact statement",
    r"audit procedure",
    r"profile applicability",
]


def clean_text(text: str) -> str:
    lines = []
    for l in text.splitlines():
        low = l.lower().strip()
        if any(re.search(p, low) for p in IGNORE_PATTERNS):
            continue
        if PAGE_RE.match(l.strip()):
            continue
        lines.append(l.strip())

    return re.sub(r"\s+", " ", " ".join(lines)).strip()


# =========================
# PDF EXTRACTION
# =========================

def extract_pdf(pdf_path: Path) -> str:
    doc = fitz.open(pdf_path)
    try:
        text = []
        for page in doc:
            text.append(page.get_text("text"))
        return "\n".join(text)
    finally:
        doc.close()


# =========================
# SPLIT INTO CONTROL BLOCKS
# =========================

CONTROL_RE = re.compile(r"(?m)^(\d+)\.(\d{1,3})\s+")


def split_blocks(text: str) -> list[tuple[str, str, str]]:
    matches = list(CONTROL_RE.finditer(text))
    blocks = []

    for i, m in enumerate(matches):
        start = m.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)

        major, minor = m.group(1), m.group(2)
        blocks.append((major, minor, text[start:end]))

    return blocks


# =========================
# FIELD EXTRACTION
# =========================

FIELD_RE = {
    "description": re.compile(r"description\s*:?", re.I),
    "rationale": re.compile(r"rationale", re.I),
    "impact": re.compile(r"impact", re.I),
    "audit": re.compile(r"audit", re.I),
    "remediation": re.compile(r"remediation", re.I),
}


def parse_block(major: str, minor: str, block: str) -> dict[str, Any] | None:
    header_match = re.match(r"(\d+\.\d+(?:\.\d+)?)\s+(.+)", block.strip())
    if not header_match:
        return None

    cis_id = header_match.group(1)
    title = header_match.group(2).strip()

    # remove header part
    body = block[header_match.end():]

    record = {
        "cis_id": cis_id,
        "title": title,
        "description": "",
        "rationale": "",
        "impact": "",
        "audit": "",
        "remediation": "",
        "category": SECTION_META.get(major, ("General", "General"))[1],
        "section": SECTION_META.get(major, ("General", "General"))[0],
        "profile_level": "Level 1",
        "severity": "Medium",
        "cloud_provider": "OCI",
    }

    current = None

    for line in body.splitlines():
        l = line.strip()
        if not l:
            continue

        # detect field switches
        for key, pattern in FIELD_RE.items():
            if pattern.search(l):
                current = key
                break
        else:
            if current:
                record[current] += " " + l

    # clean fields
    for k in ["description", "rationale", "impact", "audit", "remediation"]:
        record[k] = clean_text(record[k])

    # skip garbage blocks
    if len(record["description"]) < 20 or len(record["rationale"]) < 20:
        return None

    # severity inference
    blob = (record["title"] + record["description"]).lower()
    if any(x in blob for x in ["public", "0.0.0.0", "open", "root", "unencrypted"]):
        record["severity"] = "High"

    if any(x in blob for x in ["mfa", "password", "key", "secret"]):
        record["severity"] = "High"

    return record


# =========================
# BUILD PIPELINE
# =========================

def build_records(pdf_path: Path) -> list[dict[str, Any]]:
    raw = extract_pdf(pdf_path)
    blocks = split_blocks(raw)

    records: list[dict[str, Any]] = []
    seen = set()

    for major, minor, block in blocks:
        rec = parse_block(major, minor, block)
        if not rec:
            continue

        if rec["cis_id"] in seen:
            continue

        seen.add(rec["cis_id"])
        records.append(rec)

    return sorted(
        records,
        key=lambda r: tuple(map(int, r["cis_id"].split(".")))
    )


# =========================
# EMBEDDING TEXT
# =========================

def build_embedding_text(rec: dict[str, Any]) -> str:
    return clean_text(
        f"{rec['title']}\n"
        f"{rec['description']}\n"
        f"{rec['rationale']}\n"
        f"{rec['remediation']}"
    )


# =========================
# OPTIONAL JSONL EXPORT
# =========================

def export_jsonl(records: list[dict[str, Any]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


# =========================
# CLI
# =========================

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("pdf", type=Path)

    # optional override, but default is now fixed
    parser.add_argument(
        "--jsonl",
        type=Path,
        default=Path("cis_oci.jsonl"),
        help="Output JSONL file (default: cis_oci.jsonl)",
    )

    args = parser.parse_args()

    records = build_records(args.pdf)

    print(f"Parsed {len(records)} OCI CIS controls")

    export_jsonl(records, args.jsonl)
    print(f"Saved JSONL → {args.jsonl}")


if __name__ == "__main__":
    main()