"""OCI Agent Service — runs OCI LangGraph agent, parses findings, persists to DB.

Mirrors agent_service.py but for OCI instead of GCP.
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Callable

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models import Finding, Project, Resource, Scan, ScanResource, ScanStatus, Severity
from app.schemas.oci_scan_result import OCIFindingResult, OCIResourceResult, OCIScanResult


class AgentExecutionError(Exception):
    pass


_CIS_CATEGORY_BY_SECTION = {
    "1": "IAM",
    "2": "Networking",
    "3": "Logging",
    "4": "Compute",
    "5": "Storage",
    "6": "Database",
    "7": "Governance",
    "8": "Security",
}


def _score_from_findings(findings: list[OCIFindingResult]) -> int:
    """Score 0-100 based on findings severity (same logic as GCP)."""
    if not findings:
        return 100
    seen_pairs: set[tuple[str, str]] = set()
    total_penalty = 0
    for f in findings:
        sev_key = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
        sev_key = sev_key.upper()
        pair = (f.cis_rule_id, sev_key)
        if pair in seen_pairs:
            continue
        seen_pairs.add(pair)
        if sev_key == "CRITICAL":
            total_penalty += 15
        elif sev_key == "HIGH":
            total_penalty += 10
        elif sev_key == "MEDIUM":
            total_penalty += 5
        elif sev_key == "LOW":
            total_penalty += 2
    score = 100 - total_penalty
    return max(0, min(100, score))


def _category_from_cis_rule(cis_rule_id: str | None) -> str:
    if not cis_rule_id:
        return "Unknown"
    major = str(cis_rule_id).split(".", maxsplit=1)[0]
    return _CIS_CATEGORY_BY_SECTION.get(major, "Unknown")


def _clean_markdown_text(text: str) -> str:
    text = re.sub(r"```.*?```", "", text, flags=re.DOTALL)
    text = re.sub(r"[*_`#>]+", "", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip(" -:\n\t")


def _first_sentences(text: str, *, max_chars: int = 520, max_sentences: int = 2) -> str:
    cleaned = _clean_markdown_text(text)
    if not cleaned:
        return ""
    parts = re.split(r"(?<=[.!?])\s+", cleaned)
    out: list[str] = []
    for part in parts:
        if not part:
            continue
        candidate = " ".join(out + [part]).strip()
        if len(candidate) > max_chars and out:
            break
        out.append(part)
        if len(out) >= max_sentences:
            break
    summary = " ".join(out).strip() or cleaned
    return summary[:max_chars].rstrip()


def _findings_from_markdown(md: str) -> list[OCIFindingResult]:
    """Parse OCI agent markdown output into structured findings."""
    if not md.strip():
        return []

    findings: list[OCIFindingResult] = []
    lines = [ln.strip() for ln in md.splitlines() if ln.strip()]

    for line in lines:
        if line.startswith("{") or line.startswith("["):
            continue
        # Look for Non-Compliant pattern: "### CIS X.Y - Title"
        cis_match = re.search(r"###\s+CIS\s+(\d+\.\d+(?:\.\d+)?)", line, flags=re.IGNORECASE)
        if not cis_match:
            continue
        cis_id = cis_match.group(1)

        # Look for severity in the following lines
        sev_match = re.search(r"\b(HIGH|MEDIUM|LOW|CRITICAL)\b", md[md.index(line):md.index(line)+500], flags=re.IGNORECASE)
        severity = Severity.HIGH
        if sev_match:
            sev_text = sev_match.group(1).upper()
            if sev_text in Severity.__members__:
                severity = Severity[sev_text]

        # Extract evidence and risk from the block
        block_start = md.index(line)
        block_end = md.find("\n###", block_start + 1)
        if block_end == -1:
            block_end = len(md)
        block = md[block_start:block_end]

        # Extract evidence
        evidence_match = re.search(r"\* Evidence:\s*(.*?)(?:\n\*|\Z)", block, flags=re.DOTALL)
        evidence = evidence_match.group(1).strip() if evidence_match else ""

        # Extract risk
        risk_match = re.search(r"\* Risk:\s*(.*?)(?:\n\*|\Z)", block, flags=re.DOTALL)
        risk = risk_match.group(1).strip() if risk_match else ""

        # Extract remediation
        remediation_match = re.search(r"\* Remediation:\s*(.*?)(?:\n\*|\Z)", block, flags=re.DOTALL)
        remediation = remediation_match.group(1).strip() if remediation_match else ""

        description = f"CIS {cis_id}: {evidence}" if evidence else f"CIS {cis_id} requires attention."
        remediation_steps = remediation or f"Review CIS {cis_id} remediation guidance."

        findings.append(OCIFindingResult(
            cis_rule_id=cis_id,
            severity=severity,
            description=description,
            remediation_steps=remediation_steps,
            resource_ocid=None,
        ))

    # Deduplicate
    dedup: dict[tuple[str, Severity, str], OCIFindingResult] = {}
    for finding in findings:
        key = (finding.cis_rule_id, finding.severity, finding.description[:160])
        dedup[key] = finding
    return list(dedup.values())


def _findings_from_structured(payload: Any) -> list[OCIFindingResult]:
    """Parse structured findings from agent state."""
    if not isinstance(payload, list):
        return []
    findings: list[OCIFindingResult] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        cis_rule_id = str(item.get("cis_id", "")).strip()
        if not cis_rule_id:
            continue
        severity_raw = str(item.get("severity", "MEDIUM")).upper()
        severity = Severity[severity_raw] if severity_raw in Severity.__members__ else Severity.MEDIUM
        description = str(item.get("evidence", "")).strip() or f"CIS {cis_rule_id} requires attention."
        remediation = str(item.get("remediation", "")).strip() or "Refer to CIS remediation guidance."
        findings.append(OCIFindingResult(
            cis_rule_id=cis_rule_id,
            severity=severity,
            description=description,
            remediation_steps=remediation,
            resource_ocid=None,
        ))
    dedup: dict[tuple[str, Severity, str], OCIFindingResult] = {}
    for finding in findings:
        key = (finding.cis_rule_id, finding.severity, finding.description[:160])
        dedup[key] = finding
    return list(dedup.values())


def _resources_from_state(state: dict[str, Any]) -> list[OCIResourceResult]:
    """Extract OCI resources from agent state."""
    payload = state.get("resources_json")
    if not isinstance(payload, dict):
        return []

    resources: list[OCIResourceResult] = []
    seen: set[str] = set()

    for tool_name, tool_result in payload.items():
        if not isinstance(tool_result, dict):
            continue
        # Extract OCIDs from various fields
        for key, value in tool_result.items():
            if isinstance(value, list):
                for item in value:
                    if not isinstance(item, dict):
                        continue
                    ocid = item.get("id") or item.get("ocid")
                    if not ocid or ocid in seen:
                        continue
                    seen.add(ocid)
                    name = item.get("display_name") or item.get("name") or ocid[:20]
                    resources.append(OCIResourceResult(
                        type=key.upper() if key else "UNKNOWN",
                        name=str(name),
                        ocid=str(ocid),
                    ))

    return resources


def _result_from_state(state: dict[str, Any]) -> OCIScanResult:
    """Convert agent state dict to OCIScanResult."""
    resources = _resources_from_state(state)
    structured = state.get("structured_findings")
    findings: list[OCIFindingResult] = []

    if structured is not None:
        findings.extend(_findings_from_structured(structured))

    if not findings:
        report_md = str(state.get("report_markdown") or state.get("analysis_markdown") or "")
        findings = _findings_from_markdown(report_md)

    score = _score_from_findings(findings)

    return OCIScanResult(
        score=score,
        status=ScanStatus.COMPLETED,
        resources=resources,
        findings=findings,
    )


def _load_oci_agent_module() -> Any:
    """Dynamically load the OCI LangGraph agent module."""
    module_path = Path(__file__).resolve().parents[1] / "oci_agent" / "agent.py"
    if not module_path.exists():
        raise AgentExecutionError(f"OCI LangGraph agent not found: {module_path}")

    app_dir = Path(__file__).resolve().parents[1]
    import_paths = [
        app_dir / "oci_agent",
        app_dir / "oci_agent" / "mcp",
        app_dir / "oci_agent" / "rag",
    ]
    for p in import_paths:
        p_str = str(p)
        if p_str not in sys.path:
            sys.path.insert(0, p_str)

    spec = importlib.util.spec_from_file_location("oci_langgraph_agent", module_path)
    if spec is None or spec.loader is None:
        raise AgentExecutionError("Could not load OCI agent module.")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def run_oci_langgraph_scan() -> OCIScanResult:
    """Run a full OCI CIS scan using the LangGraph agent."""
    module = _load_oci_agent_module()
    run_oci_audit = getattr(module, "run_oci_audit", None)
    if not callable(run_oci_audit):
        raise AgentExecutionError("OCI agent does not expose callable run_oci_audit().")

    prompt = "Run a full OCI CIS audit across all sections and generate a complete report."
    report_md = run_oci_audit(prompt, stream_trace=False)

    # Try to get structured findings from the agent's state
    # The agent returns markdown, so we parse it
    state = {"report_markdown": report_md}
    return _result_from_state(state)


def run_oci_scan_with_query(query: str) -> OCIScanResult:
    """Run an OCI scan with a custom user query."""
    module = _load_oci_agent_module()
    run_oci_audit = getattr(module, "run_oci_audit", None)
    if not callable(run_oci_audit):
        raise AgentExecutionError("OCI agent does not expose callable run_oci_audit().")

    report_md = run_oci_audit(query, stream_trace=False)
    state = {"report_markdown": report_md}
    return _result_from_state(state)


def persist_oci_scan_result(
    db: Session,
    project: Project,
    result: OCIScanResult,
    trigger_type: str | None = None,
) -> int:
    """Persist OCI scan result to database."""
    resource_map: dict[str, Resource] = {}
    observed_resource_ids: set[int] = set()

    scan = Scan(
        project_id=project.id,
        score=result.score,
        status=result.status,
        trigger_type=trigger_type,
        tenant_provider_id=project.tenant_provider_id,
    )
    db.add(scan)
    db.flush()

    for resource_item in result.resources:
        existing = db.execute(
            select(Resource).where(
                Resource.project_id == project.id,
                Resource.gcp_uri == resource_item.ocid,
            )
        ).scalar_one_or_none()

        if existing:
            resource = existing
        else:
            resource = Resource(
                project_id=project.id,
                type=resource_item.type,
                name=resource_item.name,
                gcp_uri=resource_item.ocid,
            )
            db.add(resource)
            db.flush()

        resource_map[resource_item.ocid] = resource
        if resource.type != "PROJECT":
            observed_resource_ids.add(resource.id)

        scan_resource = ScanResource(
            scan_id=scan.id,
            resource_id=resource.id,
        )
        db.add(scan_resource)

    for finding_item in result.findings:
        linked_resource: Resource | None = None
        if finding_item.resource_ocid:
            linked_resource = resource_map.get(finding_item.resource_ocid)

        finding = Finding(
            scan_id=scan.id,
            resource_id=linked_resource.id if linked_resource else None,
            cis_rule_id=finding_item.cis_rule_id,
            severity=finding_item.severity,
            description=finding_item.description,
            remediation_steps=finding_item.remediation_steps,
        )
        db.add(finding)

    db.flush()
    return scan.id