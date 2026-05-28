from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any, Callable

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models import Finding, Project, Resource, Scan, ScanStatus, Severity
from app.schemas.scan_result import GCPFindingResult, GCPResourceResult, GCPScanResult


class AgentExecutionError(Exception):
    pass


def _normalize_resource_type(asset_type: str | None) -> str:
    if not asset_type:
        return "UNKNOWN"
    raw = asset_type.split("/")[-1]
    return re.sub(r"[^A-Za-z0-9]+", "_", raw).upper() or "UNKNOWN"


def _extract_uri_and_name(item: dict[str, Any]) -> tuple[str | None, str | None]:
    uri = item.get("name") or item.get("resource")
    if not isinstance(uri, str):
        return None, None
    leaf = uri.rsplit("/", maxsplit=1)[-1].strip() or uri
    display = item.get("displayName")
    if isinstance(display, str) and display.strip():
        return uri, display.strip()
    return uri, leaf


def _resources_from_state(state: dict[str, Any], project: Project) -> list[GCPResourceResult]:
    payload = state.get("resources_json")
    if not isinstance(payload, dict):
        return [
            GCPResourceResult(
                type="PROJECT",
                name=project.gcp_project_id,
                gcp_uri=f"//cloudresourcemanager.googleapis.com/projects/{project.gcp_project_id}",
            )
        ]

    seen: set[str] = set()
    out: list[GCPResourceResult] = []
    for _tool_name, tool_result in payload.items():
        if not isinstance(tool_result, dict):
            continue
        for _, value in tool_result.items():
            if not isinstance(value, list):
                continue
            for item in value:
                if not isinstance(item, dict):
                    continue
                uri, name = _extract_uri_and_name(item)
                if not uri or uri in seen:
                    continue
                seen.add(uri)
                out.append(
                    GCPResourceResult(
                        type=_normalize_resource_type(
                            item.get("assetType")
                            if isinstance(item.get("assetType"), str)
                            else item.get("type")
                            if isinstance(item.get("type"), str)
                            else None
                        ),
                        name=name or f"resource-{len(out)+1}",
                        gcp_uri=uri,
                    )
                )

    if out:
        return out
    return [
        GCPResourceResult(
            type="PROJECT",
            name=project.gcp_project_id,
            gcp_uri=f"//cloudresourcemanager.googleapis.com/projects/{project.gcp_project_id}",
        )
    ]


def _findings_from_markdown(md: str) -> list[GCPFindingResult]:
    if not md.strip():
        return []

    lines = [ln.strip() for ln in md.splitlines() if ln.strip()]
    section_lines: list[str] = []
    in_section = False
    for line in lines:
        if re.match(r"^##\s+non-compliant findings\b", line, flags=re.IGNORECASE):
            in_section = True
            continue
        if in_section and re.match(r"^##\s+", line):
            break
        if in_section:
            section_lines.append(line)

    scan_lines = section_lines if section_lines else lines
    findings: list[GCPFindingResult] = []
    for line in scan_lines:
        cis_matches = re.findall(r"\b([1-8]\.\d+(?:\.\d+)?)\b", line)
        if not cis_matches:
            continue
        sev_match = re.search(r"\b(CRITICAL|HIGH|MEDIUM|LOW)\b", line, flags=re.IGNORECASE)
        severity = Severity[(sev_match.group(1).upper() if sev_match else "MEDIUM")]
        for cis_id in cis_matches:
            findings.append(
                GCPFindingResult(
                    cis_rule_id=cis_id,
                    severity=severity,
                    description=line,
                    remediation_steps="See CIS remediation guidance in the generated report.",
                    resource_gcp_uri=None,
                )
            )

    dedup: dict[tuple[str, Severity], GCPFindingResult] = {}
    for finding in findings:
        key = (finding.cis_rule_id, finding.severity)
        dedup[key] = finding
    return list(dedup.values())


def _findings_from_structured(payload: Any) -> list[GCPFindingResult]:
    if not isinstance(payload, list):
        return []
    findings: list[GCPFindingResult] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        cis_rule_id = str(item.get("cis_rule_id", "")).strip()
        if not cis_rule_id:
            continue
        severity_raw = str(item.get("severity", "MEDIUM")).upper()
        severity = Severity[severity_raw] if severity_raw in Severity.__members__ else Severity.MEDIUM
        description = str(item.get("description", "")).strip()
        remediation = str(item.get("remediation_steps", "")).strip()
        resource_uri = item.get("resource_gcp_uri")
        resource_gcp_uri = str(resource_uri) if isinstance(resource_uri, str) and resource_uri.strip() else None
        findings.append(
            GCPFindingResult(
                cis_rule_id=cis_rule_id,
                severity=severity,
                description=description or f"CIS {cis_rule_id} requires attention.",
                remediation_steps=remediation or "Refer to CIS remediation guidance.",
                resource_gcp_uri=resource_gcp_uri,
            )
        )

    dedup: dict[tuple[str, Severity], GCPFindingResult] = {}
    for finding in findings:
        key = (finding.cis_rule_id, finding.severity)
        dedup[key] = finding
    return list(dedup.values())


def _score_from_findings(findings: list[GCPFindingResult]) -> int:
    penalty = 0
    for f in findings:
        if f.severity == Severity.CRITICAL:
            penalty += 15
        elif f.severity == Severity.HIGH:
            penalty += 10
        elif f.severity == Severity.MEDIUM:
            penalty += 5
        else:
            penalty += 2
    return max(0, min(100, 100 - penalty))


def _result_from_state(state: dict[str, Any], project: Project) -> GCPScanResult:
    resources = _resources_from_state(state, project)
    structured = state.get("structured_findings")
    if structured is not None:
        findings = _findings_from_structured(structured)
    else:
        report_md = str(state.get("report_markdown") or state.get("analysis_markdown") or "")
        findings = _findings_from_markdown(report_md)
    score = _score_from_findings(findings)
    return GCPScanResult(
        score=score,
        status=ScanStatus.COMPLETED,
        resources=resources,
        findings=findings,
    )


def _extract_json_object(text: str) -> dict[str, Any] | None:
    text = text.strip()
    if not text:
        return None
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass

    fenced = re.search(r"```json\s*(\{.*?\})\s*```", text, flags=re.DOTALL)
    if fenced:
        try:
            parsed = json.loads(fenced.group(1))
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass

    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        try:
            parsed = json.loads(text[start : end + 1])
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            return None
    return None


def _load_run_audit_callable() -> Callable[[str], str]:
    module_path = Path(__file__).resolve().parents[1] / "gcp-agent" / "agent.py"
    if not module_path.exists():
        raise AgentExecutionError(f"GCP LangGraph agent not found: {module_path}")

    spec = importlib.util.spec_from_file_location("gcp_langgraph_agent", module_path)
    if spec is None or spec.loader is None:
        raise AgentExecutionError("Could not load GCP agent module.")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    run_audit = getattr(module, "run_audit", None)
    if not callable(run_audit):
        raise AgentExecutionError("GCP agent does not expose callable run_audit(prompt).")
    return run_audit


def _load_gcp_agent_module() -> Any:
    module_path = Path(__file__).resolve().parents[1] / "gcp-agent" / "agent.py"
    if not module_path.exists():
        raise AgentExecutionError(f"GCP LangGraph agent not found: {module_path}")

    app_dir = Path(__file__).resolve().parents[1]
    import_paths = [
        app_dir / "gcp-agent",
        app_dir / "mcp",
        app_dir / "rag",
    ]
    for p in import_paths:
        p_str = str(p)
        if p_str not in sys.path:
            sys.path.insert(0, p_str)

    spec = importlib.util.spec_from_file_location("gcp_langgraph_agent", module_path)
    if spec is None or spec.loader is None:
        raise AgentExecutionError("Could not load GCP agent module.")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _build_langgraph_prompt(project: Project) -> str:
    return (
        "Generate an audit report. Run a GCP CIS security scan and return STRICT JSON only (no markdown) in this exact shape: "
        '{"score": <0-100 int>, "status": "COMPLETED", '
        '"resources": [{"type": "COMPUTE_INSTANCE", "name": "...", "gcp_uri": "..."}], '
        '"findings": [{"cis_rule_id": "1.1", "severity": "HIGH", '
        '"description": "...", "remediation_steps": "...", "resource_gcp_uri": "..."}]}. '
        f"Target project: {project.gcp_project_id}."
    )


def _build_freeform_prompt(project: Project, query: str) -> str:
    q = query.strip()
    base = f"Target project: {project.gcp_project_id}."
    if not q:
        return f"Generate an audit report. Run a GCP CIS security scan. {base}"
    return f"Generate an audit report. {q}\n\n{base}"


def _mock_scan_result(project: Project) -> GCPScanResult:
    resources = [
        GCPResourceResult(
            type="COMPUTE_INSTANCE",
            name="vm-prod-1",
            gcp_uri=f"//compute.googleapis.com/projects/{project.gcp_project_id}/zones/us-central1-a/instances/vm-prod-1",
        ),
        GCPResourceResult(
            type="STORAGE_BUCKET",
            name="public-assets-bucket",
            gcp_uri=f"//storage.googleapis.com/projects/_/buckets/public-assets-bucket-{project.id}",
        ),
    ]
    findings = [
        GCPFindingResult(
            cis_rule_id="4.1",
            severity=Severity.HIGH,
            description="Compute instance has an external IP address.",
            remediation_steps="Remove external IP and use IAP or bastion host.",
            resource_gcp_uri=resources[0].gcp_uri,
        ),
        GCPFindingResult(
            cis_rule_id="5.1",
            severity=Severity.CRITICAL,
            description="Bucket allows public IAM access.",
            remediation_steps="Remove allUsers/allAuthenticatedUsers from bucket IAM.",
            resource_gcp_uri=resources[1].gcp_uri,
        ),
    ]
    return GCPScanResult(score=58, status=ScanStatus.COMPLETED, resources=resources, findings=findings)


def run_langgraph_scan(project: Project) -> GCPScanResult:
    if settings.GCP_AGENT_RUNNER == "mock":
        return _mock_scan_result(project)

    module = _load_gcp_agent_module()
    prompt = _build_langgraph_prompt(project)

    run_audit_state = getattr(module, "run_audit_state", None)
    if callable(run_audit_state):
        state = run_audit_state(prompt)
        if isinstance(state, dict):
            return _result_from_state(state, project)

    run_audit = getattr(module, "run_audit", None)
    if not callable(run_audit):
        raise AgentExecutionError("GCP agent does not expose callable run_audit(prompt).")

    raw = run_audit(prompt)
    payload = _extract_json_object(raw)
    if payload is not None:
        return GCPScanResult.model_validate(payload)

    # Fallback for markdown-only outputs.
    fallback_state = {"report_markdown": raw}
    return _result_from_state(fallback_state, project)


def run_langgraph_scan_with_query(project: Project, query: str) -> GCPScanResult:
    if settings.GCP_AGENT_RUNNER == "mock":
        return _mock_scan_result(project)

    module = _load_gcp_agent_module()
    prompt = _build_freeform_prompt(project, query)

    run_audit_state = getattr(module, "run_audit_state", None)
    if callable(run_audit_state):
        state = run_audit_state(prompt)
        if isinstance(state, dict):
            return _result_from_state(state, project)

    run_audit = getattr(module, "run_audit", None)
    if not callable(run_audit):
        raise AgentExecutionError("GCP agent does not expose callable run_audit(prompt).")

    raw = run_audit(prompt)
    payload = _extract_json_object(raw)
    if payload is not None:
        return GCPScanResult.model_validate(payload)

    fallback_state = {"report_markdown": raw}
    return _result_from_state(fallback_state, project)


def _upsert_resource(db: Session, project_id: int, item: GCPResourceResult) -> Resource:
    existing = db.execute(
        select(Resource).where(
            Resource.project_id == project_id,
            Resource.gcp_uri == item.gcp_uri,
        )
    ).scalar_one_or_none()

    if existing:
        existing.type = item.type
        existing.name = item.name
        return existing

    resource = Resource(
        project_id=project_id,
        type=item.type,
        name=item.name,
        gcp_uri=item.gcp_uri,
    )
    db.add(resource)
    db.flush()
    return resource


def persist_scan_result(db: Session, project: Project, result: GCPScanResult) -> int:
    resource_map: dict[str, Resource] = {}
    tx = db.begin_nested() if db.in_transaction() else db.begin()
    with tx:
        scan = Scan(
            project_id=project.id,
            score=result.score,
            status=result.status,
        )
        db.add(scan)
        db.flush()

        for resource_item in result.resources:
            resource = _upsert_resource(db, project.id, resource_item)
            resource_map[resource.gcp_uri] = resource

        for finding_item in result.findings:
            linked_resource: Resource | None = None
            if finding_item.resource_gcp_uri:
                linked_resource = resource_map.get(finding_item.resource_gcp_uri)
                if linked_resource is None:
                    ghost_name = finding_item.resource_gcp_uri.rsplit("/", maxsplit=1)[-1] or "unknown"
                    ghost = GCPResourceResult(
                        type="UNKNOWN",
                        name=ghost_name,
                        gcp_uri=finding_item.resource_gcp_uri,
                    )
                    linked_resource = _upsert_resource(db, project.id, ghost)
                    resource_map[linked_resource.gcp_uri] = linked_resource

            db.add(
                Finding(
                    scan_id=scan.id,
                    resource_id=linked_resource.id if linked_resource else None,
                    cis_rule_id=finding_item.cis_rule_id,
                    severity=finding_item.severity,
                    description=finding_item.description,
                    remediation_steps=finding_item.remediation_steps,
                )
            )

    return scan.id


def run_scan_for_project(db: Session, project: Project) -> int:
    try:
        result = run_langgraph_scan(project)
        scan_id = persist_scan_result(db, project, result)
        db.commit()
        return scan_id
    except Exception as exc:
        db.rollback()
        failed_scan = Scan(
            project_id=project.id,
            score=0,
            status=ScanStatus.FAILED,
        )
        db.add(failed_scan)
        db.commit()
        raise AgentExecutionError(str(exc)) from exc


def run_scan_for_project_with_query(db: Session, project: Project, query: str) -> int:
    try:
        result = run_langgraph_scan_with_query(project, query)
        scan_id = persist_scan_result(db, project, result)
        db.commit()
        return scan_id
    except Exception as exc:
        db.rollback()
        failed_scan = Scan(
            project_id=project.id,
            score=0,
            status=ScanStatus.FAILED,
        )
        db.add(failed_scan)
        db.commit()
        raise AgentExecutionError(str(exc)) from exc
