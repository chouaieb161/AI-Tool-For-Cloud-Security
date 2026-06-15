from __future__ import annotations

import importlib.util
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models import Finding, Project, Resource, Scan, ScanResource, ScanStatus, Severity
from app.mcp.mcp_server import call_mcp_tool
from app.rag.retriever import format_retrieval_for_prompt, get_retriever
from app.rag.vector_store import DEFAULT_PERSIST
from app.schemas.scan_result import GCPFindingResult, GCPResourceResult, GCPScanResult


class AgentExecutionError(Exception):
    pass


_CIS_RESOURCE_TYPE_HINTS: dict[str, tuple[str, ...]] = {
    "1": ("API_KEY", "SERVICE_ACCOUNT_KEY", "SERVICE_ACCOUNT"),
    "2": ("LOG_METRIC", "LOG_SINK", "ALERT_POLICY"),
    "3": ("FIREWALL", "SUBNETWORK", "NETWORK"),
    "4": ("INSTANCE",),
    "5": ("BUCKET", "STORAGE_BUCKET"),
    "6": ("SQL_INSTANCE", "INSTANCE"),
    "7": ("DATASET",),
    "8": ("CLUSTER",),
}

_SECTION_CATEGORY = {
    "1": "IAM",
    "2": "Logging",
    "3": "Networking",
    "4": "Compute",
    "5": "Storage",
    "6": "SQL",
    "7": "BigQuery",
    "8": "Dataproc",
}

_CIS_TOOLS_IN_ORDER: list[tuple[str, str]] = [
    ("1", "get_iam_policy"),
    ("2", "get_logging_monitoring_config"),
    ("3", "get_network_config"),
    ("4", "get_compute_info"),
    ("5", "get_storage_metadata"),
    ("6", "get_cloud_sql_inventory"),
    ("7", "get_bigquery_inventory"),
    ("8", "get_dataproc_inventory"),
]


def _normalize_resource_type(asset_type: str | None) -> str:
    if not asset_type:
        return "UNKNOWN"
    raw = asset_type.split("/")[-1]
    return re.sub(r"[^A-Za-z0-9]+", "_", raw).upper() or "UNKNOWN"


def _extract_uri_and_name(item: dict[str, Any]) -> tuple[str | None, str | None]:
    raw_name = item.get("name")
    uri = raw_name or item.get("resource")
    project_id = item.get("project_id")
    if isinstance(project_id, str) and isinstance(raw_name, str) and not raw_name.startswith(("//", "projects/")):
        if "enable_flow_logs" in item:
            region = str(item.get("region") or "").rstrip("/").rsplit("/", maxsplit=1)[-1]
            if region:
                uri = f"//compute.googleapis.com/projects/{project_id}/regions/{region}/subnetworks/{raw_name}"
            else:
                uri = f"//compute.googleapis.com/projects/{project_id}/subnetworks/{raw_name}"
        elif "network_interfaces" in item:
            zone = str(item.get("zone") or "").rstrip("/").rsplit("/", maxsplit=1)[-1]
            if zone:
                uri = f"//compute.googleapis.com/projects/{project_id}/zones/{zone}/instances/{raw_name}"
            else:
                uri = f"//compute.googleapis.com/projects/{project_id}/instances/{raw_name}"
        elif item.get("network"):
            uri = f"//compute.googleapis.com/projects/{project_id}/resources/{raw_name}"
        elif item.get("dataset_id"):
            uri = f"//bigquery.googleapis.com/projects/{project_id}/datasets/{item['dataset_id']}"
        elif "versioning_enabled" in item or "has_public_principal" in item:
            uri = f"//storage.googleapis.com/projects/_/buckets/{raw_name}"
        else:
            uri = f"//cloudresourcemanager.googleapis.com/projects/{project_id}/resources/{raw_name}"
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


def _remediation_from_cis_rules(cis_id: str, cis_rules: str) -> str:
    block_match = re.search(
        rf"###\s+CIS\s+{re.escape(cis_id)}\b(?P<body>.*?)(?=\n###\s+CIS\s+|\n##\s+CIS domain hint:|\Z)",
        cis_rules,
        flags=re.DOTALL | re.IGNORECASE,
    )
    if not block_match:
        return f"Review CIS {cis_id} remediation guidance and apply the control using the matching GCP service configuration."

    block = block_match.group("body")
    remediation_match = re.search(
        r"\*\*Remediation:\*\*\s*(?P<body>.*?)(?=\n---\n|\n###\s+CIS\s+|\n##\s+CIS domain hint:|\Z)",
        block,
        flags=re.DOTALL | re.IGNORECASE,
    )
    remediation = remediation_match.group("body") if remediation_match else ""
    overview = _first_sentences(remediation)
    if overview:
        return overview
    return f"Review CIS {cis_id} remediation guidance and apply the control using the matching GCP service configuration."


def _resource_type_rank(cis_id: str, description: str, resource: GCPResourceResult) -> int:
    major = cis_id.split(".", maxsplit=1)[0]
    desc = description.lower()
    rtype = resource.type.upper()
    name = resource.name.lower()
    uri = resource.gcp_uri.lower()
    rank = 0

    if resource.name and resource.name.lower() in desc:
        rank += 80
    if resource.gcp_uri and resource.gcp_uri.lower() in desc:
        rank += 100

    if "firewall" in desc and "FIREWALL" in rtype:
        rank += 50
    if ("subnet" in desc or "flow log" in desc) and "SUBNETWORK" in rtype:
        rank += 50
    if "network" in desc and "NETWORK" in rtype:
        rank += 35
    if ("instance" in desc or "vm" in desc or "ip forwarding" in desc) and "INSTANCE" in rtype:
        rank += 50
    if ("bucket" in desc or "storage" in desc) and "BUCKET" in rtype:
        rank += 50
    if ("service account" in desc or "key" in desc) and ("SERVICE_ACCOUNT" in rtype or "KEY" in rtype):
        rank += 45

    for hint in _CIS_RESOURCE_TYPE_HINTS.get(major, ()):
        if hint in rtype:
            rank += 25
    if rtype == "PROJECT":
        rank -= 25
    if resource.name and resource.name.lower() in desc:
        rank += 5
    return rank


def _infer_resource_uri(cis_id: str, description: str, resources: list[GCPResourceResult]) -> str | None:
    candidates = [r for r in resources if r.type.upper() != "PROJECT"]
    if not candidates:
        return None
    ranked = sorted(
        ((r, _resource_type_rank(cis_id, description, r)) for r in candidates),
        key=lambda item: item[1],
        reverse=True,
    )
    best, score = ranked[0]
    if score <= 0:
        return None
    return best.gcp_uri


def _findings_from_markdown(
    md: str,
    *,
    cis_rules: str = "",
    resources: list[GCPResourceResult] | None = None,
) -> list[GCPFindingResult]:
    if not md.strip():
        return []

    resource_items = resources or []
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
        if line.startswith("{") or line.startswith("["):
            continue
        cis_matches = re.findall(r"\b([1-8]\.\d+(?:\.\d+)?)\b", line)
        if not cis_matches:
            continue
        sev_match = re.search(r"\b(CRITICAL|HIGH|MEDIUM|LOW)\b", line, flags=re.IGNORECASE)
        severity = Severity[(sev_match.group(1).upper() if sev_match else "MEDIUM")]
        for cis_id in cis_matches:
            remediation = _remediation_from_cis_rules(cis_id, cis_rules)
            resource_uri = _infer_resource_uri(cis_id, line, resource_items)
            findings.append(
                GCPFindingResult(
                    cis_rule_id=cis_id,
                    severity=severity,
                    description=line,
                    remediation_steps=remediation,
                    resource_gcp_uri=resource_uri,
                )
            )

    dedup: dict[tuple[str, Severity, str | None, str], GCPFindingResult] = {}
    for finding in findings:
        key = (
            finding.cis_rule_id,
            finding.severity,
            finding.resource_gcp_uri,
            finding.description[:160],
        )
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

    dedup: dict[tuple[str, Severity, str | None, str], GCPFindingResult] = {}
    for finding in findings:
        key = (
            finding.cis_rule_id,
            finding.severity,
            finding.resource_gcp_uri,
            finding.description[:160],
        )
        dedup[key] = finding
    return list(dedup.values())


def _is_generic_remediation(text: str) -> bool:
    lowered = text.strip().lower()
    if not lowered:
        return True
    return lowered in {
        "refer to cis remediation guidance.",
        "see cis remediation guidance in the generated report.",
    }


def _enrich_findings_with_context(
    findings: list[GCPFindingResult],
    *,
    cis_rules: str,
    resources: list[GCPResourceResult],
) -> list[GCPFindingResult]:
    enriched: list[GCPFindingResult] = []
    known_uris = {r.gcp_uri for r in resources}
    for finding in findings:
        remediation = finding.remediation_steps
        if _is_generic_remediation(remediation):
            remediation = _remediation_from_cis_rules(finding.cis_rule_id, cis_rules)

        resource_uri = finding.resource_gcp_uri
        if resource_uri and resource_uri not in known_uris:
            resource_uri = None

        enriched.append(
            GCPFindingResult(
                cis_rule_id=finding.cis_rule_id,
                severity=finding.severity,
                description=finding.description,
                remediation_steps=remediation,
                resource_gcp_uri=resource_uri,
            )
        )
    return enriched


def _deterministic_findings_from_state(
    state: dict[str, Any],
    *,
    cis_rules: str,
) -> list[GCPFindingResult]:
    payload = state.get("resources_json")
    if not isinstance(payload, dict):
        return []

    findings: list[GCPFindingResult] = []
    network = payload.get("get_network_config")
    if isinstance(network, dict):
        for row in network.get("subnetwork_flow_logs") or []:
            if not isinstance(row, dict) or row.get("enable_flow_logs") is not False:
                continue
            project_id = str(row.get("project_id") or "")
            name = str(row.get("name") or "unknown-subnet")
            region = str(row.get("region") or "").rstrip("/").rsplit("/", maxsplit=1)[-1]
            uri = (
                f"//compute.googleapis.com/projects/{project_id}/regions/{region}/subnetworks/{name}"
                if project_id and region
                else None
            )
            findings.append(
                GCPFindingResult(
                    cis_rule_id="3.8",
                    severity=Severity.MEDIUM,
                    description=(
                        f"VPC Flow Logs are disabled for subnetwork `{name}`"
                        + (f" in project `{project_id}`" if project_id else "")
                        + (f" region `{region}`" if region else "")
                        + ". Evidence: `enable_flow_logs=false` from Compute Subnetworks aggregated_list."
                    ),
                    remediation_steps=_remediation_from_cis_rules(
                        "3.8",
                        cis_rules,
                    ),
                    resource_gcp_uri=uri,
                )
            )

    iam = payload.get("get_iam_policy")
    if isinstance(iam, dict):
        for row in iam.get("service_account_keys") or []:
            if not isinstance(row, dict):
                continue
            name = str(row.get("name") or row.get("resource") or "unknown-key")
            project_id = str(row.get("project_id") or "")
            uri = name if name.startswith("//") else None
            findings.append(
                GCPFindingResult(
                    cis_rule_id="1.7",
                    severity=Severity.HIGH,
                    description=(
                        f"Service account key `{name}` exists and may be in use."
                        + (f" Project `{project_id}`." if project_id else "")
                    ),
                    remediation_steps=_remediation_from_cis_rules("1.7", cis_rules),
                    resource_gcp_uri=uri,
                )
            )

    storage = payload.get("get_storage_metadata")
    if isinstance(storage, dict):
        for row in storage.get("buckets") or []:
            if not isinstance(row, dict) or not row.get("has_public_principal"):
                continue
            name = str(row.get("name") or "unknown-bucket")
            uri = f"//storage.googleapis.com/projects/_/buckets/{name}"
            findings.append(
                GCPFindingResult(
                    cis_rule_id="5.1",
                    severity=Severity.HIGH,
                    description=(
                        f"Cloud Storage bucket `{name}` has public IAM principals `allUsers` or `allAuthenticatedUsers`."
                    ),
                    remediation_steps=_remediation_from_cis_rules("5.1", cis_rules),
                    resource_gcp_uri=uri,
                )
            )

    compute = payload.get("get_compute_info")
    if isinstance(compute, dict):
        for row in compute.get("instances") or []:
            if not isinstance(row, dict):
                continue
            name = str(row.get("name") or "unknown-instance")
            project_id = str(row.get("project_id") or "")
            zone = str(row.get("zone") or "").rstrip("/").rsplit("/", maxsplit=1)[-1]
            uri = (
                f"//compute.googleapis.com/projects/{project_id}/zones/{zone}/instances/{name}"
                if project_id and zone
                else None
            )
            nics = row.get("network_interfaces") or []
            has_external_ip = any(
                isinstance(nic, dict) and bool(nic.get("access_configs"))
                for nic in nics
            )
            if has_external_ip:
                findings.append(
                    GCPFindingResult(
                        cis_rule_id="4.6",
                        severity=Severity.HIGH,
                        description=(
                            f"Compute instance `{name}`"
                            + (f" in project `{project_id}`" if project_id else "")
                            + " has an external IP access config."
                        ),
                        remediation_steps=_remediation_from_cis_rules("4.6", cis_rules),
                        resource_gcp_uri=uri,
                    )
                )
            if row.get("can_ip_forward"):
                findings.append(
                    GCPFindingResult(
                        cis_rule_id="4.7",
                        severity=Severity.MEDIUM,
                        description=(
                            f"Compute instance `{name}`"
                            + (f" in project `{project_id}`" if project_id else "")
                            + " has IP forwarding enabled."
                        ),
                        remediation_steps=_remediation_from_cis_rules("4.7", cis_rules),
                        resource_gcp_uri=uri,
                    )
                )
            shielded = row.get("shielded_instance_config") or {}
            if isinstance(shielded, dict):
                shielded_ok = all(
                    shielded.get(key) is True
                    for key in (
                        "enable_secure_boot",
                        "enable_vtpm",
                        "enable_integrity_monitoring",
                    )
                )
                if not shielded_ok:
                    findings.append(
                        GCPFindingResult(
                            cis_rule_id="4.8",
                            severity=Severity.MEDIUM,
                            description=(
                                f"Compute instance `{name}` is not using full Shielded VM hardening."
                                + (f" Project `{project_id}`." if project_id else "")
                            ),
                            remediation_steps=_remediation_from_cis_rules("4.8", cis_rules),
                            resource_gcp_uri=uri,
                        )
                    )

    bigquery = payload.get("get_bigquery_inventory")
    if isinstance(bigquery, dict):
        for row in bigquery.get("datasets") or []:
            if not isinstance(row, dict) or not row.get("has_public_access"):
                continue
            dataset_id = str(row.get("dataset_id") or "unknown-dataset")
            project_id = str(row.get("project_id") or "")
            uri = (
                f"//bigquery.googleapis.com/projects/{project_id}/datasets/{dataset_id}"
                if project_id and dataset_id
                else None
            )
            findings.append(
                GCPFindingResult(
                    cis_rule_id="7.1",
                    severity=Severity.HIGH,
                    description=(
                        f"BigQuery dataset `{dataset_id}` has public access entries."
                        + (f" Project `{project_id}`." if project_id else "")
                    ),
                    remediation_steps=_remediation_from_cis_rules("7.1", cis_rules),
                    resource_gcp_uri=uri,
                )
            )

    dedup: dict[tuple[str, Severity, str | None, str], GCPFindingResult] = {}
    for finding in findings:
        key = (
            finding.cis_rule_id,
            finding.severity,
            finding.resource_gcp_uri,
            finding.description[:160],
        )
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


def _local_cis_rules_for_sections(sections: list[str], query: str) -> str:
    chunks: list[str] = []
    try:
        retriever = get_retriever(_resolve_cis_persist_path())
        for sec in sections:
            category = _SECTION_CATEGORY.get(sec)
            rows = retriever.retrieve(query, top_k=3, category=category)
            chunks.append(
                f"## CIS domain hint: section {sec} ({category or 'general'})\n"
                + format_retrieval_for_prompt(rows)
            )
    except Exception:
        return ""
    return "\n\n".join(chunks)


def _resolve_cis_persist_path() -> str:
    raw = os.environ.get("CHROMA_CIS_PATH", DEFAULT_PERSIST)
    path = Path(raw).expanduser()
    if path.is_absolute():
        return str(path)
    repo_root = Path(__file__).resolve().parents[3]
    backend_root = Path(__file__).resolve().parents[2]
    for base in (backend_root, repo_root):
        candidate = (base / path).resolve()
        if candidate.exists() and (candidate / "chroma.sqlite3").exists():
            return str(candidate)
    return str((repo_root / path).resolve())


def _run_mcp_only_scan(project: Project, *, query: str | None = None) -> GCPScanResult:
    """
    Fallback scan that uses live MCP inventory and deterministic findings only.
    This keeps /scan useful when Groq is rate-limited or unavailable.
    """
    q = (query or "").lower()
    if q:
        selected: list[tuple[str, str]] = []
        for sec, tool in _CIS_TOOLS_IN_ORDER:
            category = _SECTION_CATEGORY.get(sec, "").lower()
            if category and category in q:
                selected.append((sec, tool))
        if not selected:
            if any(k in q for k in ("network", "vpc", "firewall", "subnet", "flow log")):
                selected.append(("3", "get_network_config"))
            if any(k in q for k in ("iam", "identity", "service account", "key")):
                selected.append(("1", "get_iam_policy"))
            if any(k in q for k in ("storage", "bucket", "gcs")):
                selected.append(("5", "get_storage_metadata"))
            if any(k in q for k in ("compute", "vm", "instance")):
                selected.append(("4", "get_compute_info"))
        if not selected:
            selected = _CIS_TOOLS_IN_ORDER
    else:
        selected = _CIS_TOOLS_IN_ORDER

    resources_json: dict[str, Any] = {}
    for _sec, tool_name in selected:
        raw = call_mcp_tool(tool_name, {})
        try:
            resources_json[tool_name] = json.loads(raw)
        except json.JSONDecodeError:
            resources_json[tool_name] = {"parse_error": True, "raw": raw}

    sections = [sec for sec, _tool in selected]
    cis_rules = _local_cis_rules_for_sections(
        sections,
        query or "GCP CIS security controls for live inventory findings",
    )
    return _result_from_state(
        {
            "resources_json": resources_json,
            "cis_rules": cis_rules,
            "structured_findings": [],
            "tools_used": [tool for _sec, tool in selected],
            "sections": sections,
        },
        project,
    )


def _should_use_mcp_fallback(exc: BaseException) -> bool:
    text = f"{type(exc).__name__}: {exc}".lower()
    return any(
        marker in text
        for marker in (
            "ratelimit",
            "rate limit",
            "quota",
            "groq",
            "tokens per day",
            "tpd",
            "timeout",
        )
    )


def _result_from_state(state: dict[str, Any], project: Project) -> GCPScanResult:
    resources = _resources_from_state(state, project)
    cis_rules = str(state.get("cis_rules") or "")
    structured = state.get("structured_findings")
    findings: list[GCPFindingResult] = _deterministic_findings_from_state(
        state,
        cis_rules=cis_rules,
    )
    if structured is not None:
        findings.extend(_findings_from_structured(structured))
    if not findings:
        report_md = str(state.get("report_markdown") or state.get("analysis_markdown") or "")
        findings = _findings_from_markdown(report_md, cis_rules=cis_rules, resources=resources)
    findings = _enrich_findings_with_context(findings, cis_rules=cis_rules, resources=resources)
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
        "Generate a full audit report. Run a complete GCP CIS security scan across all 8 major CIS sections "
        "(1 IAM, 2 Logging, 3 Networking, 4 Compute, 5 Storage, 6 Cloud SQL, 7 BigQuery, 8 Dataproc). "
        "Use the configured GCP audit scope and MCP live inventory. "
        "Return STRICT JSON only (no markdown) in this exact shape: "
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

    try:
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
    except Exception as exc:
        if _should_use_mcp_fallback(exc):
            return _run_mcp_only_scan(project)
        raise


def run_langgraph_scan_with_query(project: Project, query: str) -> GCPScanResult:
    if settings.GCP_AGENT_RUNNER == "mock":
        return _mock_scan_result(project)

    module = _load_gcp_agent_module()
    prompt = _build_freeform_prompt(project, query)

    try:
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
    except Exception as exc:
        if _should_use_mcp_fallback(exc):
            return _run_mcp_only_scan(project, query=query)
        raise


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
    observed_resource_ids: set[int] = set()
    tx = db.begin_nested() if db.in_transaction() else db.begin()
    with tx:
        scan = Scan(
            project_id=project.id,
            score=result.score,
            status=result.status,
        )
        db.add(scan)
        db.flush()

        project_resource = _upsert_resource(
            db,
            project.id,
            GCPResourceResult(
                type="PROJECT",
                name=project.gcp_project_id,
                gcp_uri=f"//cloudresourcemanager.googleapis.com/projects/{project.gcp_project_id}",
            ),
        )
        resource_map[project_resource.gcp_uri] = project_resource

        for resource_item in result.resources:
            resource = _upsert_resource(db, project.id, resource_item)
            resource_map[resource.gcp_uri] = resource
            if resource.type != "PROJECT":
                observed_resource_ids.add(resource.id)

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
                    if linked_resource.type != "PROJECT":
                        observed_resource_ids.add(linked_resource.id)
            else:
                linked_resource = project_resource

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

        for resource_id in sorted(observed_resource_ids):
            db.add(ScanResource(scan_id=scan.id, resource_id=resource_id))

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
