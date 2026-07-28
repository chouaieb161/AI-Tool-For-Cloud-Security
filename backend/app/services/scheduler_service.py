"""Scheduler service for autonomous cloud security scans.

Queries enabled TenantProviders with stored credentials, runs the
appropriate agent (GCP/OCI) with DB-based credentials, and persists results.
Can be triggered via API endpoint or CLI.
"""
from __future__ import annotations

import json
import logging
from typing import Any

from sqlalchemy.orm import Session

from app.db.models import Organization, Project, Scan, ScanStatus, TenantProvider
from app.services.tenant_service import get_or_create_project_for_provider

logger = logging.getLogger(__name__)


# ─── GCP helpers ────────────────────────────────────────────────────────


def _build_gcp_mcp_call(credentials_info: dict) -> tuple[Any, dict[str, dict[str, Any]]]:
    """Create a custom mcp_call function and tool catalog from GCP credentials dict."""
    from app.mcp.mcp_server import GCPClient, get_tool_catalog

    client = GCPClient(credentials_info=credentials_info)
    tool_catalog = get_tool_catalog()

    def _call(name: str, arguments: dict[str, Any] | None = None) -> str:
        from app.mcp.mcp_server import call_mcp_tool
        return call_mcp_tool(name, arguments)

    return _call, tool_catalog


def _run_gcp_scan(project: Project, credentials_info: dict) -> dict[str, Any]:
    """Run GCP LangGraph scan with custom credentials."""
    from app.gcp_agent.agent import run_audit
    from app.services.agent_service import _result_from_state

    prompt = (
        f"Run a full GCP CIS audit for project {project.gcp_project_id} "
        "across all sections and generate a complete report."
    )

    mcp_call, tool_catalog = _build_gcp_mcp_call(credentials_info)
    report_md = run_audit(prompt, mcp_call=mcp_call, mcp_tool_catalog=tool_catalog, stream_trace=False)

    state = {"report_markdown": report_md}
    result = _result_from_state(state, project)
    return result.model_dump(mode="json")


def _persist_gcp_scan(db: Session, project: Project, result_dict: dict, trigger_type: str) -> int:
    """Persist GCP scan result to database."""
    from app.schemas.scan_result import GCPScanResult
    from app.services.agent_service import persist_scan_result

    result = GCPScanResult.model_validate(result_dict)
    return persist_scan_result(db, project, result, trigger_type=trigger_type)


# ─── OCI helpers ────────────────────────────────────────────────────────


def _build_oci_mcp_call(config_content: str, key_content: str | None) -> tuple[Any, dict[str, dict[str, Any]]]:
    """Create a custom mcp_call function and tool catalog from OCI config content."""
    from app.oci_agent.mcp.oci_mcp_server import (
        OCIClient,
        _OCI_TOOLS,
        _reset_oci_client,
    )

    _reset_oci_client()
    client = OCIClient(config_content=config_content, key_content=key_content)

    def _call(name: str, arguments: dict[str, Any] | None = None) -> str:
        fn = _OCI_TOOLS.get(name)
        if fn is None:
            return json.dumps({"tool_error": True, "error": f"Unknown OCI tool: {name}"})
        try:
            raw = fn(**(arguments or {}))
            return raw if isinstance(raw, str) else json.dumps(raw)
        except Exception as exc:
            return json.dumps({"tool_error": True, "error": str(exc)})

    # Build a minimal tool catalog from _OCI_TOOLS keys
    tool_catalog: dict[str, dict[str, Any]] = {
        name: {"name": name, "description": f"OCI {name.replace('get_oci_', '').replace('_', ' ').title()} tool"}
        for name in _OCI_TOOLS
    }

    return _call, tool_catalog


def _run_oci_scan(project: Project, config_content: str, private_key: str | None) -> dict[str, Any]:
    """Run OCI LangGraph scan with custom credentials."""
    from app.oci_agent.agent import run_oci_audit
    from app.services.oci_agent_service import _result_from_state

    prompt = "Run a full OCI CIS audit across all sections and generate a complete report."
    mcp_call, tool_catalog = _build_oci_mcp_call(config_content, private_key)
    report_md = run_oci_audit(prompt, mcp_call=mcp_call, mcp_tool_catalog=tool_catalog, stream_trace=False)

    state = {"report_markdown": report_md}
    result = _result_from_state(state)
    return result.model_dump(mode="json")


def _persist_oci_scan(db: Session, project: Project, result_dict: dict, trigger_type: str) -> int:
    """Persist OCI scan result to database."""
    from app.schemas.oci_scan_result import OCIScanResult
    from app.services.oci_agent_service import persist_oci_scan_result

    result = OCIScanResult.model_validate(result_dict)
    return persist_oci_scan_result(db, project, result, trigger_type=trigger_type)


# ─── Main scheduler ─────────────────────────────────────────────────────


def run_scheduled_scans(
    db: Session,
    *,
    provider_id: int | None = None,
    trigger_type: str = "scheduled",
) -> list[int]:
    """Run scans for all enabled TenantProviders with stored credentials.

    Args:
        db: Database session.
        provider_id: Optional specific provider ID to scan (scan all if None).
        trigger_type: Scan trigger type label.

    Returns:
        List of scan IDs created.
    """
    query = db.query(TenantProvider).filter(TenantProvider.enabled.is_(True))
    if provider_id is not None:
        query = query.filter(TenantProvider.id == provider_id)

    providers = query.all()
    if not providers:
        logger.info("No enabled tenant providers found to scan.")
        return []

    scan_ids: list[int] = []
    for tp in providers:
        config = tp.config or {}
        organisation = db.query(Organization).filter(Organization.id == tp.organisation_id).first()
        if organisation is None:
            logger.warning("Organisation %d not found for provider %d, skipping", tp.organisation_id, tp.id)
            continue
        project = get_or_create_project_for_provider(db, tp, organisation)
        if project is None:
            logger.warning("Could not get or create project for provider %s (id=%d)", tp.provider_type, tp.id)
            continue

        try:
            if tp.provider_type == "GCP":
                credentials_json = config.get("credentials_json")
                if not credentials_json:
                    logger.warning("GCP provider %d has no credentials_json in config, skipping", tp.id)
                    continue
                credentials_info = json.loads(credentials_json)
                result_dict = _run_gcp_scan(project, credentials_info)
                scan_id = _persist_gcp_scan(db, project, result_dict, trigger_type)

            elif tp.provider_type == "OCI":
                config_content = config.get("config_content")
                if not config_content:
                    logger.warning("OCI provider %d has no config_content in config, skipping", tp.id)
                    continue
                private_key = config.get("private_key")
                result_dict = _run_oci_scan(project, config_content, private_key)
                scan_id = _persist_oci_scan(db, project, result_dict, trigger_type)

            else:
                logger.warning("Unsupported provider type: %s (id=%d)", tp.provider_type, tp.id)
                continue

            db.commit()
            scan_ids.append(scan_id)
            logger.info("Scan %d completed for provider %s (id=%d)", scan_id, tp.provider_type, tp.id)

        except Exception as exc:
            db.rollback()
            logger.exception("Scan failed for provider %s (id=%d): %s", tp.provider_type, tp.id, exc)
            # Record a failed scan
            failed_scan = Scan(
                project_id=project.id,
                score=0,
                status=ScanStatus.FAILED,
                trigger_type=trigger_type,
                tenant_provider_id=tp.id,
            )
            db.add(failed_scan)
            db.commit()
            scan_ids.append(failed_scan.id)

    return scan_ids
