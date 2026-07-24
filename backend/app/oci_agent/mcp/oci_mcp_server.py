"""Read-only OCI security MCP server aligned with CIS OCI Foundations Benchmark.

Implements inventory tools for all major CIS sections using the OCI Python SDK.
All operations are strictly read-only (list/get). No write/patch/delete.

Tools:
  - get_oci_identity_inventory   (CIS 1: IAM, users, groups, policies, MFA, API keys)
  - get_oci_network_inventory    (CIS 2: VCNs, subnets, security lists, gateways)
  - get_oci_logging_inventory    (CIS 3: logs, log groups, alarms, events)
  - get_oci_compute_inventory    (CIS 4: instances, boot volumes, metadata)
  - get_oci_storage_inventory    (CIS 5: buckets, object visibility)
  - get_oci_database_inventory   (CIS 6: DB systems, autonomous DBs)
  - get_oci_governance_inventory (CIS 7: tags, budgets, quotas)
  - get_oci_security_inventory   (CIS 8: Cloud Guard, vaults, keys, scanning)

Fixes:
  1. Singleton OCIClient — reuses SDK clients across tool calls (prevents throttling)
  2. Auto-retry on 404 — retries transient errors once with 1s delay
  3. Compartment iteration — scans all ACTIVE compartments, not just root
"""
from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    "oci-security-auditor",
    instructions=(
        "Read-only OCI security tools aligned with CIS OCI Benchmark major sections. "
        "Use only list/get/read operations. No write or patch operations."
    ),
)

# =============================================================================
# Singleton OCIClient (Fix 1: reuse SDK clients across tool calls)
# =============================================================================
_oci_client_instance: OCIClient | None = None
_oci_client_lock = threading.Lock()
_oci_client_kwargs: dict[str, Any] | None = None


def _get_oci_client(**kwargs: Any) -> OCIClient:
    """Return a shared OCIClient instance. Creates once, reuses forever."""
    global _oci_client_instance, _oci_client_kwargs
    if _oci_client_instance is None:
        with _oci_client_lock:
            if _oci_client_instance is None:
                # Merge kwargs with current env for first creation
                _oci_client_kwargs = {
                    "config_file": kwargs.get("config_file") or os.environ.get("OCI_CONFIG_FILE"),
                    "profile": kwargs.get("profile") or os.environ.get("OCI_CONFIG_PROFILE", "DEFAULT"),
                    "tenancy_ocid": kwargs.get("tenancy_ocid") or os.environ.get("OCI_TENANCY_OCID"),
                    "compartment_ocid": kwargs.get("compartment_ocid") or os.environ.get("OCI_COMPARTMENT_OCID"),
                    "region": kwargs.get("region") or os.environ.get("OCI_REGION"),
                }
                _oci_client_instance = OCIClient(**_oci_client_kwargs)
    return _oci_client_instance


def _reset_oci_client() -> None:
    """Reset singleton (useful for testing or config changes)."""
    global _oci_client_instance, _oci_client_kwargs
    _oci_client_instance = None
    _oci_client_kwargs = None


# =============================================================================
# Helpers
# =============================================================================


def _normalize_provider_scope(
    tenancy_ocid: str | None = None,
    compartment_ocid: str | None = None,
    region: str | None = None,
) -> dict[str, Any]:
    return {
        "tenancy_ocid": tenancy_ocid or os.environ.get("OCI_TENANCY_OCID"),
        "compartment_ocid": compartment_ocid or os.environ.get("OCI_COMPARTMENT_OCID"),
        "region": region or os.environ.get("OCI_REGION"),
    }


def _error_payload(exc: BaseException, context: str) -> dict[str, Any]:
    return {
        "tool_error": True,
        "context": context,
        "error_type": type(exc).__name__,
        "message": str(exc),
    }


def _safe_list(fn: Any, *args: Any, limit: int = 200, **kwargs: Any) -> list[Any]:
    """Paginate an OCI SDK list_* call safely with retry on transient errors (Fix 2)."""
    import oci

    max_retries = 2
    for attempt in range(max_retries):
        try:
            items: list[Any] = []
            response = fn(*args, **kwargs)
            items.extend(list(response.data) if hasattr(response, "data") else [])
            while hasattr(response, "has_next_page") and response.has_next_page and len(items) < limit:
                kwargs["page"] = response.next_page
                response = fn(*args, **kwargs)
                items.extend(list(response.data) if hasattr(response, "data") else [])
            return items[:limit]
        except oci.exceptions.ServiceError as e:
            if e.status in (404, 429, 500, 503) and attempt < max_retries - 1:
                time.sleep(1)  # backoff before retry
                continue
            raise
        except Exception:
            if attempt < max_retries - 1:
                time.sleep(1)
                continue
            raise
    return []


def _to_dict(obj: Any) -> Any:
    """Convert OCI SDK model objects to JSON-serializable dicts."""
    if obj is None:
        return None
    if isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, list):
        return [_to_dict(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _to_dict(v) for k, v in obj.items()}
    if hasattr(obj, "to_dict"):
        try:
            return _to_dict(obj.to_dict())
        except Exception:
            pass
    if hasattr(obj, "__dict__"):
        ignore = {"swagger_types", "attribute_map"}
        result = {}
        for k, v in vars(obj).items():
            if k in ignore or k.startswith("_"):
                continue
            result[k] = _to_dict(v)
        if result:
            return result
        for k, v in vars(obj).items():
            clean = k.lstrip("_")
            if clean in ignore:
                continue
            if clean != k:
                result[clean] = _to_dict(v)
            elif k not in ignore:
                result[k] = _to_dict(v)
        return result
    return str(obj)


def _discover_active_compartments(client: OCIClient) -> list[str]:
    """(Fix 3) Return OCIDs of all ACTIVE compartments in the tenancy."""
    import oci

    try:
        cfg = client._cfg()
        identity = oci.identity.IdentityClient(cfg)
        compartments = identity.list_compartments(
            compartment_id=client.tenancy_ocid,
            compartment_id_in_subtree=True,
        ).data
        return [c.id for c in compartments if c.lifecycle_state == "ACTIVE"]
    except Exception:
        # Fallback to just the default compartment
        return [client.compartment_ocid] if client.compartment_ocid else []


def _iterate_compartments(
    client: OCIClient,
    list_fn: Any,
    list_kwargs: dict[str, Any],
    limit: int = 200,
) -> tuple[list[Any], list[dict[str, Any]]]:
    """(Fix 3) Call list_fn across all ACTIVE compartments and merge results.

    Returns (merged_items, errors).
    """
    compartments = _discover_active_compartments(client)
    all_items: list[Any] = []
    errors: list[dict[str, Any]] = []

    for cid in compartments:
        try:
            kwargs = dict(list_kwargs)
            kwargs["compartment_id"] = cid
            items = _safe_list(list_fn, **kwargs, limit=limit)
            all_items.extend(items)
        except Exception as exc:
            errors.append({"section": list_fn.__name__, "compartment": cid[:20], "error": str(exc)[:200]})

    return all_items, errors


# =============================================================================
# OCIClient
# =============================================================================


class OCIClient:
    """Read-only OCI client wrapping the OCI Python SDK clients."""

    def __init__(
        self,
        config_file: str | None = None,
        profile: str | None = None,
        tenancy_ocid: str | None = None,
        compartment_ocid: str | None = None,
        region: str | None = None,
    ) -> None:
        self.config_file = config_file or os.environ.get("OCI_CONFIG_FILE")
        self.profile = profile or os.environ.get("OCI_CONFIG_PROFILE", "DEFAULT")
        self.tenancy_ocid = tenancy_ocid or os.environ.get("OCI_TENANCY_OCID")
        self.compartment_ocid = compartment_ocid or os.environ.get("OCI_COMPARTMENT_OCID")
        self.region = region or os.environ.get("OCI_REGION")

        if not self.config_file:
            raise ValueError(
                "Set OCI_CONFIG_FILE or pass config_file path to initialize OCI client."
            )
        self.config_file = str(Path(self.config_file).expanduser().resolve())

        if not os.path.exists(self.config_file):
            raise FileNotFoundError(f"OCI config file not found: {self.config_file}")

        # Resolve tenancy from config if not provided
        if not self.tenancy_ocid:
            try:
                import oci

                cfg = oci.config.from_file(self.config_file, self.profile)
                self.tenancy_ocid = cfg.get("tenancy")
                self.region = self.region or cfg.get("region")
            except Exception:
                pass

        # Default compartment to tenancy root if not set
        if not self.compartment_ocid and self.tenancy_ocid:
            self.compartment_ocid = self.tenancy_ocid

        self._config = None

    def _cfg(self) -> dict[str, Any]:
        if self._config is None:
            import oci

            self._config = oci.config.from_file(self.config_file, self.profile)
            if self.region:
                self._config["region"] = self.region
        return self._config

    def _scope_metadata(self) -> dict[str, Any]:
        return {
            "cloud_provider": "OCI",
            "tenancy_ocid": self.tenancy_ocid,
            "compartment_ocid": self.compartment_ocid,
            "region": self.region,
        }

    # ---- CIS 1: Identity and Access Management ----
    def get_identity_inventory(self) -> dict[str, Any]:
        import oci

        cfg = self._cfg()
        identity = oci.identity.IdentityClient(cfg)
        errors: list[dict[str, Any]] = []
        users: list[Any] = []
        groups: list[Any] = []
        policies: list[Any] = []
        compartments: list[Any] = []
        api_keys: list[Any] = []
        auth_tokens: list[Any] = []

        try:
            compartments = _safe_list(
                identity.list_compartments, compartment_id=self.tenancy_ocid, compartment_id_in_subtree=True
            )
        except Exception as exc:
            errors.append({"section": "compartments", "error": str(exc)})

        try:
            users = _safe_list(identity.list_users, compartment_id=self.tenancy_ocid)
        except Exception as exc:
            errors.append({"section": "users", "error": str(exc)})

        try:
            groups = _safe_list(identity.list_groups, compartment_id=self.tenancy_ocid)
        except Exception as exc:
            errors.append({"section": "groups", "error": str(exc)})

        try:
            policies = _safe_list(identity.list_policies, compartment_id=self.tenancy_ocid)
        except Exception as exc:
            errors.append({"section": "policies", "error": str(exc)})

        # API keys per user
        for u in users[:50]:
            try:
                keys = _safe_list(identity.list_api_keys, user_id=u.id)
                for k in keys:
                    api_keys.append({"user_id": u.id, "user_name": u.name, **_to_dict(k)})
            except Exception as exc:
                errors.append({"section": f"api_keys:{u.name}", "error": str(exc)})

        # Auth tokens per user
        for u in users[:50]:
            try:
                tokens = _safe_list(identity.list_auth_tokens, user_id=u.id)
                for t in tokens:
                    auth_tokens.append({"user_id": u.id, "user_name": u.name, **_to_dict(t)})
            except Exception as exc:
                errors.append({"section": f"auth_tokens:{u.name}", "error": str(exc)})

        # Detect users without MFA (no MFA devices)
        users_without_mfa: list[dict[str, Any]] = []
        for u in users[:50]:
            try:
                mfa = _safe_list(identity.list_mfa_devices, user_id=u.id)
                if not mfa:
                    users_without_mfa.append({"user_id": u.id, "user_name": u.name})
            except Exception:
                pass

        return {
            "cis_section": "Identity and Access Management",
            **self._scope_metadata(),
            "compartments": _to_dict(compartments),
            "users": _to_dict(users),
            "groups": _to_dict(groups),
            "policies": _to_dict(policies),
            "api_keys": api_keys,
            "auth_tokens": auth_tokens,
            "users_without_mfa": users_without_mfa,
            "summary": {
                "users": len(users),
                "groups": len(groups),
                "policies": len(policies),
                "compartments": len(compartments),
                "api_keys": len(api_keys),
                "users_without_mfa": len(users_without_mfa),
            },
            "errors": errors,
        }

    # ---- CIS 2: Networking ----
    def get_network_inventory(self) -> dict[str, Any]:
        import oci

        cfg = self._cfg()
        net = oci.core.VirtualNetworkClient(cfg)
        errors: list[dict[str, Any]] = []
        vcns, _ = _iterate_compartments(self, net.list_vcns, {})
        subnets, _ = _iterate_compartments(self, net.list_subnets, {})
        security_lists, _ = _iterate_compartments(self, net.list_security_lists, {})
        gateways, _ = _iterate_compartments(self, net.list_internet_gateways, {})
        route_tables, _ = _iterate_compartments(self, net.list_route_tables, {})

        # Flag security lists with 0.0.0.0/0 open ingress
        open_security_lists: list[dict[str, Any]] = []
        for sl in security_lists:
            sl_dict = _to_dict(sl)
            ingress = sl_dict.get("ingress_security_rules") or []
            has_open = any(
                str(r.get("source", "")).strip() == "0.0.0.0/0"
                and int(r.get("tcp_options", {}).get("destination_port_range", {}).get("min", 0) or 0) in (0, 22)
                for r in ingress
                if isinstance(r, dict)
            )
            if has_open:
                open_security_lists.append({"id": sl_dict.get("id"), "display_name": sl_dict.get("display_name")})

        return {
            "cis_section": "Networking",
            **self._scope_metadata(),
            "vcns": _to_dict(vcns),
            "subnets": _to_dict(subnets),
            "security_lists": _to_dict(security_lists),
            "internet_gateways": _to_dict(gateways),
            "route_tables": _to_dict(route_tables),
            "open_security_lists": open_security_lists,
            "summary": {
                "vcns": len(vcns),
                "subnets": len(subnets),
                "security_lists": len(security_lists),
                "internet_gateways": len(gateways),
                "open_security_lists": len(open_security_lists),
            },
            "errors": errors,
        }

    # ---- CIS 3: Logging and Monitoring ----
    def get_logging_inventory(self) -> dict[str, Any]:
        import oci

        cfg = self._cfg()
        errors: list[dict[str, Any]] = []
        log_groups, _ = _iterate_compartments(self, oci.logging.LoggingManagementClient(cfg).list_log_groups, {})
        logs: list[Any] = []
        for lg in log_groups[:10]:
            try:
                lg_dict = _to_dict(lg)
                log_client = oci.logging.LoggingManagementClient(cfg)
                lgs = _safe_list(log_client.list_logs, log_group_id=lg_dict.get("id"))
                logs.extend(lgs)
            except Exception as exc:
                errors.append({"section": "logs", "error": str(exc)[:200]})
        alarms, _ = _iterate_compartments(self, oci.monitoring.MonitoringClient(cfg).list_alarms, {})

        return {
            "cis_section": "Logging and Monitoring",
            **self._scope_metadata(),
            "log_groups": _to_dict(log_groups),
            "logs": _to_dict(logs),
            "alarms": _to_dict(alarms),
            "summary": {
                "log_groups": len(log_groups),
                "logs": len(logs),
                "alarms": len(alarms),
            },
            "errors": errors,
        }

    # ---- CIS 4: Compute ----
    def get_compute_inventory(self) -> dict[str, Any]:
        import oci

        cfg = self._cfg()
        compute = oci.core.ComputeClient(cfg)
        errors: list[dict[str, Any]] = []
        instances, _ = _iterate_compartments(self, compute.list_instances, {})
        boot_volumes, _ = _iterate_compartments(self, oci.core.BlockstorageClient(cfg).list_boot_volumes, {})

        instance_flags: list[dict[str, Any]] = []
        for inst in instances:
            inst_dict = _to_dict(inst)
            metadata = inst_dict.get("metadata") or {}
            has_ssh_keys = bool(metadata.get("ssh_authorized_keys"))
            instance_flags.append({
                "id": inst_dict.get("id"),
                "display_name": inst_dict.get("display_name"),
                "lifecycle_state": inst_dict.get("lifecycle_state"),
                "has_ssh_in_metadata": has_ssh_keys,
                "shape": inst_dict.get("shape"),
            })

        return {
            "cis_section": "Compute",
            **self._scope_metadata(),
            "instances": _to_dict(instances),
            "boot_volumes": _to_dict(boot_volumes),
            "instance_flags": instance_flags,
            "summary": {
                "instances": len(instances),
                "boot_volumes": len(boot_volumes),
            },
            "errors": errors,
        }

    # ---- CIS 5: Storage ----
    def get_storage_inventory(self) -> dict[str, Any]:
        import oci

        cfg = self._cfg()
        obj_storage = oci.object_storage.ObjectStorageClient(cfg)
        errors: list[dict[str, Any]] = []
        buckets: list[Any] = []
        namespace = ""

        try:
            namespace = obj_storage.get_namespace().data
        except Exception as exc:
            errors.append({"section": "namespace", "error": str(exc)})

        if namespace:
            try:
                buckets, _ = _iterate_compartments(
                    self,
                    lambda **kw: obj_storage.list_buckets(namespace_name=namespace, **kw),
                    {},
                )
            except Exception as exc:
                errors.append({"section": "buckets", "error": str(exc)})

        public_buckets: list[dict[str, Any]] = []
        for b in buckets:
            b_dict = _to_dict(b)
            try:
                preauth = _safe_list(obj_storage.list_preauthenticated_requests, namespace_name=namespace, bucket_name=b_dict.get("name"))
                if preauth:
                    public_buckets.append({
                        "name": b_dict.get("name"),
                        "id": b_dict.get("id"),
                        "has_preauthenticated_requests": True,
                    })
            except Exception:
                pass

        return {
            "cis_section": "Storage",
            **self._scope_metadata(),
            "namespace": namespace,
            "buckets": _to_dict(buckets),
            "public_buckets": public_buckets,
            "summary": {
                "buckets": len(buckets),
                "public_buckets": len(public_buckets),
            },
            "errors": errors,
        }

    # ---- CIS 6: Database ----
    def get_database_inventory(self) -> dict[str, Any]:
        import oci

        cfg = self._cfg()
        db_client = oci.database.DatabaseClient(cfg)
        errors: list[dict[str, Any]] = []
        db_systems, _ = _iterate_compartments(self, db_client.list_db_systems, {})
        autonomous_dbs, _ = _iterate_compartments(self, db_client.list_autonomous_databases, {})

        return {
            "cis_section": "Database",
            **self._scope_metadata(),
            "db_systems": _to_dict(db_systems),
            "autonomous_databases": _to_dict(autonomous_dbs),
            "summary": {
                "db_systems": len(db_systems),
                "autonomous_databases": len(autonomous_dbs),
            },
            "errors": errors,
        }

    # ---- CIS 7: Governance ----
    def get_governance_inventory(self) -> dict[str, Any]:
        import oci

        cfg = self._cfg()
        errors: list[dict[str, Any]] = []
        tag_namespaces: list[Any] = []
        budgets: list[Any] = []

        try:
            identity = oci.identity.IdentityClient(cfg)
            tag_namespaces = _safe_list(identity.list_tag_namespaces, compartment_id=self.tenancy_ocid)
        except Exception as exc:
            errors.append({"section": "tag_namespaces", "error": str(exc)})

        try:
            budget_client = oci.budget.BudgetClient(cfg)
            budgets = _safe_list(budget_client.list_budgets, compartment_id=self.tenancy_ocid)
        except Exception as exc:
            errors.append({"section": "budgets", "error": str(exc)})

        return {
            "cis_section": "Governance",
            **self._scope_metadata(),
            "tag_namespaces": _to_dict(tag_namespaces),
            "budgets": _to_dict(budgets),
            "summary": {
                "tag_namespaces": len(tag_namespaces),
                "budgets": len(budgets),
            },
            "errors": errors,
        }

    # ---- CIS 8: Security (Cloud Guard, Vault, Scanning) ----
    def get_security_inventory(self) -> dict[str, Any]:
        import oci

        cfg = self._cfg()
        errors: list[dict[str, Any]] = []
        cloud_guard_problems: list[Any] = []
        vaults: list[Any] = []
        keys: list[Any] = []

        cloud_guard_problems, _ = _iterate_compartments(self, oci.cloud_guard.CloudGuardClient(cfg).list_problems, {})
        vaults, _ = _iterate_compartments(self, oci.key_management.KmsVaultClient(cfg).list_vaults, {})

        for v in vaults[:10]:
            v_dict = _to_dict(v)
            try:
                key_client = oci.key_management.KmsManagementClient(cfg, vault_id=v_dict.get("id"))
                vkeys = _safe_list(key_client.list_keys)
                for k in vkeys:
                    keys.append({"vault_id": v_dict.get("id"), **_to_dict(k)})
            except Exception as exc:
                errors.append({"section": f"keys:vault_{v_dict.get('id', '?')[:20]}", "error": str(exc)[:200]})

        return {
            "cis_section": "Security",
            **self._scope_metadata(),
            "cloud_guard_problems": _to_dict(cloud_guard_problems),
            "vaults": _to_dict(vaults),
            "keys": keys,
            "summary": {
                "cloud_guard_problems": len(cloud_guard_problems),
                "vaults": len(vaults),
                "keys": len(keys),
            },
            "errors": errors,
        }


# ---- MCP tool wrappers (Fix 1: use singleton _get_oci_client) ----

@mcp.tool(description="Fetch OCI identity and policy inventory for CIS analysis (CIS section 1).")
def get_oci_identity_inventory(
    config_file: str | None = None,
    profile: str | None = None,
    tenancy_ocid: str | None = None,
    compartment_ocid: str | None = None,
    region: str | None = None,
) -> str:
    try:
        client = _get_oci_client(config_file=config_file, profile=profile, tenancy_ocid=tenancy_ocid, compartment_ocid=compartment_ocid, region=region)
        result = client.get_identity_inventory()
        return json.dumps(result)
    except Exception as exc:
        return json.dumps(_error_payload(exc, "get_oci_identity_inventory"))


@mcp.tool(description="Fetch OCI network inventory for CIS analysis (CIS section 2).")
def get_oci_network_inventory(
    config_file: str | None = None,
    profile: str | None = None,
    tenancy_ocid: str | None = None,
    compartment_ocid: str | None = None,
    region: str | None = None,
) -> str:
    try:
        client = _get_oci_client(config_file=config_file, profile=profile, tenancy_ocid=tenancy_ocid, compartment_ocid=compartment_ocid, region=region)
        result = client.get_network_inventory()
        return json.dumps(result)
    except Exception as exc:
        return json.dumps(_error_payload(exc, "get_oci_network_inventory"))


@mcp.tool(description="Fetch OCI logging and monitoring inventory for CIS analysis (CIS section 3).")
def get_oci_logging_inventory(
    config_file: str | None = None,
    profile: str | None = None,
    tenancy_ocid: str | None = None,
    compartment_ocid: str | None = None,
    region: str | None = None,
) -> str:
    try:
        client = _get_oci_client(config_file=config_file, profile=profile, tenancy_ocid=tenancy_ocid, compartment_ocid=compartment_ocid, region=region)
        result = client.get_logging_inventory()
        return json.dumps(result)
    except Exception as exc:
        return json.dumps(_error_payload(exc, "get_oci_logging_inventory"))


@mcp.tool(description="Fetch OCI compute inventory for CIS analysis (CIS section 4).")
def get_oci_compute_inventory(
    config_file: str | None = None,
    profile: str | None = None,
    tenancy_ocid: str | None = None,
    compartment_ocid: str | None = None,
    region: str | None = None,
) -> str:
    try:
        client = _get_oci_client(config_file=config_file, profile=profile, tenancy_ocid=tenancy_ocid, compartment_ocid=compartment_ocid, region=region)
        result = client.get_compute_inventory()
        return json.dumps(result)
    except Exception as exc:
        return json.dumps(_error_payload(exc, "get_oci_compute_inventory"))


@mcp.tool(description="Fetch OCI object storage inventory for CIS analysis (CIS section 5).")
def get_oci_storage_inventory(
    config_file: str | None = None,
    profile: str | None = None,
    tenancy_ocid: str | None = None,
    compartment_ocid: str | None = None,
    region: str | None = None,
) -> str:
    try:
        client = _get_oci_client(config_file=config_file, profile=profile, tenancy_ocid=tenancy_ocid, compartment_ocid=compartment_ocid, region=region)
        result = client.get_storage_inventory()
        return json.dumps(result)
    except Exception as exc:
        return json.dumps(_error_payload(exc, "get_oci_storage_inventory"))


@mcp.tool(description="Fetch OCI database inventory for CIS analysis (CIS section 6).")
def get_oci_database_inventory(
    config_file: str | None = None,
    profile: str | None = None,
    tenancy_ocid: str | None = None,
    compartment_ocid: str | None = None,
    region: str | None = None,
) -> str:
    try:
        client = _get_oci_client(config_file=config_file, profile=profile, tenancy_ocid=tenancy_ocid, compartment_ocid=compartment_ocid, region=region)
        result = client.get_database_inventory()
        return json.dumps(result)
    except Exception as exc:
        return json.dumps(_error_payload(exc, "get_oci_database_inventory"))


@mcp.tool(description="Fetch OCI governance inventory (tags, budgets) for CIS analysis (CIS section 7).")
def get_oci_governance_inventory(
    config_file: str | None = None,
    profile: str | None = None,
    tenancy_ocid: str | None = None,
    compartment_ocid: str | None = None,
    region: str | None = None,
) -> str:
    try:
        client = _get_oci_client(config_file=config_file, profile=profile, tenancy_ocid=tenancy_ocid, compartment_ocid=compartment_ocid, region=region)
        result = client.get_governance_inventory()
        return json.dumps(result)
    except Exception as exc:
        return json.dumps(_error_payload(exc, "get_oci_governance_inventory"))


@mcp.tool(description="Fetch OCI security inventory (Cloud Guard, vaults, keys) for CIS analysis (CIS section 8).")
def get_oci_security_inventory(
    config_file: str | None = None,
    profile: str | None = None,
    tenancy_ocid: str | None = None,
    compartment_ocid: str | None = None,
    region: str | None = None,
) -> str:
    try:
        client = _get_oci_client(config_file=config_file, profile=profile, tenancy_ocid=tenancy_ocid, compartment_ocid=compartment_ocid, region=region)
        result = client.get_security_inventory()
        return json.dumps(result)
    except Exception as exc:
        return json.dumps(_error_payload(exc, "get_oci_security_inventory"))


# ---- In-process call helper (mirrors GCP call_mcp_tool) ----

_OCI_TOOLS = {
    "get_oci_identity_inventory": get_oci_identity_inventory,
    "get_oci_network_inventory": get_oci_network_inventory,
    "get_oci_logging_inventory": get_oci_logging_inventory,
    "get_oci_compute_inventory": get_oci_compute_inventory,
    "get_oci_storage_inventory": get_oci_storage_inventory,
    "get_oci_database_inventory": get_oci_database_inventory,
    "get_oci_governance_inventory": get_oci_governance_inventory,
    "get_oci_security_inventory": get_oci_security_inventory,
}


def call_oci_mcp_tool(name: str, arguments: dict[str, Any] | None = None) -> str:
    """Call an OCI MCP tool in-process and return its JSON string result.

    Retries once if the result contains errors (transient 404 throttling).
    """
    fn = _OCI_TOOLS.get(name)
    if fn is None:
        return json.dumps(_error_payload(ValueError(f"Unknown OCI tool: {name}"), "call_oci_mcp_tool"))
    
    # First attempt
    try:
        raw = fn(**(arguments or {}))
    except Exception as exc:
        raw = json.dumps(_error_payload(exc, f"call_oci_mcp_tool:{name}"))
    
    # Check if result has errors — if so, retry once with fresh client
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, dict) and parsed.get("errors") and len(parsed["errors"]) > 0:
            # Retry: reset singleton and call again
            _reset_oci_client()
            time.sleep(1.5)
            try:
                raw = fn(**(arguments or {}))
            except Exception as exc:
                raw = json.dumps(_error_payload(exc, f"call_oci_mcp_tool:{name} (retry)"))
    except (json.JSONDecodeError, TypeError):
        pass
    
    return raw


if __name__ == "__main__":
    mcp.run()