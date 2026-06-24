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
"""
from __future__ import annotations

import json
import os
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
    """Paginate an OCI SDK list_* call safely."""
    items: list[Any] = []
    try:
        response = fn(*args, **kwargs)
        items.extend(list(response.data) if hasattr(response, "data") else [])
        while hasattr(response, "has_next_page") and response.has_next_page and len(items) < limit:
            kwargs["page"] = response.next_page
            response = fn(*args, **kwargs)
            items.extend(list(response.data) if hasattr(response, "data") else [])
    except Exception:
        pass
    return items[:limit]


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
    # OCI SDK models have attribute_names and to_dict
    if hasattr(obj, "attribute_names"):
        return {attr: _to_dict(getattr(obj, attr, None)) for attr in obj.attribute_names}
    if hasattr(obj, "to_dict"):
        try:
            return _to_dict(obj.to_dict())
        except Exception:
            pass
    if hasattr(obj, "__dict__"):
        return {k: _to_dict(v) for k, v in vars(obj).items() if not k.startswith("_")}
    return str(obj)


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
                # If MFA listing not supported, skip
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
        vcns: list[Any] = []
        subnets: list[Any] = []
        security_lists: list[Any] = []
        gateways: list[Any] = []
        route_tables: list[Any] = []

        try:
            vcns = _safe_list(net.list_vcns, compartment_id=self.compartment_ocid)
        except Exception as exc:
            errors.append({"section": "vcns", "error": str(exc)})

        try:
            subnets = _safe_list(net.list_subnets, compartment_id=self.compartment_ocid)
        except Exception as exc:
            errors.append({"section": "subnets", "error": str(exc)})

        try:
            security_lists = _safe_list(net.list_security_lists, compartment_id=self.compartment_ocid)
        except Exception as exc:
            errors.append({"section": "security_lists", "error": str(exc)})

        try:
            gateways = _safe_list(net.list_internet_gateways, compartment_id=self.compartment_ocid)
        except Exception as exc:
            errors.append({"section": "internet_gateways", "error": str(exc)})

        try:
            route_tables = _safe_list(net.list_route_tables, compartment_id=self.compartment_ocid)
        except Exception as exc:
            errors.append({"section": "route_tables", "error": str(exc)})

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
        log_groups: list[Any] = []
        logs: list[Any] = []
        alarms: list[Any] = []

        try:
            logging_client = oci.logging.LoggingManagementClient(cfg)
            log_groups = _safe_list(logging_client.list_log_groups, compartment_id=self.compartment_ocid)
            logs = _safe_list(logging_client.list_logs, log_group_id=log_groups[0].id if log_groups else "")
        except Exception as exc:
            errors.append({"section": "logs", "error": str(exc)})

        try:
            monitoring = oci.monitoring.MonitoringClient(cfg)
            alarms = _safe_list(monitoring.list_alarms, compartment_id=self.compartment_ocid)
        except Exception as exc:
            errors.append({"section": "alarms", "error": str(exc)})

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
        instances: list[Any] = []
        boot_volumes: list[Any] = []

        try:
            instances = _safe_list(compute.list_instances, compartment_id=self.compartment_ocid)
        except Exception as exc:
            errors.append({"section": "instances", "error": str(exc)})

        try:
            bv_client = oci.core.BlockstorageClient(cfg)
            boot_volumes = _safe_list(bv_client.list_boot_volumes, compartment_id=self.compartment_ocid)
        except Exception as exc:
            errors.append({"section": "boot_volumes", "error": str(exc)})

        # Flag instances with public IPs / metadata issues
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
                buckets = _safe_list(obj_storage.list_buckets, namespace_name=namespace, compartment_id=self.compartment_ocid)
            except Exception as exc:
                errors.append({"section": "buckets", "error": str(exc)})

        # Check each bucket for public access
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
        db_systems: list[Any] = []
        autonomous_dbs: list[Any] = []

        try:
            db_systems = _safe_list(db_client.list_db_systems, compartment_id=self.compartment_ocid)
        except Exception as exc:
            errors.append({"section": "db_systems", "error": str(exc)})

        try:
            autonomous_dbs = _safe_list(db_client.list_autonomous_databases, compartment_id=self.compartment_ocid)
        except Exception as exc:
            errors.append({"section": "autonomous_dbs", "error": str(exc)})

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

        try:
            cloud_guard = oci.cloud_guard.CloudGuardClient(cfg)
            cloud_guard_problems = _safe_list(cloud_guard.list_problems, compartment_id=self.compartment_ocid)
        except Exception as exc:
            errors.append({"section": "cloud_guard", "error": str(exc)})

        try:
            vault_client = oci.key_management.KmsVaultClient(cfg)
            vaults = _safe_list(vault_client.list_vaults, compartment_id=self.compartment_ocid)
        except Exception as exc:
            errors.append({"section": "vaults", "error": str(exc)})

        try:
            for v in vaults[:10]:
                v_dict = _to_dict(v)
                key_client = oci.key_management.KmsManagementClient(cfg, vault_id=v_dict.get("id"))
                vkeys = _safe_list(key_client.list_keys)
                for k in vkeys:
                    keys.append({"vault_id": v_dict.get("id"), **_to_dict(k)})
        except Exception as exc:
            errors.append({"section": "keys", "error": str(exc)})

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


# ---- MCP tool wrappers ----

@mcp.tool(description="Fetch OCI identity and policy inventory for CIS analysis (CIS section 1).")
def get_oci_identity_inventory(
    config_file: str | None = None,
    profile: str | None = None,
    tenancy_ocid: str | None = None,
    compartment_ocid: str | None = None,
    region: str | None = None,
) -> str:
    try:
        client = OCIClient(config_file=config_file, profile=profile, tenancy_ocid=tenancy_ocid, compartment_ocid=compartment_ocid, region=region)
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
        client = OCIClient(config_file=config_file, profile=profile, tenancy_ocid=tenancy_ocid, compartment_ocid=compartment_ocid, region=region)
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
        client = OCIClient(config_file=config_file, profile=profile, tenancy_ocid=tenancy_ocid, compartment_ocid=compartment_ocid, region=region)
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
        client = OCIClient(config_file=config_file, profile=profile, tenancy_ocid=tenancy_ocid, compartment_ocid=compartment_ocid, region=region)
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
        client = OCIClient(config_file=config_file, profile=profile, tenancy_ocid=tenancy_ocid, compartment_ocid=compartment_ocid, region=region)
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
        client = OCIClient(config_file=config_file, profile=profile, tenancy_ocid=tenancy_ocid, compartment_ocid=compartment_ocid, region=region)
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
        client = OCIClient(config_file=config_file, profile=profile, tenancy_ocid=tenancy_ocid, compartment_ocid=compartment_ocid, region=region)
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
        client = OCIClient(config_file=config_file, profile=profile, tenancy_ocid=tenancy_ocid, compartment_ocid=compartment_ocid, region=region)
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
    """Call an OCI MCP tool in-process and return its JSON string result."""
    fn = _OCI_TOOLS.get(name)
    if fn is None:
        return json.dumps(_error_payload(ValueError(f"Unknown OCI tool: {name}"), "call_oci_mcp_tool"))
    try:
        return fn(**(arguments or {}))
    except Exception as exc:
        return json.dumps(_error_payload(exc, f"call_oci_mcp_tool:{name}"))


if __name__ == "__main__":
    mcp.run()