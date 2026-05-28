"""
Read-only MCP server for GCP CIS-oriented security metadata.
Uses Cloud Asset Inventory (search_all_resources) first; falls back to
Compute / Storage list/get APIs for fields Asset does not expose well.
"""

from __future__ import annotations

import json
import os
from typing import Any, Callable, Iterator

from google.api_core import exceptions as gcp_exceptions
from google.cloud import asset_v1
from google.cloud import compute_v1
from google.cloud import storage
from google.oauth2 import service_account
from google.protobuf.json_format import MessageToDict
from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    "gcp-security-auditor",
    instructions=(
        "Read-only GCP security tools aligned with CIS GCP Foundation Benchmark major sections "
        "(IAM §1, Logging §2, Networking §3, Virtual Machines §4, Storage §5, Cloud SQL §6, …). "
        "Uses Cloud Asset Inventory where possible. No write or patch operations."
    ),
)


def _gcp_error_dict(exc: BaseException, context: str) -> dict[str, Any]:
    """Normalize GCP errors for inclusion in audit JSON output."""
    payload: dict[str, Any] = {
        "tool_error": True,
        "context": context,
        "error_type": type(exc).__name__,
        "message": str(exc),
    }
    if isinstance(exc, gcp_exceptions.PermissionDenied):
        payload["permission_denied"] = True
        payload["hint"] = (
            "Grant Viewer plus Cloud Asset Viewer (cloudasset.assets.searchAllResources) "
            "on the project, or narrow tool scope."
        )
    elif isinstance(exc, gcp_exceptions.NotFound):
        payload["not_found"] = True
    elif isinstance(exc, gcp_exceptions.GoogleAPICallError):
        payload["api_error"] = True
    return payload


def _asset_result_to_dict(r: asset_v1.ResourceSearchResult) -> dict[str, Any]:
    return MessageToDict(r._pb, preserving_proto_field_name=False)


def _iter_search_all_resources(
    client: asset_v1.AssetServiceClient,
    scope: str,
    asset_types: list[str],
    query: str = "",
) -> Iterator[dict[str, Any]]:
    request = asset_v1.SearchAllResourcesRequest(
        scope=scope,
        asset_types=asset_types,
        query=query,
        page_size=500,
    )
    pager = client.search_all_resources(request=request)
    for item in pager:
        yield _asset_result_to_dict(item)


class GCPClient:
    """
    Read-only GCP access via a service account JSON file.
    All operations use list/get/search — no create/update/patch/delete.
    """

    def __init__(
        self,
        credentials_path: str | None = None,
        project_id: str | None = None,
    ) -> None:
        path = credentials_path or os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
        if not path:
            raise ValueError(
                "Set GOOGLE_APPLICATION_CREDENTIALS or pass credentials_path "
                "to point at service_account.json"
            )
        if not os.path.isfile(path):
            raise FileNotFoundError(f"Service account file not found: {path}")

        self._credentials_path = path
        self.credentials = service_account.Credentials.from_service_account_file(path)

        with open(path, encoding="utf-8") as f:
            sa = json.load(f)
        self.project_id = (
            project_id
            or os.environ.get("GCP_PROJECT_ID")
            or sa.get("project_id")
        )
        if not self.project_id:
            raise ValueError("Could not determine project_id (set GCP_PROJECT_ID).")

        self._scope = f"projects/{self.project_id}"
        self._asset = asset_v1.AssetServiceClient(credentials=self.credentials)
        self._storage = storage.Client(
            credentials=self.credentials, project=self.project_id
        )

    @property
    def scope(self) -> str:
        return self._scope

    def search_assets(self, asset_types: list[str], query: str = "") -> list[dict[str, Any]]:
        return list(_iter_search_all_resources(self._asset, self._scope, asset_types, query))

    # --- CIS §1 IAM: service accounts & keys (Asset Inventory) ---

    def collect_iam_inventory(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "cis_section": 1,
            "project_id": self.project_id,
            "service_accounts": [],
            "service_account_keys": [],
            "source": "cloudasset.googleapis.com (searchAllResources)",
        }
        try:
            out["service_accounts"] = self.search_assets(
                ["iam.googleapis.com/ServiceAccount"]
            )
            out["service_account_keys"] = self.search_assets(
                ["iam.googleapis.com/ServiceAccountKey"]
            )
        except Exception as e:
            out["errors"] = [_gcp_error_dict(e, "collect_iam_inventory")]
        return out

    # --- CIS §3 Networking: VPC, firewalls, subnet flow logs ---

    def collect_network_inventory(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "cis_section": 3,
            "project_id": self.project_id,
            "networks": [],
            "firewalls": [],
            "subnetworks": [],
            "subnetwork_flow_logs": [],
            "source_primary": "cloudasset.googleapis.com",
        }
        try:
            out["networks"] = self.search_assets(["compute.googleapis.com/Network"])
            out["firewalls"] = self.search_assets(["compute.googleapis.com/Firewall"])
            out["subnetworks"] = self.search_assets(
                ["compute.googleapis.com/Subnetwork"]
            )
        except Exception as e:
            out.setdefault("errors", []).append(
                _gcp_error_dict(e, "asset_search_network")
            )

        # Definitive flow log status from Compute API (read-only aggregated_list)
        try:
            subnets_client = compute_v1.SubnetworksClient(credentials=self.credentials)
            req = compute_v1.AggregatedListSubnetworksRequest(project=self.project_id)
            flow_rows: list[dict[str, Any]] = []
            for zone_or_region, scoped in subnets_client.aggregated_list(request=req):
                if not scoped.subnetworks:
                    continue
                for sn in scoped.subnetworks:
                    lc = sn.log_config
                    flow_rows.append(
                        {
                            "name": sn.name,
                            "region": getattr(sn, "region", None),
                            "network": sn.network,
                            "enable_flow_logs": bool(lc.enable) if lc else False,
                            "aggregation_interval": lc.aggregation_interval if lc else None,
                        }
                    )
            out["subnetwork_flow_logs"] = flow_rows
        except Exception as e:
            out.setdefault("errors", []).append(
                _gcp_error_dict(e, "compute_subnetworks_aggregated_list")
            )

        return out

    # --- CIS §5 Storage: versioning & public exposure ---

    def collect_storage_inventory(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "cis_section": 5,
            "project_id": self.project_id,
            "buckets": [],
            "source_asset": "cloudasset.googleapis.com",
            "source_detail": "storage.buckets.get + get_iam_policy (read-only)",
        }
        try:
            asset_buckets = self.search_assets(["storage.googleapis.com/Bucket"])
            out["asset_bucket_snapshot"] = asset_buckets
        except Exception as e:
            out.setdefault("errors", []).append(
                _gcp_error_dict(e, "asset_search_buckets")
            )

        detailed: list[dict[str, Any]] = []
        try:
            for b in self._storage.list_buckets(project=self.project_id):
                row: dict[str, Any] = {"name": b.name}
                try:
                    full = self._storage.get_bucket(b.name)
                    row["versioning_enabled"] = bool(full.versioning_enabled)
                    row["uniform_bucket_level_access"] = getattr(
                        full.iam_configuration,
                        "uniform_bucket_level_access_enabled",
                        None,
                    )
                    policy = full.get_iam_policy(requested_policy_version=3)
                    bindings_summary: list[dict[str, Any]] = []
                    for binding in policy.bindings or []:
                        if isinstance(binding, dict):
                            members = list(binding.get("members") or [])
                            role = binding.get("role")
                        else:
                            members = list(getattr(binding, "members", None) or [])
                            role = getattr(binding, "role", None)
                        public = [
                            m
                            for m in members
                            if m in ("allUsers", "allAuthenticatedUsers")
                        ]
                        if public:
                            bindings_summary.append(
                                {
                                    "role": role,
                                    "public_members": public,
                                }
                            )
                    row["public_access_bindings"] = bindings_summary
                    row["has_public_principal"] = bool(bindings_summary)
                except Exception as inner:
                    row["bucket_detail_error"] = _gcp_error_dict(
                        inner, f"bucket:{b.name}"
                    )
                detailed.append(row)
            out["buckets"] = detailed
        except Exception as e:
            out.setdefault("errors", []).append(
                _gcp_error_dict(e, "storage_list_buckets")
            )
        return out

    # --- CIS §4 Virtual Machines (Compute): public IPs & Shielded VM ---

    def collect_compute_inventory(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "cis_section": 4,
            "project_id": self.project_id,
            "instances": [],
            "source_asset": "cloudasset.googleapis.com",
            "source_detail": "compute.instances aggregated_list (read-only)",
        }
        try:
            out["asset_instances"] = self.search_assets(
                ["compute.googleapis.com/Instance"]
            )
        except Exception as e:
            out.setdefault("errors", []).append(
                _gcp_error_dict(e, "asset_search_instances")
            )

        instances_out: list[dict[str, Any]] = []
        try:
            inst_client = compute_v1.InstancesClient(credentials=self.credentials)
            req = compute_v1.AggregatedListInstancesRequest(project=self.project_id)
            for _zone, scoped in inst_client.aggregated_list(request=req):
                if not scoped.instances:
                    continue
                for vm in scoped.instances:
                    nics = []
                    for nic in vm.network_interfaces or []:
                        access = [
                            {"nat_i_p": a.nat_i_p, "name": a.name}
                            for a in nic.access_configs or []
                        ]
                        nics.append(
                            {
                                "name": nic.name,
                                "network": nic.network,
                                "subnetwork": nic.subnetwork,
                                "access_configs": access,
                            }
                        )
                    shield = vm.shielded_instance_config
                    instances_out.append(
                        {
                            "name": vm.name,
                            "zone": vm.zone,
                            "status": vm.status,
                            "network_interfaces": nics,
                            "shielded_instance_config": {
                                "enable_secure_boot": getattr(
                                    shield, "enable_secure_boot", None
                                ),
                                "enable_vtpm": getattr(shield, "enable_vtpm", None),
                                "enable_integrity_monitoring": getattr(
                                    shield, "enable_integrity_monitoring", None
                                ),
                            }
                            if shield
                            else None,
                        }
                    )
            out["instances"] = instances_out
        except Exception as e:
            out.setdefault("errors", []).append(
                _gcp_error_dict(e, "compute_aggregated_list_instances")
            )
        return out

    # --- CIS §2 Logging and Monitoring: sinks, metrics (read-only) ---

    def collect_logging_monitoring_inventory(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "cis_section": 2,
            "project_id": self.project_id,
            "log_sinks": [],
            "log_metrics": [],
            "source": "logging.googleapis.com (list_sinks / list_metrics)",
        }
        try:
            from google.cloud import logging as gcl

            lc = gcl.Client(project=self.project_id, credentials=self.credentials)
            for sink in lc.list_sinks():
                flt = getattr(sink, "filter_", None) or getattr(sink, "filter", None)
                out["log_sinks"].append(
                    {
                        "name": sink.name,
                        "destination": sink.destination,
                        "filter": flt,
                    }
                )
        except Exception as e:
            out.setdefault("errors", []).append(
                _gcp_error_dict(e, "logging_list_sinks")
            )
        try:
            from google.cloud import logging as gcl

            lc = gcl.Client(project=self.project_id, credentials=self.credentials)
            list_m = getattr(lc, "list_metrics", None)
            if callable(list_m):
                for metric in list_m():
                    flt = getattr(metric, "filter_", None) or getattr(
                        metric, "filter", None
                    )
                    out["log_metrics"].append(
                        {
                            "name": metric.name,
                            "description": getattr(metric, "description", None),
                            "filter": flt,
                        }
                    )
        except Exception as e:
            out.setdefault("errors", []).append(
                _gcp_error_dict(e, "logging_list_metrics")
            )
        return out

    # --- CIS §6 Cloud SQL: instances (Asset + optional metadata) ---

    def collect_cloud_sql_inventory(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "cis_section": 6,
            "project_id": self.project_id,
            "instances": [],
            "source": "cloudasset.googleapis.com (sqladmin.googleapis.com/Instance)",
        }
        try:
            out["instances"] = self.search_assets(
                ["sqladmin.googleapis.com/Instance"]
            )
        except Exception as e:
            out["errors"] = [_gcp_error_dict(e, "asset_search_cloud_sql")]
        return out

    # --- CIS §7 BigQuery: datasets (read-only) ---

    def collect_bigquery_inventory(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "cis_section": 7,
            "project_id": self.project_id,
            "datasets": [],
            "datasets_asset": [],
            "source": "bigquery.googleapis.com + cloudasset (Dataset)",
        }
        try:
            from google.cloud import bigquery

            bq = bigquery.Client(
                project=self.project_id, credentials=self.credentials
            )
            for ds_ref in bq.list_datasets():
                row: dict[str, Any] = {"dataset_id": ds_ref.dataset_id}
                try:
                    d = bq.get_dataset(ds_ref.reference)
                    row["location"] = d.location
                    row["full_dataset_id"] = d.full_dataset_id
                    row["default_table_expiration_ms"] = d.default_table_expiration_ms
                    de = d.default_encryption_configuration
                    if de is not None:
                        row["default_kms_key_name"] = getattr(de, "kms_key_name", None)
                except Exception as inner:
                    row["detail_error"] = _gcp_error_dict(
                        inner, f"bigquery_dataset:{ds_ref.dataset_id}"
                    )
                out["datasets"].append(row)
        except Exception as e:
            out.setdefault("errors", []).append(
                _gcp_error_dict(e, "bigquery_list_datasets")
            )
        try:
            out["datasets_asset"] = self.search_assets(
                ["bigquery.googleapis.com/Dataset"]
            )
        except Exception as e:
            out.setdefault("errors", []).append(
                _gcp_error_dict(e, "asset_search_bigquery_dataset")
            )
        return out

    # --- CIS §8 Dataproc: clusters (Asset Inventory) ---

    def collect_dataproc_inventory(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "cis_section": 8,
            "project_id": self.project_id,
            "clusters": [],
            "source": "cloudasset.googleapis.com (dataproc.googleapis.com/Cluster)",
        }
        try:
            out["clusters"] = self.search_assets(
                ["dataproc.googleapis.com/Cluster"]
            )
        except Exception as e:
            out["errors"] = [_gcp_error_dict(e, "asset_search_dataproc")]
        return out


_client: GCPClient | None = None


def get_gcp_client() -> GCPClient:
    global _client
    if _client is None:
        _client = GCPClient()
    return _client


def _client_for_project(project_id: str | None) -> GCPClient:
    if project_id:
        return GCPClient(project_id=project_id)
    return get_gcp_client()


def _json_dumps(data: Any) -> str:
    return json.dumps(data, indent=2, default=str)


@mcp.tool()
def get_iam_policy(project_id: str | None = None) -> str:
    """
    CIS Section 1 — IAM: list service accounts and service account keys via
    Cloud Asset Inventory (read-only).
    """
    try:
        return _json_dumps(_client_for_project(project_id).collect_iam_inventory())
    except Exception as e:
        return _json_dumps(_gcp_error_dict(e, "get_iam_policy"))


@mcp.tool()
def get_network_config(project_id: str | None = None) -> str:
    """
    CIS Section 3 — Networking: VPC-related assets, firewall rules, subnets,
    and VPC Flow Logs enablement per subnet (read-only).
    """
    try:
        return _json_dumps(
            _client_for_project(project_id).collect_network_inventory()
        )
    except Exception as e:
        return _json_dumps(_gcp_error_dict(e, "get_network_config"))


@mcp.tool()
def get_storage_metadata(project_id: str | None = None) -> str:
    """
    CIS Section 5 — Storage: bucket versioning, uniform access, and any
    bindings involving allUsers / allAuthenticatedUsers (read-only).
    """
    try:
        return _json_dumps(
            _client_for_project(project_id).collect_storage_inventory()
        )
    except Exception as e:
        return _json_dumps(_gcp_error_dict(e, "get_storage_metadata"))


@mcp.tool()
def get_compute_info(project_id: str | None = None) -> str:
    """
    CIS Section 4 — Virtual Machines (Compute): instances with external IPs and
    Shielded VM settings (read-only; Asset + Compute Engine API).
    """
    try:
        return _json_dumps(
            _client_for_project(project_id).collect_compute_inventory()
        )
    except Exception as e:
        return _json_dumps(_gcp_error_dict(e, "get_compute_info"))


@mcp.tool()
def get_logging_monitoring_config(project_id: str | None = None) -> str:
    """
    CIS Section 2 — Logging and Monitoring: log sinks and log-based metrics
    (read-only; Cloud Logging API).
    """
    try:
        return _json_dumps(
            _client_for_project(project_id).collect_logging_monitoring_inventory()
        )
    except Exception as e:
        return _json_dumps(_gcp_error_dict(e, "get_logging_monitoring_config"))


@mcp.tool()
def get_cloud_sql_inventory(project_id: str | None = None) -> str:
    """
    CIS Section 6 — Cloud SQL Database Services: Cloud SQL instances via
    Cloud Asset Inventory (read-only).
    """
    try:
        return _json_dumps(
            _client_for_project(project_id).collect_cloud_sql_inventory()
        )
    except Exception as e:
        return _json_dumps(_gcp_error_dict(e, "get_cloud_sql_inventory"))


@mcp.tool()
def get_bigquery_inventory(project_id: str | None = None) -> str:
    """
    CIS Section 7 — BigQuery: datasets (location, expiration, encryption hints)
    plus Asset snapshot (read-only).
    """
    try:
        return _json_dumps(
            _client_for_project(project_id).collect_bigquery_inventory()
        )
    except Exception as e:
        return _json_dumps(_gcp_error_dict(e, "get_bigquery_inventory"))


@mcp.tool()
def get_dataproc_inventory(project_id: str | None = None) -> str:
    """
    CIS Section 8 — Dataproc: clusters via Cloud Asset Inventory (read-only).
    """
    try:
        return _json_dumps(
            _client_for_project(project_id).collect_dataproc_inventory()
        )
    except Exception as e:
        return _json_dumps(_gcp_error_dict(e, "get_dataproc_inventory"))


TOOL_DISPATCH: dict[str, Callable[..., str]] = {
    "get_iam_policy": get_iam_policy,
    "get_logging_monitoring_config": get_logging_monitoring_config,
    "get_network_config": get_network_config,
    "get_compute_info": get_compute_info,
    "get_storage_metadata": get_storage_metadata,
    "get_cloud_sql_inventory": get_cloud_sql_inventory,
    "get_bigquery_inventory": get_bigquery_inventory,
    "get_dataproc_inventory": get_dataproc_inventory,
}


TOOL_CATALOG: dict[str, dict[str, Any]] = {
    "get_iam_policy": {
        "cis_section": "1",
        "category": "IAM",
        "description": "List service accounts and service-account keys (read-only).",
        "arguments": {"project_id": "optional string"},
    },
    "get_logging_monitoring_config": {
        "cis_section": "2",
        "category": "Logging",
        "description": "List log sinks and log-based metrics (read-only).",
        "arguments": {"project_id": "optional string"},
    },
    "get_network_config": {
        "cis_section": "3",
        "category": "Networking",
        "description": "List VPC networks, firewalls, subnets, and flow-log settings (read-only).",
        "arguments": {"project_id": "optional string"},
    },
    "get_compute_info": {
        "cis_section": "4",
        "category": "Compute",
        "description": "List VM instances with public-IP and Shielded VM related fields (read-only).",
        "arguments": {"project_id": "optional string"},
    },
    "get_storage_metadata": {
        "cis_section": "5",
        "category": "Storage",
        "description": "List bucket security metadata (versioning, UBLA, public bindings) (read-only).",
        "arguments": {"project_id": "optional string"},
    },
    "get_cloud_sql_inventory": {
        "cis_section": "6",
        "category": "SQL",
        "description": "List Cloud SQL instances using Cloud Asset Inventory (read-only).",
        "arguments": {"project_id": "optional string"},
    },
    "get_bigquery_inventory": {
        "cis_section": "7",
        "category": "BigQuery",
        "description": "List BigQuery dataset metadata and asset snapshot (read-only).",
        "arguments": {"project_id": "optional string"},
    },
    "get_dataproc_inventory": {
        "cis_section": "8",
        "category": "Dataproc",
        "description": "List Dataproc clusters using Cloud Asset Inventory (read-only).",
        "arguments": {"project_id": "optional string"},
    },
}


def get_tool_catalog() -> dict[str, dict[str, Any]]:
    """Return MCP tool metadata for agent-side planning."""
    return TOOL_CATALOG.copy()


def call_mcp_tool(name: str, arguments: dict[str, Any] | None = None) -> str:
    """Programmatic entry point for the LangGraph agent (same logic as MCP tools)."""
    arguments = arguments or {}
    if name not in TOOL_DISPATCH:
        return _json_dumps({"tool_error": True, "message": f"Unknown tool: {name}"})
    return TOOL_DISPATCH[name](**arguments)


if __name__ == "__main__":
    mcp.run(transport="stdio")
