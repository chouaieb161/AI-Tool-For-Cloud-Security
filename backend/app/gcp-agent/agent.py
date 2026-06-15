"""
LangGraph agent: fetch GCP state via MCP tool functions, retrieve CIS rules (RAG),
analyze with Groq (default: Llama 3.3 70B), emit Markdown report.
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from pathlib import Path
from typing import Any, Callable, TypedDict, Annotated
import typing

from dotenv import load_dotenv
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage
from langchain_core.tools import StructuredTool
from langchain_groq import ChatGroq
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages

from app.mcp.mcp_server import call_mcp_tool, get_tool_catalog
from app.rag.retriever import format_retrieval_for_prompt, get_retriever
from app.rag.vector_store import DEFAULT_PERSIST

# CIS GCP Foundation Benchmark major section → retriever metadata category (ingestion.SECTION_META)
_SECTION_CATEGORY = {
    "1": "IAM",
    "2": "Logging",
    "3": "Networking",
    "4": "Compute",  # §4 Virtual Machines
    "5": "Storage",
    "6": "SQL",  # Cloud SQL
    "7": "BigQuery",
    "8": "Dataproc",
}

# Tools in CIS §1–§8 order (matches MCP server + ingestion.SECTION_META)
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

_env_candidates = [
    Path(__file__).resolve().parents[3] / ".env",  # repo root
    Path(__file__).resolve().parents[2] / ".env",  # backend/
    Path(__file__).resolve().parent / ".env",  # backend/app/gcp-agent/
]
for env_path in _env_candidates:
    if env_path.exists():
        load_dotenv(env_path, override=False)


def _resolve_credentials_path() -> None:
    """Normalize GOOGLE_APPLICATION_CREDENTIALS to an absolute path if set."""
    raw = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
    if not raw:
        return
    path = Path(raw).expanduser()
    if not path.is_absolute():
        repo_root = Path(__file__).resolve().parents[3]
        backend_root = Path(__file__).resolve().parents[2]
        candidate = (repo_root / path).resolve()
        if candidate.exists():
            os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = str(candidate)
            return
        candidate = (backend_root / path).resolve()
        if candidate.exists():
            os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = str(candidate)
            return
    elif path.exists():
            os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = str(path.resolve())


_resolve_credentials_path()


def _resolve_chroma_path() -> None:
    """Normalize CHROMA_CIS_PATH across repo-root and backend working directories."""
    raw = os.environ.get("CHROMA_CIS_PATH")
    if not raw:
        return
    path = Path(raw).expanduser()
    if path.is_absolute():
        if path.exists():
            os.environ["CHROMA_CIS_PATH"] = str(path.resolve())
        return
    repo_root = Path(__file__).resolve().parents[3]
    backend_root = Path(__file__).resolve().parents[2]
    for base in (backend_root, repo_root):
        candidate = (base / path).resolve()
        if candidate.exists() and (candidate / "chroma.sqlite3").exists():
            os.environ["CHROMA_CIS_PATH"] = str(candidate)
            return
    for base in (backend_root, repo_root):
        candidate = (base / path).resolve()
        if candidate.exists():
            os.environ["CHROMA_CIS_PATH"] = str(candidate)
            return


_resolve_chroma_path()

# Groq model id: https://console.groq.com/docs/models
GROQ_MODEL = os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")

# Prompt-size guardrails (char-based, approximate token budgeting).
_FULL_AUDIT_SECTION_THRESHOLD = 6
_CIS_MAX_CHARS_FULL_AUDIT = int(os.environ.get("CIS_MAX_CHARS_FULL_AUDIT", "12000"))
_CIS_MAX_CHARS_PARTIAL_AUDIT = int(os.environ.get("CIS_MAX_CHARS_PARTIAL_AUDIT", "20000"))
_RESOURCE_JSON_MAX_CHARS = int(os.environ.get("RESOURCE_JSON_MAX_CHARS", "18000"))


def _make_langfuse_config() -> dict[str, Any] | None:
    """
    Create a Langfuse RunnableConfig for LangChain/LangGraph callbacks.

    This traces LangGraph node boundaries and any LangChain Runnable steps.
    It will not automatically trace MCP calls unless we wrap them as LangChain Tools.
    """
    logger = logging.getLogger(__name__)
    public_key = os.environ.get("LANGFUSE_PUBLIC_KEY")
    secret_key = os.environ.get("LANGFUSE_SECRET_KEY")
    base_url = os.environ.get("LANGFUSE_HOST") or os.environ.get("LANGFUSE_BASE_URL")
    if not public_key or not secret_key:
        logger.info("Langfuse tracing disabled: missing LANGFUSE_PUBLIC_KEY or LANGFUSE_SECRET_KEY.")
        return None
    if base_url and not os.environ.get("LANGFUSE_HOST"):
        # Langfuse v2/v3 examples often use LANGFUSE_HOST, while some setups
        # store the same value as LANGFUSE_BASE_URL.
        os.environ["LANGFUSE_HOST"] = base_url
    try:
        from langfuse import Langfuse
        from langfuse.langchain import CallbackHandler
    except Exception as exc:
        logger.warning("Langfuse tracing disabled: could not import Langfuse SDK: %s", exc)
        return None

    session_id = uuid.uuid4().hex
    try:
        # Langfuse SDK v4 requires the client to be initialized before the
        # LangChain callback can retrieve it by public key.
        Langfuse(
            public_key=public_key,
            secret_key=secret_key,
            base_url=base_url,
        )
        handler = CallbackHandler(public_key=public_key)
    except Exception as exc:
        logger.warning("Langfuse tracing disabled: client initialization failed: %s", exc)
        return None

    return {
        "callbacks": [handler],
        "run_name": "gcp-cis-security-agent",
        "tags": ["gcp", "cis", "security-audit"],
        "metadata": {
            "langfuse_session_id": session_id,
            "agent": "gcp-cis-security-agent",
            "model": GROQ_MODEL,
            "langfuse_host": base_url or "default",
        },
    }


def _build_langchain_mcp_tools(
    *,
    tool_catalog: dict[str, dict[str, Any]],
    mcp_call: Callable[[str, dict[str, Any] | None], str],
) -> dict[str, StructuredTool]:
    """
    Wrap each MCP tool as a LangChain StructuredTool so Langfuse can trace tool execution.
    """
    tools: dict[str, StructuredTool] = {}

    for tool_name, meta in tool_catalog.items():
        description = str(meta.get("description", "")).strip() or tool_name

        # StructuredTool.from_function builds an input schema from the signature.
        def _make_fn(_tool_name: str) -> Callable[..., str]:
            def _fn(
                project_id: str | None = None,
                audit_scope: str | None = None,
                organization_id: str | None = None,
                folder_id: str | None = None,
            ) -> str:
                args: dict[str, Any] = {}
                if project_id:
                    args["project_id"] = project_id
                if audit_scope:
                    args["audit_scope"] = audit_scope
                if organization_id:
                    args["organization_id"] = organization_id
                if folder_id:
                    args["folder_id"] = folder_id
                return mcp_call(_tool_name, args)

            return _fn

        fn = _make_fn(tool_name)
        tools[tool_name] = StructuredTool.from_function(
            fn,
            name=tool_name,
            description=description,
        )

    return tools


def configure_quiet_runtime() -> None:
    """
    Reduce third-party noise in production-style runs (HF Hub, httpx, Google clients).
    Call once before running the graph or loading embedding/reranker models.
    """
    os.environ.setdefault("HF_HUB_DISABLE_PROGRESS_BARS", "1")
    os.environ.setdefault("HF_HUB_DISABLE_TELEMETRY", "1")
    os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
    os.environ.setdefault("TRANSFORMERS_VERBOSITY", "error")
    if not logging.root.handlers:
        logging.basicConfig(level=logging.WARNING)
    for name in (
        "httpx",
        "httpcore",
        "huggingface_hub",
        "urllib3",
        "urllib3.connectionpool",
        "google",
        "google.auth",
        "google.auth.transport",
        "chromadb",
        "sentence_transformers",
        "openai",
        "groq",
        "langchain_core",
        "langchain_groq",
        "langgraph",
    ):
        logging.getLogger(name).setLevel(logging.WARNING)


def _observation_inventory(resources: dict[str, Any]) -> list[str]:
    lines: list[str] = []
    for tool_name, payload in resources.items():
        if not isinstance(payload, dict):
            lines.append(f"  • {tool_name}: non-object payload ({type(payload).__name__})")
            continue
        errs = payload.get("errors") or []
        if errs:
            lines.append(f"  • {tool_name}: {len(errs)} error(s) in payload")
            for e in errs[:3]:
                if isinstance(e, dict):
                    msg = str(e.get("message", e))[:160]
                    lines.append(f"      - {e.get('context', '?')}: {msg}")
            if len(errs) > 3:
                lines.append(f"      - … and {len(errs) - 3} more")
        elif payload.get("tool_error"):
            lines.append(f"  • {tool_name}: tool_error — {payload.get('message', '')[:160]}")
        else:
            keys = [k for k in payload.keys() if k not in ("cis_section", "project_id", "source")]
            lines.append(f"  • {tool_name}: ok ({len(keys)} top-level field(s))")
    return lines or ["  • (no tool payloads)"]


def print_agent_step(
    node: str,
    delta: dict[str, Any],
    *,
    step_no: int,
    total: int = 5,
) -> None:
    """Thought / Action / Observation trace for CLI UX."""
    bar = "─" * 62
    print(f"\n{bar}\n Step {step_no}/{total} · {node}\n{bar}")

    if node == "plan_tools":
        print("Thought:")
        print("  Decide which MCP tools are needed for this user request.")
        print("\nAction:")
        planned = delta.get("selected_tools") or []
        planned_names = [p.get("name", "") for p in planned if isinstance(p, dict)]
        print(f"  Planned MCP tools: {', '.join(planned_names) or '(none)'}")
        notes = str(delta.get("planner_notes", "")).strip()
        if notes:
            print(f"  Planner notes: {notes}")
        print("\nObservation:")
        print(f"  Planned sections: {', '.join(delta.get('sections') or []) or 'n/a'}")

    elif node == "fetch_resources":
        print("Thought:")
        print("  Execute the planned MCP tools against GCP (read-only).")
        tools = delta.get("tools_used") or []
        secs = delta.get("sections") or []
        print("\nAction:")
        print(f"  MCP tools: {', '.join(tools) or '(none)'}")
        print(f"  CIS section hints: {', '.join(secs) or 'n/a'}")
        print("\nObservation:")
        for line in _observation_inventory(delta.get("resources_json") or {}):
            print(line)

    elif node == "retrieve_rules":
        cis = delta.get("cis_rules") or ""
        print("Thought:")
        print("  Pull CIS benchmark excerpts from Chroma (hybrid RAG) for those sections.")
        print("\nAction:")
        print("  retriever.retrieve(...) per section category")
        print("\nObservation:")
        print(f"  CIS context length: {len(cis)} characters (~{cis.count('### CIS')} excerpt block(s))")

    elif node == "analyze":
        body = delta.get("analysis_markdown") or ""
        print("Thought:")
        print("  Compare GCP JSON to CIS text; label Non-Compliant / Compliant / Not Assessed.")
        print("\nAction:")
        print(f"  ChatGroq(model={GROQ_MODEL!r})")
        print("\nObservation:")
        preview = body.strip().replace("\n", " ")[:220]
        print(f"  Analysis length: {len(body)} chars")
        if preview:
            print(f"  Preview: {preview}{'…' if len(body) > 220 else ''}")

    elif node == "report":
        rep = delta.get("report_markdown") or ""
        print("Thought:")
        print("  Prepend audit header (tools + section hints) to the analysis body.")
        print("\nAction:")
        print("  Assemble final Markdown report")
        print("\nObservation:")
        print(f"  Report length: {len(rep)} characters (ready to print below).")

    else:
        print("Thought: (node-specific trace not defined)")
        print("\nObservation:")
        if not delta:
            print("  Keys updated: none")
        else:
            print(f"  Keys updated: {', '.join(delta.keys())}")


def _stream_audit(
    app: Any,
    user_prompt: str,
    *,
    stream_trace: bool,
    langfuse_config: dict[str, Any] | None = None,
) -> str:
    report_md = ""
    step = 0
    node_order = (
        "route_intent",
        "plan_tools",
        "plan_tools_assist",
        "fetch_resources",
        "retrieve_rules",
        "analyze",
        "structure_findings",
        "report",
        "assist",
        "memory_update",
    )
    stream_kwargs: dict[str, Any] = {"stream_mode": "updates"}
    if langfuse_config:
        stream_kwargs["config"] = langfuse_config
    for chunk in app.stream(
        {"messages": [HumanMessage(content=user_prompt)]},
        **stream_kwargs,
    ):
        for node_name, delta in chunk.items():
            step += 1
            if stream_trace:
                try:
                    idx = node_order.index(node_name) + 1
                except ValueError:
                    idx = step
                print_agent_step(node_name, delta, step_no=idx, total=len(node_order))
            if node_name == "report":
                report_md = delta.get("report_markdown") or report_md
    return report_md


class AgentState(TypedDict):
    """State schema for CIS GCP audit agent."""
    messages: typing.Annotated[list[BaseMessage], add_messages]
    intent: str
    selected_tools: list[dict[str, Any]]
    tools_used: list[str]
    sections: list[str]
    planner_notes: str
    resources_json: dict[str, Any]
    cis_rules: str
    analysis_markdown: str
    structured_findings: list[dict[str, Any]]
    report_markdown: str


MemorySink = Callable[[dict[str, Any]], None]


def _is_full_audit_scope(sections: list[str]) -> bool:
    return len(sections) >= _FULL_AUDIT_SECTION_THRESHOLD


def _truncate_text(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    keep = max(0, max_chars - 32)
    return text[:keep].rstrip() + "\n\n...[truncated for prompt budget]..."


def _compact_for_prompt(
    value: Any,
    *,
    max_dict_items: int,
    max_list_items: int,
    max_string_chars: int,
    max_depth: int,
    _depth: int = 0,
) -> Any:
    if _depth >= max_depth:
        return "...[max depth reached]..."
    if isinstance(value, dict):
        compact: dict[str, Any] = {}
        items = list(value.items())
        for k, v in items[:max_dict_items]:
            compact[str(k)] = _compact_for_prompt(
                v,
                max_dict_items=max_dict_items,
                max_list_items=max_list_items,
                max_string_chars=max_string_chars,
                max_depth=max_depth,
                _depth=_depth + 1,
            )
        if len(items) > max_dict_items:
            compact["_truncated_keys"] = len(items) - max_dict_items
        return compact
    if isinstance(value, list):
        compact_list = [
            _compact_for_prompt(
                item,
                max_dict_items=max_dict_items,
                max_list_items=max_list_items,
                max_string_chars=max_string_chars,
                max_depth=max_depth,
                _depth=_depth + 1,
            )
            for item in value[:max_list_items]
        ]
        if len(value) > max_list_items:
            compact_list.append(f"...[{len(value) - max_list_items} more item(s)]...")
        return compact_list
    if isinstance(value, str):
        return value if len(value) <= max_string_chars else value[:max_string_chars] + "...[truncated]"
    return value


def _build_prompt_inventory(resources: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    variants = (
        # Preserve as much as possible first, then tighten aggressively.
        dict(max_dict_items=40, max_list_items=30, max_string_chars=500, max_depth=6),
        dict(max_dict_items=25, max_list_items=15, max_string_chars=280, max_depth=5),
        dict(max_dict_items=15, max_list_items=8, max_string_chars=180, max_depth=4),
    )
    for i, limits in enumerate(variants):
        compact = _compact_for_prompt(resources, **limits)
        rendered = json.dumps(compact, indent=2, default=str)
        if len(rendered) <= _RESOURCE_JSON_MAX_CHARS:
            return compact, i > 0
    # Last-resort hard cut keeps valid JSON while preserving top-level shape.
    fallback = _compact_for_prompt(
        resources,
        max_dict_items=10,
        max_list_items=5,
        max_string_chars=120,
        max_depth=3,
    )
    return fallback, True


def _resource_index_for_prompt(resources: dict[str, Any], *, limit: int = 120) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    seen: set[str] = set()
    for tool_name, payload in resources.items():
        if not isinstance(payload, dict):
            continue
        for key, value in payload.items():
            if not isinstance(value, list):
                continue
            for item in value:
                if not isinstance(item, dict):
                    continue
                uri = item.get("name") or item.get("resource")
                if not isinstance(uri, str):
                    continue
                if uri in seen:
                    continue
                seen.add(uri)
                project_id = ""
                if "/projects/" in uri:
                    project_id = uri.split("/projects/", maxsplit=1)[1].split("/", maxsplit=1)[0]
                elif uri.startswith("projects/"):
                    project_id = uri.split("/", maxsplit=2)[1]
                rows.append(
                    {
                        "tool": tool_name,
                        "list": str(key),
                        "project_id": project_id,
                        "type": str(item.get("assetType") or item.get("type") or ""),
                        "display_name": str(item.get("displayName") or uri.rsplit("/", 1)[-1]),
                        "uri": uri,
                    }
                )
                if len(rows) >= limit:
                    return rows
    return rows


def _scan_coverage_for_prompt(resources: dict[str, Any]) -> str:
    lines: list[str] = []
    for tool_name, payload in resources.items():
        if not isinstance(payload, dict):
            lines.append(f"- {tool_name}: invalid payload ({type(payload).__name__})")
            continue
        scope = payload.get("audit_scope") or payload.get("project_id") or "unknown scope"
        counts = []
        for key, value in payload.items():
            if isinstance(value, list) and key != "errors":
                counts.append(f"{key}={len(value)}")
        errors = payload.get("errors") or []
        status = "ok" if not errors and not payload.get("tool_error") else "data gaps/errors"
        line = f"- {tool_name}: {status}; scope={scope}; " + (", ".join(counts) or "no list fields")
        lines.append(line[:600])
        for err in errors[:3]:
            if isinstance(err, dict):
                lines.append(
                    f"  - gap: {err.get('context', '?')}: {str(err.get('message', err))[:240]}"
                )
        if len(errors) > 3:
            lines.append(f"  - gap: {len(errors) - 3} additional error(s)")
    return "\n".join(lines) if lines else "- No live inventory tools were run."


def _extract_user_question(text: str) -> str:
    marker = "user question:"
    lower = text.lower()
    idx = lower.rfind(marker)
    if idx == -1:
        return text.strip()
    return text[idx + len(marker) :].strip()


def _last_user_text(state: AgentState) -> str:
    for m in reversed(state.get("messages", [])):
        if isinstance(m, HumanMessage):
            return _extract_user_question(str(m.content))
    return ""


def _route_intent(user_text: str) -> str:
    t = user_text.lower().strip()
    if any(
        phrase in t
        for phrase in (
            "full audit",
            "complete audit",
            "run audit",
            "generate report",
            "full report",
            "audit report",
            "cis report",
            "scan report",
        )
    ):
        return "report"
    if any(
        phrase in t
        for phrase in (
            "how do i fix",
            "how to fix",
            "remediate",
            "remediation",
            "what should i do",
            "how do we fix",
            "recommendation",
            "explain",
            "help me",
        )
    ):
        return "assist"
    return "assist"


def _select_tools_and_sections(user_text: str) -> tuple[list[str], list[str]]:
    t = user_text.lower().strip()

    # Full benchmark: all eight major sections / MCP tools
    if any(
        phrase in t
        for phrase in (
            "full audit",
            "complete audit",
            "all cis sections",
            "all eight sections",
            "all 8 sections",
            "entire benchmark",
            "whole benchmark",
            "section 1 through 8",
            "sections 1 through 8",
            "1 through 8",
            "audit everything",
            "full cis audit",
        )
    ):
        return (
            [pair[1] for pair in _CIS_TOOLS_IN_ORDER],
            [pair[0] for pair in _CIS_TOOLS_IN_ORDER],
        )

    tools: list[str] = []
    sections: list[str] = []

    if any(
        k in t
        for k in (
            "iam",
            "identity",
            "service account",
            "section 1",
            "cis 1",
            "cis section 1",
        )
    ):
        tools.append("get_iam_policy")
        sections.append("1")
    if any(
        k in t
        for k in (
            "logging",
            "monitoring",
            "log sink",
            "log sinks",
            "audit log",
            "cloud logging",
            "log metric",
            "alert policy",
            "section 2",
            "cis 2",
            "cis section 2",
        )
    ):
        tools.append("get_logging_monitoring_config")
        sections.append("2")
    if any(
        k in t
        for k in (
            "network",
            "vpc",
            "firewall",
            "flow log",
            "section 3",
            "cis 3",
            "cis section 3",
        )
    ):
        tools.append("get_network_config")
        sections.append("3")
    if any(
        k in t
        for k in (
            "compute",
            "vm",
            "instance",
            "instances",
            "shield",
            "shielded",
            "public ip",
            "virtual machine",
            "section 4",
            "cis 4",
            "cis section 4",
        )
    ):
        tools.append("get_compute_info")
        sections.append("4")
    if any(
        k in t
        for k in (
            "storage",
            "bucket",
            "gcs",
            "cloud storage",
            "section 5",
            "cis 5",
            "cis section 5",
        )
    ):
        tools.append("get_storage_metadata")
        sections.append("5")
    if any(
        k in t
        for k in (
            "cloud sql",
            "sql instance",
            "mysql",
            "postgres",
            "postgresql",
            "section 6",
            "cis 6",
            "cis section 6",
        )
    ):
        tools.append("get_cloud_sql_inventory")
        sections.append("6")
    if any(
        k in t
        for k in (
            "bigquery",
            "bq dataset",
            "bq ",
            "section 7",
            "cis 7",
            "cis section 7",
        )
    ):
        tools.append("get_bigquery_inventory")
        sections.append("7")
    if any(
        k in t
        for k in (
            "dataproc",
            "spark cluster",
            "hadoop",
            "section 8",
            "cis 8",
            "cis section 8",
        )
    ):
        tools.append("get_dataproc_inventory")
        sections.append("8")

    if not tools:
        tools = ["get_iam_policy", "get_network_config"]
        sections = ["1", "3"]

    # de-dupe preserving order
    seen: set[str] = set()
    utools: list[str] = []
    for x in tools:
        if x not in seen:
            seen.add(x)
            utools.append(x)
    seen_s: set[str] = set()
    usec: list[str] = []
    for x in sections:
        if x not in seen_s:
            seen_s.add(x)
            usec.append(x)
    return utools, usec


def _extract_first_json_object(text: str) -> dict[str, Any] | None:
    """Best-effort extractor for a top-level JSON object from model text output."""
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    blob = text[start : end + 1]
    try:
        parsed = json.loads(blob)
        return parsed if isinstance(parsed, dict) else None
    except Exception:
        return None


def _extract_first_json_array(text: str) -> list[dict[str, Any]] | None:
    start = text.find("[")
    end = text.rfind("]")
    if start == -1 or end == -1 or end <= start:
        return None
    blob = text[start : end + 1]
    try:
        parsed = json.loads(blob)
        if isinstance(parsed, list):
            return [x for x in parsed if isinstance(x, dict)]
    except Exception:
        return None
    return None


def _normalize_selected_tools(
    planned: list[dict[str, Any]] | None,
    *,
    tool_catalog: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """Validate/normalize tool plan against MCP tool catalog."""
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    if not planned:
        return out
    for row in planned:
        if not isinstance(row, dict):
            continue
        name = str(row.get("name", "")).strip()
        if not name or name in seen:
            continue
        if name not in tool_catalog:
            continue
        args = row.get("arguments")
        if not isinstance(args, dict):
            args = {}
        # Keep arguments shallow+JSON-safe.
        safe_args: dict[str, Any] = {}
        for k, v in args.items():
            if isinstance(k, str) and (isinstance(v, (str, int, float, bool)) or v is None):
                value = str(v).strip() if v is not None else None
                if value and _is_valid_tool_scope_arg(k, value):
                    safe_args[k] = v
        out.append({"name": name, "arguments": safe_args})
        seen.add(name)
    return out


def _is_valid_tool_scope_arg(key: str, value: str) -> bool:
    """Reject planner-invented placeholders like organizations/ORG_ID."""
    upper = value.upper()
    if any(token in upper for token in ("ORG_ID", "ORGANIZATION_ID", "FOLDER_ID", "PROJECT_ID", "YOUR_")):
        return False
    if key == "organization_id":
        return value.isdigit()
    if key == "folder_id":
        return value.isdigit()
    if key == "audit_scope":
        if value.startswith("organizations/"):
            return value.split("/", maxsplit=1)[1].isdigit()
        if value.startswith("folders/"):
            return value.split("/", maxsplit=1)[1].isdigit()
        if value.startswith("projects/"):
            return bool(value.split("/", maxsplit=1)[1].strip())
        return False
    if key == "project_id":
        return bool(value)
    return True


def node_plan_tools(
    state: AgentState,
    *,
    tool_catalog: dict[str, dict[str, Any]],
    langfuse_config: dict[str, Any] | None = None,
    allow_empty: bool = False,
) -> dict[str, Any]:
    """
    LLM-driven tool planner using MCP catalog.
    Falls back to deterministic keyword routing if the planner output is invalid.
    """
    user_text = _last_user_text(state)
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        if allow_empty:
            return {
                "selected_tools": [],
                "tools_used": [],
                "sections": [],
                "planner_notes": "LLM planner disabled (missing GROQ_API_KEY); no tools selected.",
            }
        fallback_tools, fallback_sections = _select_tools_and_sections(user_text)
        selected = [{"name": n, "arguments": {}} for n in fallback_tools]
        return {
            "selected_tools": selected,
            "tools_used": fallback_tools,
            "sections": fallback_sections,
            "planner_notes": "LLM planner disabled (missing GROQ_API_KEY); used keyword fallback.",
        }

    planner_llm = ChatGroq(
        model=GROQ_MODEL,
        temperature=0,
        groq_api_key=api_key,
        max_tokens=800,
    )
    allow_empty_note = (
        "- If no tools are needed, return an empty selected_tools array and sections [].\n"
        if allow_empty
        else ""
    )
    prompt = (
        "You are a security audit planner. Select the minimal set of MCP tools needed to answer the user request.\n"
        "Available tools (JSON):\n"
        f"{json.dumps(tool_catalog, indent=2)}\n\n"
        "Rules:\n"
        "- Only choose tools from the provided catalog.\n"
        "- Use empty arguments {} unless a project, folder, or organization scope is explicitly requested.\n"
        "- For an organization-wide audit, pass {'audit_scope':'organizations/ORG_ID'} or {'organization_id':'ORG_ID'}.\n"
        "- For a folder-wide audit, pass {'audit_scope':'folders/FOLDER_ID'} or {'folder_id':'FOLDER_ID'}.\n"
        "- For a project-only audit, pass {'project_id':'PROJECT_ID'}.\n"
        f"{allow_empty_note}"
        "- Return pure JSON only (no markdown) with schema:\n"
        '{'
        '"selected_tools":[{"name":"tool_name","arguments":{}}],'
        '"sections":["1","5"],'
        '"notes":"short reason"'
        '}\n'
        f"User request: {user_text}"
    )
    resp = planner_llm.invoke(
        [HumanMessage(content=prompt)],
        config=langfuse_config or {},
    )
    raw = resp.content if isinstance(resp.content, str) else str(resp.content)
    parsed = _extract_first_json_object(raw) or {}
    selected = _normalize_selected_tools(
        parsed.get("selected_tools") if isinstance(parsed, dict) else None,
        tool_catalog=tool_catalog,
    )
    sections = parsed.get("sections") if isinstance(parsed, dict) else None
    sec_list = [str(s) for s in sections] if isinstance(sections, list) else []
    sec_list = [s for s in sec_list if s in _SECTION_CATEGORY]

    if not selected and not allow_empty:
        fallback_tools, fallback_sections = _select_tools_and_sections(user_text)
        selected = [{"name": n, "arguments": {}} for n in fallback_tools]
        sec_list = fallback_sections
        notes = "Planner output invalid; used keyword fallback."
    elif not selected and allow_empty:
        notes = "Planner selected no tools for this request."
    else:
        if not sec_list:
            sec_list = [
                tool_catalog[t["name"]]["cis_section"]
                for t in selected
                if t["name"] in tool_catalog
            ]
        notes = str(parsed.get("notes", "Planned with LLM")).strip()
    return {
        "selected_tools": selected,
        "tools_used": [t["name"] for t in selected],
        "sections": sec_list,
        "planner_notes": notes,
    }


def node_fetch_resources(
    state: AgentState,
    *,
    langchain_tools_by_name: dict[str, StructuredTool],
    langfuse_config: dict[str, Any] | None,
    mcp_call: Callable[[str, dict[str, Any] | None], str],
) -> dict[str, Any]:
    selected = state.get("selected_tools") or []
    if not selected:
        if state.get("intent") == "assist":
            return {
                "resources_json": {},
                "tools_used": [],
                "sections": state.get("sections") or [],
            }
        fallback_tools, fallback_sections = _select_tools_and_sections(_last_user_text(state))
        selected = [{"name": n, "arguments": {}} for n in fallback_tools]
        state_tools = fallback_tools
        state_sections = fallback_sections
    else:
        state_tools = [str(x.get("name", "")) for x in selected if isinstance(x, dict)]
        state_sections = state.get("sections") or []
    resources: dict[str, Any] = {}
    for row in selected:
        if not isinstance(row, dict):
            continue
        name = str(row.get("name", "")).strip()
        args = row.get("arguments") if isinstance(row.get("arguments"), dict) else {}
        if not name:
            continue
        tool = langchain_tools_by_name.get(name)
        if tool is not None:
            raw = tool.invoke(args, config=langfuse_config or {})
        else:
            raw = mcp_call(name, args)
        try:
            resources[name] = json.loads(raw)
        except json.JSONDecodeError:
            resources[name] = {"parse_error": True, "raw": raw}
    return {
        "resources_json": resources,
        "tools_used": state_tools,
        "sections": state_sections,
    }


def node_route_intent(state: AgentState) -> dict[str, Any]:
    user_text = _last_user_text(state)
    return {"intent": _route_intent(user_text)}


def node_assist(
    state: AgentState,
    *,
    langfuse_config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        md = "## Response\n\nMissing `GROQ_API_KEY` in environment (.env)."
        return {"report_markdown": md, "messages": [AIMessage(content=md)]}

    user_text = _last_user_text(state)
    resources = state.get("resources_json") or {}
    compact_resources, inventory_compacted = _build_prompt_inventory(resources)
    cis_rules = state.get("cis_rules") or ""
    has_resources = bool(resources)

    system = SystemMessage(
        content=(
            "You are a helpful GCP security assistant. Answer the user's question in a ChatGPT-like tone. "
            "Provide short, step-by-step remediation guidance. "
            "If evidence is missing, say what data is missing and suggest next checks. "
            "When you cite CIS controls, include the control ID inline."
        )
    )
    human = HumanMessage(
        content=(
            f"User question: {user_text}\n\n"
            f"Scan coverage and tool status:\n{_scan_coverage_for_prompt(resources)}\n\n"
            f"CIS benchmark excerpts:\n{cis_rules}\n\n"
            + (
                f"GCP inventory (JSON):\n```json\n{json.dumps(compact_resources, indent=2, default=str)}\n```\n\n"
                if has_resources
                else "No live inventory JSON was retrieved for this question.\n\n"
            )
            + (
                "Note: Inventory was compacted to stay within model request limits.\n"
                if inventory_compacted
                else ""
            )
        )
    )

    llm = ChatGroq(
        model=GROQ_MODEL,
        temperature=0.2,
        groq_api_key=api_key,
    )
    resp = llm.invoke([system, human], config=langfuse_config or {})
    text = resp.content if isinstance(resp.content, str) else str(resp.content)
    return {"report_markdown": text, "messages": [AIMessage(content=text)]}


def node_retrieve_rules(state: AgentState) -> dict[str, Any]:
    user_text = _last_user_text(state)
    sections = state.get("sections") or ["1"]
    is_full_audit = _is_full_audit_scope(sections)
    rag_query = user_text.strip() or "GCP CIS security controls relevant to collected resources"
    persist = os.environ.get("CHROMA_CIS_PATH", DEFAULT_PERSIST)
    chunks: list[str] = []
    try:
        retriever = get_retriever(persist)
        if len(sections) == 1:
            cat = _SECTION_CATEGORY.get(sections[0])
            rows = retriever.retrieve(rag_query, top_k=6, category=cat)
            chunks.append(format_retrieval_for_prompt(rows))
        else:
            per_section_top_k = 2 if is_full_audit else 3
            for sec in sections:
                cat = _SECTION_CATEGORY.get(sec)
                rows = retriever.retrieve(rag_query, top_k=per_section_top_k, category=cat)
                chunks.append(
                    f"## CIS domain hint: section {sec} ({cat or 'general'})\n"
                    + format_retrieval_for_prompt(rows)
                )
    except Exception as exc:
        chunks.append(
            f"(CIS retrieval failed: {exc}. "
            f"Run `python vector_store.py cis_pdf/<benchmark>.pdf` after `pip install -r requirements.txt`.)"
        )
    max_cis_chars = _CIS_MAX_CHARS_FULL_AUDIT if is_full_audit else _CIS_MAX_CHARS_PARTIAL_AUDIT
    cis_text = _truncate_text("\n\n".join(chunks), max_cis_chars)
    return {"cis_rules": cis_text}


def node_analyze(
    state: AgentState,
    *,
    langfuse_config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        md = "## Analysis\n\nMissing `GROQ_API_KEY` in environment (.env)."
        return {"analysis_markdown": md, "messages": [AIMessage(content=md)]}

    resources = state.get("resources_json") or {}
    compact_resources, inventory_compacted = _build_prompt_inventory(resources)
    resource_index = _resource_index_for_prompt(resources)
    cis_rules = state.get("cis_rules") or ""

    permission_notes: list[str] = []
    seen_note: set[str] = set()
    for tool_name, payload in resources.items():
        if isinstance(payload, dict):
            errs = payload.get("errors") or []
            for e in errs:
                if isinstance(e, dict):
                    ctx = e.get("context", tool_name)
                    msg = str(e.get("message", e))
                    line = f"- **{ctx}**: {msg}"
                    if line not in seen_note:
                        seen_note.add(line)
                        permission_notes.append(line)
            if payload.get("tool_error"):
                line = f"- **{tool_name}**: {payload.get('message', payload)}"
                if line not in seen_note:
                    seen_note.add(line)
                    permission_notes.append(line)

    system = SystemMessage(
        content=(
            "You are an expert GCP Cloud Security Engineer performing a read-only CIS-style audit.\n"
            "You MUST base conclusions only on:\n"
            "1) The JSON resource inventory provided, and\n"
            "2) The CIS benchmark excerpts provided.\n\n"
            "For each potential issue, state whether it is **Non-Compliant**, **Compliant**, "
            "or **Not Assessed** (insufficient data).\n"
            "Prioritize explicit **Non-Compliant** findings when the inventory clearly violates "
            "a cited CIS recommendation.\n"
            "If the inventory shows errors (permission denied, API disabled, forbidden, etc.), "
            "reflect them under **Data gaps** only — never invent resource state.\n"
            "If a tool marks a control as manual_not_directly_testable, not_covered, or missing evidence, "
            "classify it as **Not Assessed** and place it in **Data gaps**, not **Non-Compliant**.\n"
            "CIS GCP Foundation numbering: §1 IAM, §2 Logging, §3 Networking, §4 Virtual Machines, "
            "§5 Storage, §6 Cloud SQL, §7 BigQuery, §8 Dataproc. Only discuss gaps for controls that "
            "match the tools that were run and the evidence in the JSON; do not ask for VM or other "
            "resource types that were not part of this audit scope.\n\n"
            "FORMATTING (mandatory):\n"
            "- Use exactly four sections, in order, with these headings only once each: "
            "## Summary, ## Non-Compliant findings, ## Other observations, ## Data gaps.\n"
            "- In ## Summary, explicitly mention the audit scope and the MCP tools/lists scanned.\n"
            "- In **Non-Compliant findings**, begin each bullet with a CIS rule id like 'CIS 1.1' or 'CIS 1.1.1'.\n"
            "- For each Non-Compliant finding, include the exact resource URI or say project/org-level finding.\n"
            "- Only mark Non-Compliant when the JSON proves the issue. Otherwise use Other observations or Data gaps.\n"
            "- Do not repeat paragraphs, bullet lists, or closing lines. No duplicated "
            "\"To address these gaps\" blocks.\n"
            "- Under **Data gaps**, use at most 6 short bullets unless the user asked for exhaustive detail.\n"
            "- Stop writing immediately after **Data gaps**; do not restate earlier sections."
        )
    )
    human = HumanMessage(
        content=(
            "### Scan coverage and tool status\n"
            f"{_scan_coverage_for_prompt(resources)}\n\n"
            "### Resource index (use exact URI when naming affected resources)\n"
            f"```json\n{json.dumps(resource_index, indent=2, default=str)}\n```\n\n"
            f"### CIS benchmark excerpts\n{cis_rules}\n\n"
            f"### GCP inventory (JSON)\n```json\n{json.dumps(compact_resources, indent=2, default=str)}\n```\n\n"
            "### Permission / API notes\n"
            + (
                "\n".join(permission_notes)
                if permission_notes
                else "_No tool-level permission errors recorded._"
            )
            + (
                "\n\n_Note: Inventory was compacted to stay within model request limits._"
                if inventory_compacted
                else ""
            )
        )
    )
    
    llm = ChatGroq(
        model=GROQ_MODEL,
        temperature=0,
        groq_api_key=api_key,
        
    )
    resp = llm.invoke([system, human], config=langfuse_config or {})
    text = resp.content if isinstance(resp.content, str) else str(resp.content)
    return {"analysis_markdown": text, "messages": [AIMessage(content=text)]}


def node_structured_findings(
    state: AgentState,
    *,
    langfuse_config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        return {"structured_findings": []}

    resources = state.get("resources_json") or {}
    compact_resources, inventory_compacted = _build_prompt_inventory(resources)
    resource_index = _resource_index_for_prompt(resources, limit=180)
    cis_rules = state.get("cis_rules") or ""
    analysis = state.get("analysis_markdown") or ""

    system = SystemMessage(
        content=(
            "You extract structured GCP security findings from evidence.\n"
            "Return ONLY a JSON array. Each item must have:\n"
            "- cis_rule_id (string like '1.7')\n"
            "- severity (CRITICAL|HIGH|MEDIUM|LOW)\n"
            "- description (short sentence)\n"
            "- remediation_steps (1-2 sentences)\n"
            "- resource_gcp_uri (string or null)\n"
            "Rules:\n"
            "- Use only evidence from JSON inventory and CIS excerpts.\n"
            "- resource_gcp_uri MUST be either null or an exact uri copied from the provided Resource index.\n"
            "- If no exact Resource index uri matches the finding, set resource_gcp_uri to null.\n"
            "- remediation_steps must be a concise overview of the matching CIS Remediation excerpt, not a pointer to another report.\n"
            "- Do not extract findings for manual_not_directly_testable, not_covered, missing evidence, or Not Assessed controls.\n"
            "- If evidence is insufficient for a resource-specific finding, use null for resource_gcp_uri instead of guessing.\n"
            "- If evidence is insufficient for the security conclusion itself, return [] instead of guessing.\n"
            "- Do not include markdown or commentary."
        )
    )
    human = HumanMessage(
        content=(
            f"Resource index:\n```json\n{json.dumps(resource_index, indent=2, default=str)}\n```\n\n"
            f"Scan coverage and tool status:\n{_scan_coverage_for_prompt(resources)}\n\n"
            f"CIS benchmark excerpts:\n{cis_rules}\n\n"
            f"Analysis:\n{analysis}\n\n"
            f"GCP inventory (JSON):\n```json\n{json.dumps(compact_resources, indent=2, default=str)}\n```\n\n"
            + (
                "Note: Inventory was compacted to stay within model request limits.\n"
                if inventory_compacted
                else ""
            )
        )
    )

    llm = ChatGroq(
        model=GROQ_MODEL,
        temperature=0,
        groq_api_key=api_key
    )
    resp = llm.invoke([system, human], config=langfuse_config or {})
    raw = resp.content if isinstance(resp.content, str) else str(resp.content)
    parsed = _extract_first_json_array(raw) or []
    return {"structured_findings": parsed}


def node_report(state: AgentState) -> dict[str, Any]:
    tools = state.get("tools_used") or []
    sections = state.get("sections") or []
    body = state.get("analysis_markdown") or "_No analysis._"
    header = (
        "# GCP CIS-oriented security audit\n\n"
        f"**Tools invoked:** {', '.join(tools) or 'none'}\n\n"
        f"**CIS section hints:** {', '.join(sections) or 'n/a'}\n\n"
        "---\n\n"
    )
    report = header + body
    return {"report_markdown": report}


def node_memory_update(
    state: AgentState,
    *,
    memory_sink: MemorySink | None = None,
) -> dict[str, Any]:
    if memory_sink is None:
        return {}
    payload = {
        "report_markdown": state.get("report_markdown", ""),
        "analysis_markdown": state.get("analysis_markdown", ""),
        "tools_used": state.get("tools_used", []),
        "sections": state.get("sections", []),
    }
    memory_sink(payload)
    return {}


def build_graph(
    *,
    mcp_call: Callable[[str, dict[str, Any] | None], str] | None = None,
    mcp_tool_catalog: dict[str, dict[str, Any]] | None = None,
    langfuse_config: dict[str, Any] | None = None,
    memory_sink: MemorySink | None = None,
) -> StateGraph:
    mcp_call_fn = mcp_call or call_mcp_tool
    tool_catalog = mcp_tool_catalog or get_tool_catalog()
    langchain_tools_by_name = _build_langchain_mcp_tools(
        tool_catalog=tool_catalog,
        mcp_call=mcp_call_fn,
    )
    g = StateGraph(AgentState)
    g.add_node("route_intent", node_route_intent)
    g.add_node(
        "plan_tools",
        lambda state: node_plan_tools(
            state,
            tool_catalog=tool_catalog,
            langfuse_config=langfuse_config,
            allow_empty=False,
        ),
    )
    g.add_node(
        "plan_tools_assist",
        lambda state: node_plan_tools(
            state,
            tool_catalog=tool_catalog,
            langfuse_config=langfuse_config,
            allow_empty=True,
        ),
    )
    g.add_node(
        "fetch_resources",
        lambda state: node_fetch_resources(
            state,
            langchain_tools_by_name=langchain_tools_by_name,
            langfuse_config=langfuse_config,
            mcp_call=mcp_call_fn,
        ),
    )
    g.add_node("retrieve_rules", node_retrieve_rules)
    g.add_node(
        "analyze",
        lambda state: node_analyze(state, langfuse_config=langfuse_config),
    )
    g.add_node(
        "structure_findings",
        lambda state: node_structured_findings(state, langfuse_config=langfuse_config),
    )
    g.add_node("report", node_report)
    g.add_node(
        "assist",
        lambda state: node_assist(state, langfuse_config=langfuse_config),
    )
    g.add_node(
        "memory_update",
        lambda state: node_memory_update(state, memory_sink=memory_sink),
    )
    g.add_edge(START, "route_intent")
    g.add_conditional_edges(
        "route_intent",
        lambda state: state.get("intent", "assist"),
        {
            "report": "plan_tools",
            "assist": "plan_tools_assist",
        },
    )
    g.add_edge("plan_tools", "fetch_resources")
    g.add_conditional_edges(
        "plan_tools_assist",
        lambda state: "fetch_resources" if state.get("selected_tools") else "retrieve_rules",
        {
            "fetch_resources": "fetch_resources",
            "retrieve_rules": "retrieve_rules",
        },
    )
    g.add_edge("fetch_resources", "retrieve_rules")
    g.add_conditional_edges(
        "retrieve_rules",
        lambda state: "analyze" if state.get("intent") == "report" else "assist",
        {
            "analyze": "analyze",
            "assist": "assist",
        },
    )
    g.add_edge("analyze", "structure_findings")
    g.add_edge("structure_findings", "report")
    g.add_edge("report", "memory_update")
    g.add_edge("assist", "memory_update")
    g.add_edge("memory_update", END)
    return g.compile()


def run_audit(
    user_prompt: str,
    *,
    stream_trace: bool | None = None,
    quiet: bool = True,
    mcp_call: Callable[[str, dict[str, Any] | None], str] | None = None,
    mcp_tool_catalog: dict[str, dict[str, Any]] | None = None,
    memory_sink: MemorySink | None = None,
) -> str:
    """
    Run the full graph; returns final Markdown report.

    ``stream_trace`` defaults from env ``CIS_AGENT_TRACE`` (``1`` = show Thought/Action/Observation).
    ``quiet`` lowers log noise from httpx, Hugging Face Hub, Google clients, etc.
    """
    if stream_trace is None:
        stream_trace = os.environ.get("CIS_AGENT_TRACE", "1").lower() in (
            "1",
            "true",
            "yes",
        )
    if quiet:
        configure_quiet_runtime()

    langfuse_config = _make_langfuse_config()

    app = build_graph(
        mcp_call=mcp_call,
        mcp_tool_catalog=mcp_tool_catalog,
        langfuse_config=langfuse_config,
        memory_sink=memory_sink,
    )
    report_md = _stream_audit(
        app,
        user_prompt,
        stream_trace=stream_trace,
        langfuse_config=langfuse_config,
    )
    if not report_md.strip():
        if langfuse_config:
            out = app.invoke(
                {"messages": [HumanMessage(content=user_prompt)]},
                config=langfuse_config,
            )
        else:
            out = app.invoke({"messages": [HumanMessage(content=user_prompt)]})
        report_md = out.get("report_markdown", "") or ""
    return report_md


def run_audit_state(
    user_prompt: str,
    *,
    quiet: bool = True,
    mcp_call: Callable[[str, dict[str, Any] | None], str] | None = None,
    mcp_tool_catalog: dict[str, dict[str, Any]] | None = None,
    memory_sink: MemorySink | None = None,
) -> dict[str, Any]:
    """
    Run the full graph and return final state dictionary (resources_json, analysis_markdown, etc.).
    Useful for API services that need structured persistence beyond the Markdown report.
    """
    if quiet:
        configure_quiet_runtime()

    langfuse_config = _make_langfuse_config()
    app = build_graph(
        mcp_call=mcp_call,
        mcp_tool_catalog=mcp_tool_catalog,
        langfuse_config=langfuse_config,
        memory_sink=memory_sink,
    )
    if langfuse_config:
        return app.invoke(
            {"messages": [HumanMessage(content=user_prompt)]},
            config=langfuse_config,
        )
    return app.invoke({"messages": [HumanMessage(content=user_prompt)]})


if __name__ == "__main__":
    import sys

    prompt = (
        " ".join(sys.argv[1:]).strip()
        or "Audit my IAM and Networking for CIS compliance."
    )
    width = 62
    sep = "=" * width
    print(sep)
    print(" CIS GCP Security Auditor".ljust(width - 1))
    print(sep)
    print(f"\nGoal: {prompt}\n")
    report = run_audit(prompt)
    print(f"\n{sep}\n FINAL REPORT\n{sep}\n")
    print(report)
