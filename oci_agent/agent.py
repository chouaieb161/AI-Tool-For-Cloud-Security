"""LangGraph OCI agent: fetch OCI state via MCP tools, retrieve CIS OCI rules (RAG),
analyze with Groq (default: Llama 3.3 70B), emit Markdown report + structured findings.

Mirrors app.gcp-agent.agent but uses OCI MCP tools and OCI CIS retriever.
"""
from __future__ import annotations

import json
import logging
import os
import uuid
from pathlib import Path
from typing import Any, Callable, TypedDict
import typing

from dotenv import load_dotenv
from langchain_core.messages import BaseMessage, HumanMessage
from langchain_core.tools import StructuredTool
from langchain_groq import ChatGroq
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages

from app.oci_agent.mcp.oci_mcp_server import call_oci_mcp_tool
from app.oci_agent.rag.retriever import format_retrieval_for_prompt, get_oci_retriever
from app.oci_agent.rag.vector_store import DEFAULT_PERSIST

# CIS OCI Foundations Benchmark major section -> retriever category (6-category mapping)
_SECTION_CATEGORY = {
    "1": "Identity and Access Management",
    "2": "Networking",
    "3": "Logging and Monitoring",
    "4": "Compute",
    "5": "Storage",
    "6": "Asset Management",
}

# Tools in CIS §1–§8 order (matches OCI MCP server)
_CIS_TOOLS_IN_ORDER: list[tuple[str, str]] = [
    ("1", "get_oci_identity_inventory"),
    ("2", "get_oci_network_inventory"),
    ("3", "get_oci_logging_inventory"),
    ("4", "get_oci_compute_inventory"),
    ("5", "get_oci_storage_inventory"),
    ("6", "get_oci_database_inventory"),
    ("7", "get_oci_governance_inventory"),
    ("8", "get_oci_security_inventory"),
]

# Tool catalog (name -> meta) for planner
def _build_tool_catalog() -> dict[str, dict[str, Any]]:
    catalog: dict[str, dict[str, Any]] = {}
    for section, tool_name in _CIS_TOOLS_IN_ORDER:
        catalog[tool_name] = {
            "name": tool_name,
            "description": f"Fetch OCI {tool_name.replace('get_oci_','').replace('_inventory','')} inventory (CIS section {section}).",
            "cis_section": section,
        }
    return catalog


_env_candidates = [
    Path(__file__).resolve().parents[3] / ".env",  # repo root
    Path(__file__).resolve().parents[2] / ".env",  # backend/
    Path(__file__).resolve().parent / ".env",
]
for env_path in _env_candidates:
    if env_path.exists():
        load_dotenv(env_path, override=False)


def _resolve_oci_config_path() -> None:
    """Normalize OCI_CONFIG_FILE to an absolute path if set."""
    raw = os.environ.get("OCI_CONFIG_FILE")
    if not raw:
        return
    path = Path(raw).expanduser()
    if not path.is_absolute():
        repo_root = Path(__file__).resolve().parents[3]
        backend_root = Path(__file__).resolve().parents[2]
        for base in (repo_root, backend_root, Path.home()):
            candidate = (base / path).resolve()
            if candidate.exists():
                os.environ["OCI_CONFIG_FILE"] = str(candidate)
                return
    elif path.exists():
        os.environ["OCI_CONFIG_FILE"] = str(path.resolve())


_resolve_oci_config_path()


def _resolve_chroma_path() -> None:
    raw = os.environ.get("OCI_CHROMA_CIS_PATH")
    if not raw:
        return
    path = Path(raw).expanduser()
    if path.is_absolute():
        if path.exists():
            os.environ["OCI_CHROMA_CIS_PATH"] = str(path.resolve())
        return
    repo_root = Path(__file__).resolve().parents[3]
    backend_root = Path(__file__).resolve().parents[2]
    for base in (backend_root, repo_root):
        candidate = (base / path).resolve()
        if candidate.exists():
            os.environ["OCI_CHROMA_CIS_PATH"] = str(candidate)
            return


_resolve_chroma_path()

GROQ_MODEL = os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")

_FULL_AUDIT_SECTION_THRESHOLD = 6
_CIS_MAX_CHARS_FULL_AUDIT = int(os.environ.get("OCI_CIS_MAX_CHARS_FULL_AUDIT", "12000"))
_CIS_MAX_CHARS_PARTIAL_AUDIT = int(os.environ.get("OCI_CIS_MAX_CHARS_PARTIAL_AUDIT", "20000"))
_RESOURCE_JSON_MAX_CHARS = int(os.environ.get("OCI_RESOURCE_JSON_MAX_CHARS", "18000"))


def configure_quiet_runtime() -> None:
    os.environ.setdefault("HF_HUB_DISABLE_PROGRESS_BARS", "1")
    os.environ.setdefault("HF_HUB_DISABLE_TELEMETRY", "1")
    os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
    os.environ.setdefault("TRANSFORMERS_VERBOSITY", "error")
    if not logging.root.handlers:
        logging.basicConfig(level=logging.WARNING)
    for name in (
        "httpx", "httpcore", "huggingface_hub", "urllib3", "oci", "chromadb",
        "sentence_transformers", "openai", "groq", "langchain_core",
        "langchain_groq", "langgraph",
    ):
        logging.getLogger(name).setLevel(logging.WARNING)


def _make_langfuse_config() -> dict[str, Any] | None:
    public_key = os.environ.get("LANGFUSE_PUBLIC_KEY")
    secret_key = os.environ.get("LANGFUSE_SECRET_KEY")
    base_url = os.environ.get("LANGFUSE_HOST") or os.environ.get("LANGFUSE_BASE_URL")
    if not public_key or not secret_key:
        return None
    if base_url and not os.environ.get("LANGFUSE_HOST"):
        os.environ["LANGFUSE_HOST"] = base_url
    try:
        from langfuse import Langfuse
        from langfuse.langchain import CallbackHandler
    except Exception:
        return None
    session_id = uuid.uuid4().hex
    try:
        Langfuse(public_key=public_key, secret_key=secret_key, base_url=base_url)
        handler = CallbackHandler(public_key=public_key)
    except Exception:
        return None
    return {
        "callbacks": [handler],
        "run_name": "oci-cis-security-agent",
        "tags": ["oci", "cis", "security-audit"],
        "metadata": {
            "langfuse_session_id": session_id,
            "agent": "oci-cis-security-agent",
            "model": GROQ_MODEL,
            "langfuse_host": base_url or "default",
        },
    }


def _build_langchain_mcp_tools(
    *,
    tool_catalog: dict[str, dict[str, Any]],
    mcp_call: Callable[[str, dict[str, Any] | None], str],
) -> dict[str, StructuredTool]:
    tools: dict[str, StructuredTool] = {}
    for tool_name, meta in tool_catalog.items():
        description = str(meta.get("description", "")).strip() or tool_name

        def _make_fn(_tool_name: str) -> Callable[..., str]:
            def _fn(
                config_file: str | None = None,
                profile: str | None = None,
                tenancy_ocid: str | None = None,
                compartment_ocid: str | None = None,
                region: str | None = None,
            ) -> str:
                args: dict[str, Any] = {}
                if config_file:
                    args["config_file"] = config_file
                if profile:
                    args["profile"] = profile
                if tenancy_ocid:
                    args["tenancy_ocid"] = tenancy_ocid
                if compartment_ocid:
                    args["compartment_ocid"] = compartment_ocid
                if region:
                    args["region"] = region
                return mcp_call(_tool_name, args)

            return _fn

        fn = _make_fn(tool_name)
        tools[tool_name] = StructuredTool.from_function(fn, name=tool_name, description=description)
    return tools


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
            keys = [k for k in payload.keys() if k not in ("cis_section", "tenancy_ocid", "compartment_ocid", "region", "cloud_provider")]
            lines.append(f"  • {tool_name}: ok ({len(keys)} top-level field(s))")
    return lines or ["  • (no tool payloads)"]


def print_agent_step(node: str, delta: dict[str, Any], *, step_no: int, total: int = 5) -> None:
    bar = "─" * 62
    print(f"\n{bar}\n Step {step_no}/{total} · {node}\n{bar}")
    if node == "plan_tools":
        print("Thought: Decide which OCI MCP tools are needed.")
        planned = delta.get("selected_tools") or []
        planned_names = [p.get("name", "") for p in planned if isinstance(p, dict)]
        print(f"Action: Planned MCP tools: {', '.join(planned_names) or '(none)'}")
        print(f"Observation: Planned sections: {', '.join(delta.get('sections') or []) or 'n/a'}")
    elif node == "fetch_resources":
        print("Thought: Execute planned OCI MCP tools (read-only).")
        print(f"Action: MCP tools: {', '.join(delta.get('tools_used') or []) or '(none)'}")
        print("Observation:")
        for line in _observation_inventory(delta.get("resources_json") or {}):
            print(line)
    elif node == "retrieve_rules":
        cis = delta.get("cis_rules") or ""
        print(f"Observation: CIS context length: {len(cis)} chars (~{cis.count('### CIS')} block(s))")
    elif node == "analyze":
        body = delta.get("analysis_markdown") or ""
        print(f"Action: ChatGroq(model={GROQ_MODEL!r})")
        print(f"Observation: Analysis length: {len(body)} chars")
    elif node == "report":
        rep = delta.get("report_markdown") or ""
        print(f"Observation: Report length: {len(rep)} chars")
    else:
        print(f"Observation: Keys updated: {', '.join(delta.keys()) if delta else 'none'}")


def _stream_audit(app: Any, user_prompt: str, *, stream_trace: bool, langfuse_config: dict[str, Any] | None = None) -> str:
    report_md = ""
    step = 0
    node_order = ("route_intent", "plan_tools", "fetch_resources", "retrieve_rules", "analyze", "structure_findings", "report", "assist", "memory_update")
    stream_kwargs: dict[str, Any] = {"stream_mode": "updates"}
    if langfuse_config:
        stream_kwargs["config"] = langfuse_config
    for chunk in app.stream({"messages": [HumanMessage(content=user_prompt)]}, **stream_kwargs):
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


def _compact_for_prompt(value: Any, *, max_dict_items: int, max_list_items: int, max_string_chars: int, max_depth: int, _depth: int = 0) -> Any:
    if _depth >= max_depth:
        return "...[max depth reached]..."
    if isinstance(value, dict):
        compact: dict[str, Any] = {}
        items = list(value.items())
        for k, v in items[:max_dict_items]:
            compact[str(k)] = _compact_for_prompt(v, max_dict_items=max_dict_items, max_list_items=max_list_items, max_string_chars=max_string_chars, max_depth=max_depth, _depth=_depth + 1)
        if len(items) > max_dict_items:
            compact["_truncated_keys"] = len(items) - max_dict_items
        return compact
    if isinstance(value, list):
        compact_list = [_compact_for_prompt(item, max_dict_items=max_dict_items, max_list_items=max_list_items, max_string_chars=max_string_chars, max_depth=max_depth, _depth=_depth + 1) for item in value[:max_list_items]]
        if len(value) > max_list_items:
            compact_list.append(f"...[{len(value) - max_list_items} more item(s)]...")
        return compact_list
    if isinstance(value, str):
        return value if len(value) <= max_string_chars else value[:max_string_chars] + "...[truncated]"
    return value


def _build_prompt_inventory(resources: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    variants = (
        dict(max_dict_items=40, max_list_items=30, max_string_chars=500, max_depth=6),
        dict(max_dict_items=25, max_list_items=15, max_string_chars=280, max_depth=5),
        dict(max_dict_items=15, max_list_items=8, max_string_chars=180, max_depth=4),
    )
    for i, limits in enumerate(variants):
        compact = _compact_for_prompt(resources, **limits)
        rendered = json.dumps(compact, indent=2, default=str)
        if len(rendered) <= _RESOURCE_JSON_MAX_CHARS:
            return compact, i > 0
    fallback = _compact_for_prompt(resources, max_dict_items=10, max_list_items=5, max_string_chars=120, max_depth=3)
    return fallback, True


def _scan_coverage_for_prompt(resources: dict[str, Any]) -> str:
    lines: list[str] = []
    for tool_name, payload in resources.items():
        if not isinstance(payload, dict):
            lines.append(f"- {tool_name}: invalid payload ({type(payload).__name__})")
            continue
        scope = payload.get("compartment_ocid") or payload.get("tenancy_ocid") or "unknown scope"
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
                lines.append(f"  - gap: {err.get('context', '?')}: {str(err.get('message', err))[:240]}")
        if len(errors) > 3:
            lines.append(f"  - gap: {len(errors) - 3} additional error(s)")
    return "\n".join(lines) if lines else "- No live inventory tools were run."


def _extract_user_question(text: str) -> str:
    marker = "user question:"
    lower = text.lower()
    idx = lower.rfind(marker)
    if idx == -1:
        return text.strip()
    return text[idx + len(marker):].strip()


def _last_user_text(state: AgentState) -> str:
    for m in reversed(state.get("messages", [])):
        if isinstance(m, HumanMessage):
            return _extract_user_question(str(m.content))
    return ""


def _route_intent(user_text: str) -> str:
    t = user_text.lower().strip()
    if any(phrase in t for phrase in ("full audit", "complete audit", "run audit", "generate report", "full report", "audit report", "cis report", "scan report")):
        return "report"
    return "assist"


def _select_tools_and_sections(user_text: str) -> tuple[list[str], list[str]]:
    t = user_text.lower().strip()
    if any(phrase in t for phrase in ("full audit", "complete audit", "all cis sections", "all eight sections", "all 8 sections", "entire benchmark", "whole benchmark", "1 through 8", "audit everything", "full cis audit")):
        return ([pair[1] for pair in _CIS_TOOLS_IN_ORDER], [pair[0] for pair in _CIS_TOOLS_IN_ORDER])

    tools: list[str] = []
    sections: list[str] = []

    if any(k in t for k in ("iam", "identity", "user", "group", "policy", "mfa", "compartment", "section 1", "cis 1")):
        tools.append("get_oci_identity_inventory"); sections.append("1")
    if any(k in t for k in ("network", "vcn", "subnet", "security list", "firewall", "section 2", "cis 2")):
        tools.append("get_oci_network_inventory"); sections.append("2")
    if any(k in t for k in ("logging", "monitoring", "log", "alarm", "audit log", "section 3", "cis 3")):
        tools.append("get_oci_logging_inventory"); sections.append("3")
    if any(k in t for k in ("compute", "instance", "vm", "boot volume", "section 4", "cis 4")):
        tools.append("get_oci_compute_inventory"); sections.append("4")
    if any(k in t for k in ("storage", "bucket", "object", "section 5", "cis 5")):
        tools.append("get_oci_storage_inventory"); sections.append("5")
    if any(k in t for k in ("database", "db", "autonomous", "mysql", "postgres", "section 6", "cis 6")):
        tools.append("get_oci_database_inventory"); sections.append("6")
    if any(k in t for k in ("governance", "tag", "budget", "section 7", "cis 7")):
        tools.append("get_oci_governance_inventory"); sections.append("7")
    if any(k in t for k in ("security", "cloud guard", "vault", "key", "kms", "scanning", "section 8", "cis 8")):
        tools.append("get_oci_security_inventory"); sections.append("8")

    if not tools:
        tools = ["get_oci_identity_inventory", "get_oci_network_inventory"]
        sections = ["1", "2"]

    seen: set[str] = set()
    utools: list[str] = []
    for x in tools:
        if x not in seen:
            seen.add(x); utools.append(x)
    seen_s: set[str] = set()
    usec: list[str] = []
    for x in sections:
        if x not in seen_s:
            seen_s.add(x); usec.append(x)
    return utools, usec


def _extract_first_json_object(text: str) -> dict[str, Any] | None:
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    blob = text[start:end + 1]
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
    blob = text[start:end + 1]
    try:
        parsed = json.loads(blob)
        if isinstance(parsed, list):
            return [x for x in parsed if isinstance(x, dict)]
    except Exception:
        return None
    return None


def _normalize_selected_tools(planned: list[dict[str, Any]] | None, *, tool_catalog: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    if not planned:
        return out
    for row in planned:
        if not isinstance(row, dict):
            continue
        name = str(row.get("name", "")).strip()
        if not name or name in seen or name not in tool_catalog:
            continue
        args = row.get("arguments") if isinstance(row.get("arguments"), dict) else {}
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
    upper = value.upper()
    if any(token in upper for token in ("TENANCY_OCID", "COMPARTMENT_OCID", "YOUR_", "OCID_HERE")):
        return False
    if key in ("tenancy_ocid", "compartment_ocid"):
        return value.startswith("ocid1.")
    if key == "region":
        return bool(value)
    if key in ("config_file", "profile"):
        return bool(value)
    return True


def node_route_intent(state: AgentState) -> dict[str, Any]:
    return {"intent": _route_intent(_last_user_text(state))}


def node_plan_tools(state: AgentState, *, tool_catalog: dict[str, dict[str, Any]], langfuse_config: dict[str, Any] | None = None, allow_empty: bool = False) -> dict[str, Any]:
    user_text = _last_user_text(state)
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        if allow_empty:
            return {"selected_tools": [], "tools_used": [], "sections": [], "planner_notes": "LLM planner disabled (missing GROQ_API_KEY); no tools selected."}
        fallback_tools, fallback_sections = _select_tools_and_sections(user_text)
        selected = [{"name": n, "arguments": {}} for n in fallback_tools]
        return {"selected_tools": selected, "tools_used": fallback_tools, "sections": fallback_sections, "planner_notes": "LLM planner disabled (missing GROQ_API_KEY); used keyword fallback."}

    planner_llm = ChatGroq(model=GROQ_MODEL, temperature=0, groq_api_key=api_key, max_tokens=800)
    allow_empty_note = "- If no tools are needed, return an empty selected_tools array and sections [].\n" if allow_empty else ""
    prompt = (
        "You are an OCI security audit planner. Select the minimal set of MCP tools needed to answer the user request.\n"
        "Available tools (JSON):\n"
        f"{json.dumps(tool_catalog, indent=2)}\n\n"
        "Rules:\n"
        "- Only choose tools from the provided catalog.\n"
        "- Use empty arguments {} unless a tenancy/compartment scope is explicitly requested.\n"
        "- For a tenancy-wide audit, pass {'tenancy_ocid':'ocid1.tenancy...'}.\n"
        "- For a compartment-scoped audit, pass {'compartment_ocid':'ocid1.compartment...'}.\n"
        f"{allow_empty_note}"
        "- Return pure JSON only (no markdown) with schema:\n"
        '{"selected_tools":[{"name":"tool_name","arguments":{}}],"sections":["1","5"],"notes":"short reason"}\n'
        f"User request: {user_text}"
    )
    resp = planner_llm.invoke([HumanMessage(content=prompt)], config=langfuse_config or {})
    raw = resp.content if isinstance(resp.content, str) else str(resp.content)
    parsed = _extract_first_json_object(raw) or {}
    selected = _normalize_selected_tools(parsed.get("selected_tools") if isinstance(parsed, dict) else None, tool_catalog=tool_catalog)
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
            sec_list = [tool_catalog[t["name"]]["cis_section"] for t in selected if t["name"] in tool_catalog]
        notes = str(parsed.get("notes", "Planned with LLM")).strip()
    return {"selected_tools": selected, "tools_used": [t["name"] for t in selected], "sections": sec_list, "planner_notes": notes}


def node_fetch_resources(state: AgentState, *, langchain_tools_by_name: dict[str, StructuredTool], langfuse_config: dict[str, Any] | None, mcp_call: Callable[[str, dict[str, Any] | None], str]) -> dict[str, Any]:
    selected = state.get("selected_tools") or []
    if not selected:
        if state.get("intent") == "assist":
            return {"resources_json": {}, "tools_used": [], "sections": state.get("sections") or []}
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
    return {"resources_json": resources, "tools_used": state_tools, "sections": state_sections}


def node_retrieve_rules(state: AgentState) -> dict[str, Any]:
    sections = state.get("sections") or []
    if not sections:
        sections = [pair[0] for pair in _CIS_TOOLS_IN_ORDER]
    retriever = get_oci_retriever()
    parts: list[str] = []
    for sec in sections:
        category = _SECTION_CATEGORY.get(sec)
        if not category:
            continue
        query = f"OCI CIS section {sec} {category} security controls requirements"
        rows = retriever.retrieve(query, top_k=5, category=category)
        if rows:
            parts.append(format_retrieval_for_prompt(rows))
    cis_rules = "\n\n".join(parts) if parts else "(No CIS OCI rules retrieved.)"
    max_chars = _CIS_MAX_CHARS_FULL_AUDIT if _is_full_audit_scope(sections) else _CIS_MAX_CHARS_PARTIAL_AUDIT
    cis_rules = _truncate_text(cis_rules, max_chars)
    return {"cis_rules": cis_rules}


def node_analyze(state: AgentState, *, langfuse_config: dict[str, Any] | None = None) -> dict[str, Any]:
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        return {"analysis_markdown": "## Analysis skipped\n\nGROQ_API_KEY not set. Cannot run LLM analysis."}
    resources = state.get("resources_json") or {}
    cis_rules = state.get("cis_rules") or ""
    sections = state.get("sections") or []
    compact, truncated = _build_prompt_inventory(resources)
    inventory_json = json.dumps(compact, indent=2, default=str)
    coverage = _scan_coverage_for_prompt(resources)

    llm = ChatGroq(model=GROQ_MODEL, temperature=0, groq_api_key=api_key, max_tokens=4000)
    system = (
        "You are an OCI Cloud Security Auditor aligned with the CIS Oracle Cloud Infrastructure Foundations Benchmark.\n"
        "Compare the live OCI inventory JSON against the CIS benchmark excerpts.\n"
        "For each relevant CIS control, output a verdict: Compliant / Non-Compliant / Not Assessed.\n"
        "For Non-Compliant findings, include: CIS ID, title, risk, evidence from the inventory, and remediation steps.\n"
        "Be concise and specific. Use Markdown headings per CIS section."
    )
    user = (
        f"## CIS Sections in scope: {', '.join(sections) or 'all'}\n\n"
        f"## Live OCI inventory (JSON){' (truncated)' if truncated else ''}:\n{inventory_json}\n\n"
        f"## Scan coverage:\n{coverage}\n\n"
        f"## CIS Benchmark excerpts (RAG):\n{cis_rules}\n\n"
        "Produce the security analysis in Markdown."
    )
    from langchain_core.messages import SystemMessage
    resp = llm.invoke([SystemMessage(content=system), HumanMessage(content=user)], config=langfuse_config or {})
    body = resp.content if isinstance(resp.content, str) else str(resp.content)
    return {"analysis_markdown": body}


def node_structure_findings(state: AgentState, *, langfuse_config: dict[str, Any] | None = None) -> dict[str, Any]:
    api_key = os.environ.get("GROQ_API_KEY")
    analysis = state.get("analysis_markdown") or ""
    if not api_key or not analysis:
        return {"structured_findings": []}
    llm = ChatGroq(model=GROQ_MODEL, temperature=0, groq_api_key=api_key, max_tokens=3000)
    prompt = (
        "Extract all security findings from the following OCI CIS audit analysis.\n"
        "Return a JSON array. Each item schema:\n"
        '{"cis_id":"1.1","title":"...","section":"Identity and Access Management",'
        '"severity":"High|Medium|Low","status":"Non-Compliant|Compliant|Not Assessed",'
        '"evidence":"...","remediation":"..."}\n'
        "Return ONLY the JSON array, no markdown.\n\n"
        f"Analysis:\n{analysis[:12000]}"
    )
    resp = llm.invoke([HumanMessage(content=prompt)], config=langfuse_config or {})
    raw = resp.content if isinstance(resp.content, str) else str(resp.content)
    findings = _extract_first_json_array(raw) or []
    return {"structured_findings": findings}


def node_report(state: AgentState) -> dict[str, Any]:
    analysis = state.get("analysis_markdown") or ""
    tools_used = state.get("tools_used") or []
    sections = state.get("sections") or []
    notes = state.get("planner_notes") or ""
    header = (
        "# OCI CIS Security Audit Report\n\n"
        f"**CIS Sections:** {', '.join(sections) or 'all'}\n\n"
        f"**MCP tools used:** {', '.join(tools_used) or 'none'}\n\n"
        f"**Planner notes:** {notes}\n\n"
        "---\n\n"
    )
    return {"report_markdown": header + analysis}


def node_assist(state: AgentState, *, langfuse_config: dict[str, Any] | None = None) -> dict[str, Any]:
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        return {"report_markdown": "Assist mode requires GROQ_API_KEY."}
    user_text = _last_user_text(state)
    cis_rules = state.get("cis_rules") or ""
    resources = state.get("resources_json") or {}
    llm = ChatGroq(model=GROQ_MODEL, temperature=0, groq_api_key=api_key, max_tokens=2000)
    system = "You are an OCI security assistant. Answer the user's question using the provided CIS context and OCI inventory."
    compact, _ = _build_prompt_inventory(resources)
    user = (
        f"User question: {user_text}\n\n"
        f"CIS context:\n{cis_rules[:8000]}\n\n"
        f"OCI inventory (compact JSON):\n{json.dumps(compact, default=str)[:8000]}\n\n"
        "Answer concisely in Markdown."
    )
    from langchain_core.messages import SystemMessage
    resp = llm.invoke([SystemMessage(content=system), HumanMessage(content=user)], config=langfuse_config or {})
    body = resp.content if isinstance(resp.content, str) else str(resp.content)
    return {"report_markdown": body}


def node_memory_update(state: AgentState, memory_sink: MemorySink | None = None) -> dict[str, Any]:
    if memory_sink is None:
        return {}
    findings = state.get("structured_findings") or []
    memory_sink({
        "agent": "oci-cis-security-agent",
        "sections": state.get("sections") or [],
        "tools_used": state.get("tools_used") or [],
        "findings_count": len(findings),
        "findings": findings,
        "report_markdown": state.get("report_markdown") or "",
    })
    return {}


def build_graph(
    *,
    memory_sink: MemorySink | None = None,
    langfuse_config: dict[str, Any] | None = None,
) -> Any:
    tool_catalog = _build_tool_catalog()
    langchain_tools = _build_langchain_mcp_tools(tool_catalog=tool_catalog, mcp_call=call_oci_mcp_tool)

    def _route(state: AgentState) -> str:
        return state.get("intent", "assist")

    graph = StateGraph(AgentState)
    graph.add_node("route_intent", node_route_intent)
    graph.add_node("plan_tools", lambda s: node_plan_tools(s, tool_catalog=tool_catalog, langfuse_config=langfuse_config))
    graph.add_node("fetch_resources", lambda s: node_fetch_resources(s, langchain_tools_by_name=langchain_tools, langfuse_config=langfuse_config, mcp_call=call_oci_mcp_tool))
    graph.add_node("retrieve_rules", node_retrieve_rules)
    graph.add_node("analyze", lambda s: node_analyze(s, langfuse_config=langfuse_config))
    graph.add_node("structure_findings", lambda s: node_structure_findings(s, langfuse_config=langfuse_config))
    graph.add_node("report", node_report)
    graph.add_node("assist", lambda s: node_assist(s, langfuse_config=langfuse_config))
    graph.add_node("memory_update", lambda s: node_memory_update(s, memory_sink))

    graph.add_edge(START, "route_intent")
    graph.add_conditional_edges("route_intent", _route, {"report": "plan_tools", "assist": "plan_tools"})
    graph.add_edge("plan_tools", "fetch_resources")
    graph.add_edge("fetch_resources", "retrieve_rules")
    graph.add_edge("retrieve_rules", "analyze")
    graph.add_edge("analyze", "structure_findings")
    graph.add_edge("structure_findings", "report")
    graph.add_edge("report", "memory_update")
    graph.add_edge("memory_update", END)
    graph.add_edge("assist", END)
    return graph.compile()


def run_oci_audit(user_prompt: str, *, stream_trace: bool = True, memory_sink: MemorySink | None = None) -> str:
    configure_quiet_runtime()
    langfuse_config = _make_langfuse_config()
    app = build_graph(memory_sink=memory_sink, langfuse_config=langfuse_config)
    return _stream_audit(app, user_prompt, stream_trace=stream_trace, langfuse_config=langfuse_config)


def run_oci_audit_full(*, stream_trace: bool = True, memory_sink: MemorySink | None = None, **scope: Any) -> str:
    """Run a full CIS OCI audit across all 8 sections."""
    prompt = "Run a full OCI CIS audit across all sections and generate a complete report."
    if scope:
        scope_str = " ".join(f"{k}={v}" for k, v in scope.items())
        prompt = f"{prompt} Scope: {scope_str}"
    return run_oci_audit(prompt, stream_trace=stream_trace, memory_sink=memory_sink)


if __name__ == "__main__":
    import sys
    prompt = " ".join(sys.argv[1:]) or "Run a full OCI CIS audit and generate a report."
    report = run_oci_audit(prompt, stream_trace=True)
    print("\n" + "=" * 80)
    print(report)