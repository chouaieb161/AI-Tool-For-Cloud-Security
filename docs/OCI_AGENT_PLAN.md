# OCI CIS Agent Plan

## Goal

Add an Oracle Cloud Infrastructure security agent to the existing multi-agent cloud security platform. The OCI agent should work like the current GCP agent: collect read-only cloud inventory through MCP tools, retrieve CIS OCI benchmark guidance through RAG, analyze the evidence with LangGraph and an LLM, then return both a human-readable report and structured findings for the dashboard.

The important design rule is: **OCI should become one provider agent in a provider-neutral platform**, not a one-off copy of the GCP code.

## Current Project Pattern

The current GCP implementation has these main pieces:

- FastAPI backend for projects, scans, credentials, chat, and dashboard data.
- SQLAlchemy models for projects, resources, scans, findings, chat sessions, and memory notes.
- A provider-specific MCP server in `backend/app/mcp/mcp_server.py`.
- A provider-specific LangGraph agent in `backend/app/gcp-agent/agent.py`.
- RAG ingestion/retrieval for CIS benchmark controls using Chroma, BM25, embeddings, and optional reranking.
- Groq/LangChain for analysis and chat-style answers.
- Frontend pages for credential setup, scans, dashboard, and chat.

The OCI agent should reuse the same orchestration shape:

```text
User request / Scan trigger
        |
        v
FastAPI service layer
        |
        v
Provider router selects OCI agent
        |
        v
LangGraph OCI agent
        |
        +--> Plan OCI MCP tools
        +--> Fetch OCI inventory with read-only credentials
        +--> Retrieve CIS OCI controls from RAG
        +--> Analyze evidence
        +--> Extract structured findings
        +--> Persist scan/resources/findings
```

## Recommended Technologies

Use the same core stack already present:

- **FastAPI** for API routes.
- **SQLAlchemy/PostgreSQL** for persistence.
- **LangGraph** for agent workflow.
- **MCP / FastMCP** for read-only cloud inventory tools.
- **LangChain + Groq** for LLM calls.
- **Chroma + BM25 + sentence-transformers** for CIS RAG.
- **Langfuse** for tracing, as already supported in the GCP agent.

Add OCI-specific dependencies:

- `oci` Python SDK for OCI API calls.
- Optional later: `cryptography` or a cloud KMS integration for encrypting uploaded OCI credential material at rest.

Add to `requirements.txt` later:

```text
oci>=2.0.0
```

## Target Backend Structure

Near-term structure:

```text
backend/app/
  oci-agent/
    agent.py
  mcp/
    oci_mcp_server.py
    mcp_server.py              # existing GCP MCP server
  rag/
    cis_pdf/
      CIS_Oracle_Cloud_Infrastructure_Foundation_Benchmark.pdf
```

Cleaner provider-neutral structure for the next iteration:

```text
backend/app/
  agents/
    gcp/agent.py
    oci/agent.py
  mcp/
    gcp_server.py
    oci_server.py
  providers/
    base.py
    gcp.py
    oci.py
```

The second structure will make AWS and Azure easier later.

## OCI Credential Model

OCI supports several authentication methods. For this application, use these in order:

### MVP: User API Key Config

The user provides an OCI config and private key, equivalent to `~/.oci/config`.

Required fields:

- `tenancy`
- `user`
- `fingerprint`
- `key_file` or uploaded private key content
- `region`
- optional `pass_phrase`
- optional `profile`, defaulting to `DEFAULT`

The backend should normalize this into a project/provider credential record and create OCI SDK clients from it.

Example OCI config shape:

```ini
[DEFAULT]
user=ocid1.user.oc1...
fingerprint=aa:bb:cc:...
tenancy=ocid1.tenancy.oc1...
region=us-ashburn-1
key_file=/secure/path/oci_api_key.pem
```

### Later: Instance Principals / Resource Principals

If the app runs inside OCI, prefer instance principals or resource principals. This removes uploaded user private keys and is better for production deployments.

Use cases:

- **Instance principals**: backend runs on an OCI compute instance.
- **Resource principals**: backend runs on OCI Functions or another supported OCI service.
- **Delegation/security token**: useful for CLI-style short-lived access, but less convenient for the web app MVP.

## Credential Storage Plan

For MVP local development:

- Store uploaded OCI config and private key under a backend credentials directory.
- Set runtime environment variables such as `OCI_CONFIG_FILE`, `OCI_CONFIG_PROFILE`, and `OCI_REGION`.
- Validate credentials immediately by calling a low-risk identity API such as tenancy/region/compartment listing.

For production:

- Do not store raw private keys as plain files.
- Encrypt credential material at rest.
- Add a `cloud_credentials` table with provider, project/account scope, encrypted payload, created time, and last validation status.
- Never expose private key content in API responses, logs, LangGraph state, MCP tool output, or LLM prompts.

Suggested table:

```text
cloud_credentials
  id
  provider              # GCP, OCI, AWS, AZURE
  project_id            # local project row
  display_name
  scope_id              # OCI tenancy OCID or compartment OCID
  region
  encrypted_payload
  status
  created_at
  updated_at
```

## OCI Permissions

The agent should be read-only. It needs enough access to inspect compartments and read configuration metadata.

For an MVP tenancy-wide audit, create an OCI group for the auditing user and attach policies similar to:

```text
Allow group CloudSecurityAuditors to inspect compartments in tenancy
Allow group CloudSecurityAuditors to read all-resources in tenancy
```

For a narrower compartment audit:

```text
Allow group CloudSecurityAuditors to inspect compartments in tenancy
Allow group CloudSecurityAuditors to read all-resources in compartment <compartment-name>
```

This is broad but practical for the first working version. After the MVP, reduce privileges into service-specific policies where possible, for example identity, network, compute, object storage, logging, audit, database, vault/key management, and cloud guard.

The agent should detect and report permission gaps. A permission error must become a **Data gap**, not a false non-compliant finding.

## OCI Scope Model

OCI resources are organized under a tenancy and compartments.

The OCI agent should accept:

- `tenancy_ocid`
- `compartment_ocid`
- `region`
- `include_subcompartments`

Default MVP behavior:

- If `compartment_ocid` is provided, audit that compartment and optionally its children.
- If only `tenancy_ocid` is provided, audit root tenancy and all accessible compartments.
- If the user has limited access, audit only what can be listed and record data gaps.

## OCI MCP Tool Design

Create `backend/app/mcp/oci_mcp_server.py` with a class similar to the current `GCPClient`.

Core client:

```python
class OCIClient:
    def __init__(
        self,
        config_file: str | None = None,
        profile: str | None = None,
        tenancy_ocid: str | None = None,
        compartment_ocid: str | None = None,
        region: str | None = None,
    ) -> None:
        ...
```

MCP tools should be intentionally read-only and grouped by CIS domains:

- `get_oci_identity_inventory`
  - users, groups, policies, compartments, API keys, auth tokens, customer secret keys, network sources, dynamic groups.
- `get_oci_network_inventory`
  - VCNs, subnets, security lists, NSGs, route tables, internet gateways, NAT gateways, service gateways, load balancers where relevant.
- `get_oci_compute_inventory`
  - instances, boot volumes, public IPs, metadata options, instance principals indicators.
- `get_oci_object_storage_inventory`
  - buckets, public access type, versioning, retention, encryption metadata, pre-authenticated requests.
- `get_oci_logging_monitoring_inventory`
  - audit configuration, logging groups/logs, service connectors, alarms, events rules.
- `get_oci_database_inventory`
  - DB systems, autonomous databases, backups, public access, encryption, maintenance settings.
- `get_oci_vault_kms_inventory`
  - vaults, keys, rotation metadata, lifecycle state.
- `get_oci_cloud_guard_inventory`
  - Cloud Guard status, detector recipes, target coverage, problems where accessible.

Each tool should return JSON with a consistent shape:

```json
{
  "cloud_provider": "OCI",
  "cis_section": "Identity",
  "tenancy_ocid": "...",
  "compartment_ocid": "...",
  "region": "...",
  "resources": [],
  "errors": []
}
```

Errors should be normalized like the GCP implementation:

```json
{
  "tool_error": true,
  "context": "list_instances",
  "error_type": "ServiceError",
  "message": "...",
  "permission_denied": true,
  "hint": "Grant read access for compute instances in this compartment."
}
```

## OCI Agent LangGraph Flow

The OCI agent should mirror the GCP agent:

```text
START
  -> route_intent
  -> plan_tools / plan_tools_assist
  -> fetch_resources
  -> retrieve_rules
  -> analyze / assist
  -> structure_findings
  -> report
  -> memory_update
END
```

The state can reuse the same typed structure:

```python
class AgentState(TypedDict):
    messages: Annotated[list[BaseMessage], add_messages]
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
```

Provider-specific differences should live in:

- OCI tool catalog.
- OCI CIS section/category mapping.
- OCI prompt text.
- OCI resource extraction and URI normalization.

## RAG for CIS OCI Benchmark

The existing RAG system can be reused, but ingestion must become provider-aware.

Recommended changes:

- Add `cloud_provider` metadata filter to retrieval.
- Add an OCI section mapping instead of hardcoding GCP sections only.
- Store OCI benchmark records in either:
  - a separate Chroma path, such as `.chroma_cis_oci`, or
  - the same collection with `cloud_provider="OCI"` metadata.

MVP preference: use a separate path first because it is simpler and avoids mixing GCP and OCI controls accidentally.

Later preference: one shared CIS collection filtered by `cloud_provider`.

OCI ingestion target:

```text
backend/app/rag/cis_pdf/CIS_Oracle_Cloud_Infrastructure_Foundation_Benchmark.pdf
```

The parser should output records like:

```json
{
  "cis_id": "1.1",
  "title": "...",
  "section": "Identity and Access Management",
  "category": "IAM",
  "description": "...",
  "rationale": "...",
  "audit": "...",
  "remediation": "...",
  "profile_level": "Level 1",
  "severity": "L1",
  "cloud_provider": "OCI"
}
```

## Deterministic Checks vs LLM Analysis

The safest architecture is hybrid:

- MCP tools collect raw OCI configuration.
- Deterministic Python checkers evaluate controls that are directly testable.
- RAG supplies official CIS context and remediation.
- LLM writes the final explanation and handles ambiguous/manual controls.

This reduces hallucination risk. The LLM should not decide everything from scratch when simple rules can evaluate the evidence.

Example deterministic checks:

- Bucket public access is enabled.
- Compute instance has a public IP.
- Security list allows `0.0.0.0/0` to SSH/RDP.
- Cloud Guard is disabled or not targeted.
- Audit/logging is not enabled where required.
- IAM user has active API keys or auth tokens beyond policy.

Output from deterministic checks:

```json
{
  "cis_rule_id": "x.y",
  "status": "NON_COMPLIANT",
  "severity": "HIGH",
  "evidence": {
    "resource_id": "...",
    "field": "public_access_type",
    "observed": "ObjectRead"
  }
}
```

## Provider-Neutral Data Model Changes

The current database names are GCP-specific:

- `Project.gcp_project_id`
- `Resource.gcp_uri`
- GCP-specific scan schemas and result classes.

For OCI, prefer a provider-neutral extension:

```text
projects
  id
  name
  cloud_provider        # GCP, OCI, AWS, AZURE
  external_account_id   # GCP project id, OCI tenancy OCID, AWS account id, etc.
  default_region
```

```text
resources
  id
  project_id
  provider              # OCI
  type
  name
  cloud_uri             # provider-neutral replacement for gcp_uri
  region
  compartment_or_scope
```

For a fast MVP, keep existing GCP fields and add OCI-specific fields carefully, but the provider-neutral migration will pay off quickly.

## API and Frontend Changes

Backend:

- Add `provider` to project creation.
- Add OCI credential upload/status endpoints.
- Add provider router in scan service:
  - `GCP -> gcp-agent`
  - `OCI -> oci-agent`
- Add provider-aware chat prompt generation.
- Add provider-aware resource/finding extraction.

Frontend:

- Setup page should let the user choose cloud provider.
- For OCI, collect:
  - tenancy OCID
  - user OCID
  - fingerprint
  - region
  - private key upload
  - optional passphrase
  - compartment OCID or tenancy-wide scan toggle
- Dashboard should display provider-neutral resource IDs and OCI compartments.
- Chat should show the active provider/context.

## Security Rules

The OCI implementation must follow these rules:

- Never send private keys, fingerprints, raw config files, or secrets to the LLM.
- Never include credential material in MCP outputs.
- Use read-only SDK calls only.
- Normalize permission errors into data gaps.
- Keep audit scope explicit: tenancy, compartment, region, and include-subcompartments flag.
- Prefer short-lived or platform-managed identity when deployed inside OCI.
- Log only metadata: provider, tenancy/compartment IDs, tool names, counts, and error categories.

## Implementation Phases

### Phase 1: Planning and RAG

- Add OCI CIS benchmark PDF.
- Generalize ingestion to support `cloud_provider="OCI"`.
- Build `.chroma_cis_oci`.
- Add OCI category aliases to retriever or create an OCI retriever wrapper.

### Phase 2: OCI MCP Inventory

- Add `oci` SDK dependency.
- Create `oci_mcp_server.py`.
- Implement credential loading and validation.
- Implement compartment discovery.
- Add identity, networking, compute, object storage, logging, database, vault, and Cloud Guard inventory tools.
- Add tool catalog and programmatic `call_oci_mcp_tool`.

### Phase 3: OCI LangGraph Agent

- Create `backend/app/oci-agent/agent.py`.
- Mirror GCP graph structure.
- Add OCI tool planning and section mapping.
- Add OCI-specific analysis and structured finding prompts.
- Add tests using mocked OCI SDK clients.

### Phase 4: API Integration

- Add provider routing in `agent_service.py` and `chat_service.py`.
- Add OCI scan result schemas or provider-neutral schemas.
- Persist OCI resources using provider-neutral fields.
- Add credential status/upload endpoints for OCI.

### Phase 5: Frontend

- Add provider selection to setup.
- Add OCI credential form.
- Show tenancy, compartment, region, and provider in dashboard/chat.
- Keep scan and chat UX consistent with GCP.

### Phase 6: Hardening

- Encrypt credentials at rest.
- Add least-privilege policy templates.
- Add deterministic compliance checker modules.
- Add Langfuse tags: `oci`, `cis`, `security-audit`.
- Add integration tests with recorded/mocked OCI responses.

## First MVP Acceptance Criteria

The OCI MVP is complete when:

- A user can configure OCI credentials.
- The backend validates OCI access.
- The agent can discover compartments and fetch read-only inventory.
- The agent can retrieve OCI CIS benchmark controls.
- A scan produces a markdown report and structured findings.
- Findings are saved and shown in the existing dashboard.
- Permission gaps are clearly shown as data gaps.
- No credential material appears in logs, prompts, reports, or persisted findings.

## Recommended First Build Order

1. Add OCI CIS RAG ingestion.
2. Build `OCIClient` and `oci_mcp_server.py`.
3. Implement identity, network, compute, and object storage tools first.
4. Create the OCI LangGraph agent by adapting the current GCP agent.
5. Add provider routing in backend services.
6. Add OCI credential setup UI.
7. Add deterministic checkers for the most obvious high-value controls.

