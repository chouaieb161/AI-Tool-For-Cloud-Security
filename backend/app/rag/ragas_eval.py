"""
RAGAS evaluation harness for the CIS RAG pipeline.

Runs the four core RAGAS retrieval/generation metrics against the GCP (Chroma +
BM25 hybrid) and OCI (Supabase pgvector) retrievers:

  - Faithfulness         : is the generated answer grounded in the retrieved context
  - Answer Relevancy     : does the answer actually address the question
  - Context Precision    : are the relevant chunks ranked above irrelevant ones
  - Context Recall       : did retrieval cover all claims of the reference answer

The judge LLM defaults to the same Groq model used by the agents (OpenAI-compatible
endpoint) and the embeddings reuse the app's local BGE backend.

Usage:
    python -m app.rag.ragas_eval --provider gcp --limit 3
    python -m app.rag.ragas_eval --provider oci --top-k 4 --out reports/ragas_oci.json
    python -m app.rag.ragas_eval --provider gcp --trace   # also push judge runs to Langfuse
    python -m app.rag.ragas_eval --provider gcp --thresholds faithfulness:0.9,context_recall:0.85
"""

from __future__ import annotations

import argparse
import json
import os
import time
import warnings
from pathlib import Path
from typing import Any, Callable

from dotenv import load_dotenv
from langchain_core.embeddings import Embeddings
from langchain_core.messages import HumanMessage, SystemMessage

from app.rag.embeddings import get_embedding_backend

load_dotenv()  # picks up repo .env

GROQ_MODEL = os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")
RAGAS_JUDGE_MODEL = os.environ.get("RAGAS_JUDGE_MODEL", GROQ_MODEL)
TOP_K = int(os.environ.get("RAGAS_TOP_K", "5"))
LANGFUSE_BASE_URL = os.environ.get("LANGFUSE_HOST") or os.environ.get("LANGFUSE_BASE_URL")

# Repo root = <repo>/backend/app/rag -> three parents up is <repo>.
_REPO_ROOT = Path(__file__).resolve().parents[3]
_BACKEND_DIR = Path(__file__).resolve().parents[2]
_DEFAULT_CHROMA = _REPO_ROOT / ".chroma_cis"
_raw_chroma = os.environ.get("CHROMA_CIS_PATH") or str(_DEFAULT_CHROMA)
_chroma_path = Path(_raw_chroma)
if not _chroma_path.is_absolute():
    # The app sets CHROMA_CIS_PATH=../.chroma_cis relative to the backend dir.
    _chroma_path = (_BACKEND_DIR / _chroma_path).resolve()
_CHROMA_PATH = str(_chroma_path)

# A small curated set of CIS-oriented questions. `ground_truth` is the ideal
# answer (reference) used by context_precision / context_recall.
DEFAULT_QUESTIONS: list[dict[str, str]] = [
    {
        "question": "How should organizations manage service account keys to reduce the risk of leaked credentials?",
        "ground_truth": (
            "Avoid user-managed service account keys because they are never rotated automatically and a leaked key "
            "remains usable until manually revoked. Prefer Google-managed keys, workload identity, or short-lived credentials."
        ),
    },
    {
        "question": "Should the default VPC network remain enabled in a cloud project?",
        "ground_truth": (
            "No. The default network typically allows overly broad ingress such as 0.0.0.0/0 on common ports. It should "
            "be disabled and replaced with a purpose-built network using least-privilege firewall rules."
        ),
    },
    {
        "question": "Is multi-factor authentication required for cloud users, and why?",
        "ground_truth": (
            "Yes, MFA must be enforced for all human users because password-only credentials are easily compromised. "
            "Enforcing MFA protects against account takeover, and users without MFA are flagged as a CIS control violation."
        ),
    },
    {
        "question": "How can public storage buckets be secured?",
        "ground_truth": (
            "Storage buckets should never be publicly accessible. Public buckets expose data and must be restricted via "
            "IAM, disabling public access and enabling uniform bucket-level access, with monitoring for public exposure."
        ),
    },
    {
        "question": "What logging and monitoring practices are recommended for cloud workloads?",
        "ground_truth": (
            "Enable audit logging, route logs to a centralized sink or monitoring system, and configure alerts or alarms "
            "for suspicious activity so security events are detected and retained."
        ),
    },
    {
        "question": "How should cloud network firewalls or security lists be configured?",
        "ground_truth": (
            "Firewall rules and security lists should follow least privilege: allow only necessary ports and protocols, "
            "restrict source CIDR ranges, never open admin ports to 0.0.0.0/0, and keep a default-deny posture."
        ),
    },
    {
        "question": "Are user-managed SSH keys or long-lived API keys recommended for cloud instances?",
        "ground_truth": (
            "No. Prefer OS login or short-lived credentials over embedded long-lived keys; manage keys centrally and "
            "rotate them because leaked keys grant persistent access until they are removed."
        ),
    },
    {
        "question": "What should be done with cloud admin roles or privileged users?",
        "ground_truth": (
            "Grant least privilege, separate duties, remove unused admin users and groups, require MFA for admin "
            "accounts, and audit privileged access regularly."
        ),
    },
    {
        "question": "How should unused or stale user accounts and service accounts be handled?",
        "ground_truth": (
            "Remove or disable accounts that are inactive for a defined period (typically 90 days), audit privileged "
            "accounts regularly, and avoid dormant service accounts with active keys that are never used."
        ),
    },
    {
        "question": "What does CIS recommend about organization policy constraints such as allowed resource locations?",
        "ground_truth": (
            "Enforce organization or organization-policy constraints for allowed resource locations, disable default "
            "network creation, and restrict external IP assignment so resources are created only in approved regions "
            "with least-privilege defaults."
        ),
    },
    {
        "question": "Are project-wide SSH keys acceptable on compute instances?",
        "ground_truth": (
            "No. Block project-wide SSH keys and rely on instance-level keys or short-lived OS login instead, so a "
            "compromised key cannot grant access to every instance in the project."
        ),
    },
    {
        "question": "Should VPC flow logs be enabled for cloud networks?",
        "ground_truth": (
            "Yes. Enable VPC flow logs to capture network traffic metadata, forward them to a centralized log sink, "
            "and set an appropriate retention period so traffic anomalies are visible and retained."
        ),
    },
    {
        "question": "Are compute instances allowed to have public or external IP addresses?",
        "ground_truth": (
            "Avoid public IP addresses on compute instances unless strictly required. Prefer private IPs, bastion "
            "hosts, or identity-aware proxy access; flag instances that have external IPs assigned."
        ),
    },
    {
        "question": "Is IP forwarding permitted on compute instances?",
        "ground_truth": (
            "No. Disable IP forwarding on instances except where deliberately required, because an instance with IP "
            "forwarding enabled can route traffic and be used as a pivot to reach other networks."
        ),
    },
    {
        "question": "How should DNS be hardened for cloud resources?",
        "ground_truth": (
            "Use managed DNS with DNSSEC where supported, restrict zone transfers, avoid overly broad public exposure "
            "of internal records, and prefer private DNS for internal resource resolution."
        ),
    },
    {
        "question": "What should be enabled to preserve and manage storage objects over time?",
        "ground_truth": (
            "Enable object versioning and bucket lifecycle policies so objects are preserved against accidental "
            "deletion and expire according to retention requirements, with uniform bucket-level access and "
            "encryption at rest."
        ),
    },
    {
        "question": "Is encryption at rest required for storage and databases?",
        "ground_truth": (
            "Yes. Encrypt storage buckets, block volumes, database disks and backups at rest, ideally with "
            "customer-managed keys so keys can be rotated and access revoked independently."
        ),
    },
    {
        "question": "What network access is acceptable for database instances?",
        "ground_truth": (
            "Database instances should not be reachable from the public internet. Avoid public IPs or public "
            "endpoints, restrict access to authorized networks or security lists, require TLS for connections, "
            "and keep encryption at rest enabled."
        ),
    },
    {
        "question": "How should audit logging be configured across an organization?",
        "ground_truth": (
            "Enable audit logging at the organization and project or tenancy level, route logs to a centralized sink "
            "or monitoring system, and retain them for the required period so security events can be detected and "
            "investigated."
        ),
    },
    {
        "question": "Which security events should trigger alarms or alerts?",
        "ground_truth": (
            "Alerts should fire on privileged identity and IAM policy changes, instance creation, deletion or stop "
            "events, storage bucket exposure changes, failed sign-in attempts, and other actions that could indicate "
            "compromise or privilege escalation."
        ),
    },
]

# Minimum acceptable aggregate score per metric. Override with --thresholds.
DEFAULT_THRESHOLDS: dict[str, float] = {
    "faithfulness": 0.85,
    "answer_relevancy": 0.80,
    "context_precision": 0.75,
    "context_recall": 0.80,
}


def _load_ragas():
    """Import RAGAS lazily so the rest of the app never pays the import cost.

    RAGAS 0.4.x emits DeprecationWarnings for the legacy ``evaluate()`` API and the
    legacy metric objects; they are expected here, so we silence them for this module.
    """
    warnings.filterwarnings("ignore", category=DeprecationWarning)
    warnings.filterwarnings("ignore", message="LLM returned.*generations")
    from ragas import evaluate  # noqa: F401, PLC0415
    from ragas.dataset_schema import EvaluationDataset
    from ragas.embeddings import _LangchainEmbeddingsWrapper
    from ragas.llms import llm_factory
    from ragas.metrics import Faithfulness, answer_relevancy, context_precision, context_recall

    return evaluate, EvaluationDataset, _LangchainEmbeddingsWrapper, llm_factory, (
        Faithfulness,
        answer_relevancy,
        context_precision,
        context_recall,
    )


class _BackendEmbeddings(Embeddings):
    """Expose the app's BGE backend through the LangChain Embeddings interface RAGAS expects."""

    def __init__(self, backend: Any) -> None:
        self._b = backend

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        return self._b.embed_documents(texts)

    def embed_query(self, text: str) -> list[float]:
        return self._b.embed_queries([text])[0]


def _make_judge_and_embeddings():
    """Build the RAGAS judge LLM (Groq) and embeddings (local BGE)."""
    from openai import OpenAI

    (
        _evaluate,
        _ds,
        emb_wrapper,
        llm_factory,
        _metrics,
    ) = _load_ragas()

    judge_llm = llm_factory(
        model=RAGAS_JUDGE_MODEL,
        provider="openai",
        client=OpenAI(base_url="https://api.groq.com/openai/v1", api_key=os.environ["GROQ_API_KEY"]),
        temperature=0,
    )
    embeddings = emb_wrapper(_BackendEmbeddings(get_embedding_backend()))
    return judge_llm, embeddings


def _build_metrics(judge_llm: Any, embeddings: Any) -> list[Any]:
    _, _, _, _, (Faithfulness, answer_relevancy, context_precision, context_recall) = _load_ragas()
    metrics = [
        Faithfulness(llm=judge_llm),
        answer_relevancy,
        context_precision,
        context_recall,
    ]
    # Legacy metric objects are module-level singletons; attach the LLM/embeddings.
    answer_relevancy.llm = judge_llm
    answer_relevancy.embeddings = embeddings
    context_precision.llm = judge_llm
    context_recall.llm = judge_llm
    return metrics


def _format_context(row: dict[str, Any]) -> str:
    cid = row.get("cis_id", "")
    title = row.get("title", "")
    text = row.get("relevant_text", "")
    head = f"CIS {cid} - {title}" if cid else title
    return f"{head}\n{text}".strip()


def get_retriever(provider: str) -> Callable[[str, int], list[dict[str, Any]]]:
    """Return a callable (question, top_k) -> list of CIS rows for the provider."""
    if provider == "gcp":
        from app.rag.retriever import get_retriever as _gcp

        retriever = _gcp(_CHROMA_PATH)

        def _retrieve(q: str, k: int) -> list[dict[str, Any]]:
            return retriever.retrieve(q, top_k=k)

        return _retrieve

    if provider == "oci":
        from app.oci_agent.rag.rag import get_oci_retriever

        retriever = get_oci_retriever()

        def _retrieve(q: str, k: int) -> list[dict[str, Any]]:
            return retriever.retrieve(q, top_k=k)

        return _retrieve

    raise ValueError(f"Unsupported provider: {provider!r} (expected 'gcp' or 'oci')")


def answer_from_context(question: str, contexts: list[str]) -> str:
    """Generate an answer from the retrieved contexts only (mirrors agent retrieval path)."""
    from langchain_groq import ChatGroq

    llm = ChatGroq(model=GROQ_MODEL, temperature=0, groq_api_key=os.environ.get("GROQ_API_KEY"), max_tokens=350)
    system = SystemMessage(
        content=(
            "You are a concise cloud security advisor. Answer the question using ONLY the CIS "
            "benchmark excerpts below. If the excerpts do not contain enough information, say so "
            "instead of guessing."
        )
    )
    human = HumanMessage(
        content=f"Question: {question}\n\nCIS excerpts:\n{chr(10).join(contexts)}\n\nAnswer:"
    )
    resp = llm.invoke([system, human])
    return resp.content if isinstance(resp.content, str) else str(resp.content)


def _langfuse_callbacks() -> list[Any]:
    """Return a Langfuse LangChain callback handler if credentials are configured."""
    public_key = os.environ.get("LANGFUSE_PUBLIC_KEY")
    secret_key = os.environ.get("LANGFUSE_SECRET_KEY")
    if not public_key or not secret_key:
        return []
    try:
        from langfuse import Langfuse
        from langfuse.langchain import CallbackHandler

        Langfuse(
            public_key=public_key,
            secret_key=secret_key,
            base_url=LANGFUSE_BASE_URL,
        )
        return [CallbackHandler(public_key=public_key)]
    except Exception:
        return []


def run_evaluation(
    provider: str,
    questions: list[dict[str, str]] | None = None,
    *,
    top_k: int = TOP_K,
    trace: bool = False,
    out_path: str | None = None,
    thresholds: dict[str, float] | None = None,
) -> dict[str, Any]:
    """Run RAGAS evaluation for a provider. Returns per-row scores + aggregate means."""
    from ragas import evaluate  # noqa: PLC0415

    judge_llm, embeddings = _make_judge_and_embeddings()
    metrics = _build_metrics(judge_llm, embeddings)
    retrieve = get_retriever(provider)

    rows: list[dict[str, Any]] = []
    for q in questions or DEFAULT_QUESTIONS:
        question = q["question"]
        results = retrieve(question, top_k)
        contexts = [_format_context(r) for r in results]
        answer = answer_from_context(question, contexts)
        rows.append(
            {
                "user_input": question,
                "response": answer,
                "retrieved_contexts": contexts,
                "reference": q["ground_truth"],
            }
        )

    _, EvaluationDataset, _, _, _ = _load_ragas()
    dataset = EvaluationDataset.from_list(rows)

    callbacks = _langfuse_callbacks() if trace else []
    print(f"[ragas] evaluating provider={provider!r} samples={len(rows)} top_k={top_k} ...")
    result = evaluate(
        dataset,
        metrics=metrics,
        llm=judge_llm,
        embeddings=embeddings,
        raise_exceptions=False,
        show_progress=True,
        experiment_name=f"ragas-{provider}",
        callbacks=callbacks,
    )

    df = result.to_pandas()
    metric_cols = ["faithfulness", "answer_relevancy", "context_precision", "context_recall"]
    means = {m: _safe_mean(df, m) for m in metric_cols}

    thresholds = thresholds or DEFAULT_THRESHOLDS
    verdicts = {
        m: (means[m] is not None and means[m] >= thr)
        for m, thr in thresholds.items()
        if means.get(m) is not None
    }
    _missing = [
        m for m in thresholds if means.get(m) is None
    ]
    passed = all(verdicts.values()) and not _missing

    report: dict[str, Any] = {
        "provider": provider,
        "model": RAGAS_JUDGE_MODEL,
        "top_k": top_k,
        "n_samples": len(rows),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "thresholds": thresholds,
        "passed": bool(passed),
        "aggregate": means,
        "rows": df[["user_input", "response", "retrieved_contexts", "reference"] + metric_cols].to_dict("records"),
    }

    if out_path:
        os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, ensure_ascii=False)
        print(f"[ragas] report written to {out_path}")

    print("\n=== RAGAS aggregate scores ===")
    for m, s in means.items():
        verdict = ""
        if s is not None and m in thresholds:
            verdict = " PASS" if s >= thresholds[m] else " FAIL"
        print(f"  {m:20s} {s if s is None else round(s, 4)}{verdict}")
    if _missing:
        why = ", ".join(_missing)
        print(f"  [thresholds] insufficient data for: {why}")
    print(f"  OVERALL: {'PASS' if passed else 'FAIL'}")
    return report


def _safe_mean(df: Any, col: str) -> float | None:
    if col not in df.columns:
        return None
    vals = df[col].dropna()
    if vals.empty:
        return None
    return float(vals.mean())


def main() -> None:
    parser = argparse.ArgumentParser(description="RAGAS evaluation for the CIS RAG pipeline")
    parser.add_argument("--provider", choices=["gcp", "oci"], required=True)
    parser.add_argument("--top-k", type=int, default=TOP_K, help="Number of retrieved contexts per question")
    parser.add_argument("--limit", type=int, default=None, help="Limit number of questions evaluated")
    parser.add_argument("--out", default=None, help="JSON report output path")
    parser.add_argument(
        "--thresholds",
        default=None,
        help="Comma-separated metric:value overrides, e.g. faithfulness:0.9,context_recall:0.85",
    )
    parser.add_argument("--trace", action="store_true", help="Push judge LLM runs to Langfuse")
    args = parser.parse_args()

    questions = DEFAULT_QUESTIONS
    if args.limit:
        questions = questions[: args.limit]

    thresholds = None
    if args.thresholds:
        thresholds = {}
        for token in args.thresholds.split(","):
            name, _, value = token.partition(":")
            thresholds[name.strip()] = float(value)

    run_evaluation(
        args.provider,
        questions,
        top_k=args.top_k,
        trace=args.trace,
        out_path=args.out,
        thresholds=thresholds,
    )


if __name__ == "__main__":
    main()
