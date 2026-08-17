FROM python:3.12-slim

# Optional token for gated HuggingFace models
ARG HF_TOKEN=""

# System deps for sentence-transformers, chromadb, and google-cloud clients
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy repo-root requirements.txt for layer caching
COPY requirements.txt .

# Install CPU-only torch first (avoids ~2GB of CUDA libs)
RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu
RUN pip install --no-cache-dir -r requirements.txt

# Pre-download the embedding model so cold starts don't fetch it from HuggingFace
RUN HF_TOKEN=${HF_TOKEN} python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('BAAI/bge-large-en-v1.5', device='cpu')"

# Copy the FastAPI app and CIS rules
COPY backend/app ./app
COPY backend/cis_oci.jsonl ./cis_oci.jsonl
COPY cis_parsed.jsonl ./cis_parsed.jsonl

# Build the GCP CIS Chroma vector store from the parsed CIS benchmark (tracked)
# so the image is self-contained without committing the binary store.
RUN python -c "import json; from app.rag.vector_store import index_records; recs=[json.loads(l) for l in open('cis_parsed.jsonl', encoding='utf-8') if l.strip()]; n=index_records(recs, persist_directory='/data/chroma_cis', reset=True); print(f'indexed {n} CIS controls')"

# Volume mount point for runtime-persisted vector store
ENV CHROMA_CIS_PATH=/data/chroma_cis
ENV CIS_EMBED_DEVICE=cpu
ENV CIS_ENABLE_RERANK=0

EXPOSE 8000

# Non-root user for safety
RUN useradd --create-home appuser && chown -R appuser:appuser /app /data
USER appuser

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]