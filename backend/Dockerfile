FROM python:3.12-slim

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

# Copy the FastAPI app and CIS OCI rules
COPY backend/app ./app
COPY backend/cis_oci.jsonl ./cis_oci.jsonl

# Prebuilt GCP CIS Chroma vector store
COPY .chroma_cis /data/chroma_cis

# Volume mount point for runtime-persisted vector store
ENV CHROMA_CIS_PATH=/data/chroma_cis
ENV CIS_EMBED_DEVICE=cpu
ENV CIS_ENABLE_RERANK=0

EXPOSE 8000

# Non-root user for safety
RUN useradd --create-home appuser && chown -R appuser:appuser /app /data
USER appuser

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]