from __future__ import annotations

import sys, os, json
sys.path.insert(0, r"C:\Users\MSI\AI-tool-for-cloud-security\backend")

from dotenv import load_dotenv
load_dotenv(r"C:\Users\MSI\AI-tool-for-cloud-security\.env")

from app.oci_agent.rag.rag import get_oci_retriever, format_retrieval_for_prompt

r = get_oci_retriever()
# Try without category filter
results = r.retrieve("IAM", top_k=3)
print(f"Without filter: {len(results)} results")
for row in results:
    print(f"  CIS {row['cis_id']}: cat={row['category']}")

# Now try with specific category
results2 = r.retrieve("security controls", top_k=3, category="Identity and Access Management")
print(f"\nWith IAM filter: {len(results2)} results")
for row in results2:
    print(f"  CIS {row['cis_id']}: {row['title'][:60]}")
