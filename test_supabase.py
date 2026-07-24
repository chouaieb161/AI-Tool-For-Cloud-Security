from __future__ import annotations

import sys
import os
sys.path.insert(0, r"C:\Users\MSI\AI-tool-for-cloud-security\backend")

from dotenv import load_dotenv
load_dotenv(r"C:\Users\MSI\AI-tool-for-cloud-security\.env")

print("OCI_SUPABASE_URL set:", bool(os.environ.get("OCI_SUPABASE_URL")))
print("OCI_SUPABASE_KEY set:", bool(os.environ.get("OCI_SUPABASE_KEY")))
print("OCI_SUPABASE_VECTORS_TABLE:", os.environ.get("OCI_SUPABASE_VECTORS_TABLE"))
print("OCI_SUPABASE_QUERY_NAME:", os.environ.get("OCI_SUPABASE_QUERY_NAME"))

from supabase import create_client

url = os.environ["OCI_SUPABASE_URL"]
key = os.environ["OCI_SUPABASE_KEY"]
client = create_client(url, key)

table = os.environ.get("OCI_SUPABASE_VECTORS_TABLE", "oci_vectors")
resp = client.table(table).select("id", count="exact").execute()
print(f"Table {table}: {len(resp.data)} rows (count: {resp.count})")

if resp.data:
    row = client.table(table).select("*").limit(1).execute()
    print("Sample row keys:", list(row.data[0].keys()) if row.data else "none")
